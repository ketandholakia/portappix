unit Portappix.Runner;

{
  The portable-app execution engine (Phase 2: transactional journal).

  Run is now a write-ahead transaction: every host mutation is recorded in
  the transaction journal (durably persisted) BEFORE it is performed, and
  the journal is updated again after the mutation completes. The cleanup
  path — used both after a normal run and after any failure — replays the
  recorded operations in reverse through TPortappixTransactionReconciler,
  which is the same idempotent code the crash-recovery engine uses.

  Ordering (see docs/security/JOURNAL_TRANSACTION_AND_RECOVERY.md):
    BeginTransaction (durable 'preparing' -> 'prepared')
    junction host preparation: remove pre-existing reparse point (original
      target recorded) / rename host directory to <path>_host_backup
    registry backups (reg.exe export into the transaction directory)
    -> hostBackupComplete
    junction creation, host registry deletes, portable registry import
    -> hostStateChanging -> hostStateChanged -> running
    (app runs) -> cleaning: portable export, then reverse reconciliation
    -> completed (transaction directory removed)
  If the journal cannot be persisted at any point, the host mutation does
  not proceed.
}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  System.StrUtils,
  System.Generics.Collections,
  System.Generics.Defaults,
  Portappix.Common,
  Portappix.Transactions,
  Portappix.Junction,
  Portappix.Manifest,
  Portappix.Policy,
  Portappix.Process,
  Portappix.Registry;

type
  EPortappixRunnerError = class(Exception);
  EPortappixPolicyError = class(EPortappixRunnerError);
  EPortappixElevationRequired = class(EPortappixRunnerError);

  IPortappixJournal = interface
    ['{B8A13E7E-3A9D-4B0B-9C13-6F4E9E2C4D52}']
    function BeginTransaction(const AAppId: string): IPortappixTransaction;
    procedure RecoverPendingCleanups;
    function GetOnLog: TProc<string>;
    procedure SetOnLog(const AValue: TProc<string>);
    property OnLog: TProc<string> read GetOnLog write SetOnLog;
  end;

  TPortableAppRunner = class
  private
    FManifest: TPortappixManifest;
    FManifestPath: string;
    FRootPath: string;
    FAppDir: string;
    FDataDir: string;
    FExePath: string;
    FEnvironment: TDictionary<string, string>;
    FRegistryKeys: TArray<string>;
    FJunctions: TDictionary<string, string>;
    FExitCode: Cardinal;
    FOnLog: TProc<string>;
    FJournal: IPortappixJournal;
    FRegistryOps: IPortappixRegistryOps;
    FHostPathOps: IPortappixHostPathOps;
    // What each junction host path looked like before the run ('absent',
    // 'directory', 'junction') — persisted on the create operation so
    // restoration can verify the final state.
    FJunctionOriginalKind: TDictionary<string, string>;
    procedure Log(const AMessage: string);
    procedure ResolvePaths;
    procedure ResolveRegistryKeys;
    procedure PrepareDataDirectories;
    procedure BuildEnvironment;
    procedure EnsureEnvironmentDirectories;
    function ExpandTokens(const AValue: string): string;
    function BuildEnvironmentBlock: string;
    function LaunchProcess(const AEnvironmentBlock: string): Cardinal;
    procedure ImportPortableRegistry;
    function ExportPortableRegistry: Boolean;
    function RegistryKeyExists(const AKey: string): Boolean;
    function GetPortableRegistryFile: string;
    // Transactional phases.
    procedure PrepareJunctionHost(const ATx: IPortappixTransaction;
      const AHostPath, ATargetPath: string);
    procedure BackupRegistryKey(const ATx: IPortappixTransaction; const AKey: string);
    procedure CreateJunctionJournaled(const ATx: IPortappixTransaction;
      const AHostPath, ATargetPath: string);
    procedure DeleteHostKeysJournaled(const ATx: IPortappixTransaction);
    procedure CleanupTransaction(const ATx: IPortappixTransaction);
  public
    constructor Create(const AManifestPath: string; const ARootPath: string = '');
      overload;
    constructor Create(const AManifestPath: string; const AJournal: IPortappixJournal;
      const ARootPath: string = ''); overload;
    constructor Create(const AManifestPath: string; const AJournal: IPortappixJournal;
      const ARootPath: string; const ARegistryOps: IPortappixRegistryOps); overload;
    destructor Destroy; override;
    function Run: Cardinal;
    class procedure PerformCleanup(const AAppId: string; const AHijackedKeys: TArray<string>;
      const ADataDir: string; const ALog: TProc<string> = nil); overload; static;
    class procedure PerformCleanup(const AAppId: string; const AHijackedKeys: TArray<string>;
      const AJunctions: TArray<string>; const ADataDir: string;
      const ALog: TProc<string> = nil;
      const ARegistryOps: IPortappixRegistryOps = nil;
      const AHostPathOps: IPortappixHostPathOps = nil); overload; static;
    property Manifest: TPortappixManifest read FManifest;
    property ManifestPath: string read FManifestPath;
    property RootPath: string read FRootPath;
    property AppDirectory: string read FAppDir;
    property DataDirectory: string read FDataDir;
    property ExecutablePath: string read FExePath;
    property ExitCode: Cardinal read FExitCode;
    property OnLog: TProc<string> read FOnLog write FOnLog;
    property RegistryOps: IPortappixRegistryOps read FRegistryOps write FRegistryOps;
    property HostPathOps: IPortappixHostPathOps read FHostPathOps write FHostPathOps;
  end;

implementation

const
  ERROR_ELEVATION_REQUIRED = 740;

function GetHostEnvironment: TDictionary<string, string>;
var
  EnvironmentBlock: PChar;
  Entry: PChar;
  EntryText: string;
  SeparatorPosition: Integer;
begin
  Result := TDictionary<string, string>.Create(TIStringComparer.Ordinal);
  EnvironmentBlock := GetEnvironmentStrings;
  if EnvironmentBlock = nil then
    Exit;

  try
    Entry := EnvironmentBlock;
    while Entry^ <> #0 do
    begin
      EntryText := Entry;
      if EntryText <> '' then
      begin
        if EntryText[1] = '=' then
          SeparatorPosition := PosEx('=', EntryText, 2)
        else
          SeparatorPosition := Pos('=', EntryText);

        if SeparatorPosition > 1 then
          Result.AddOrSetValue(
            Copy(EntryText, 1, SeparatorPosition - 1),
            Copy(EntryText, SeparatorPosition + 1, MaxInt));
      end;

      Inc(Entry, Length(EntryText) + 1);
    end;
  finally
    FreeEnvironmentStrings(EnvironmentBlock);
  end;
end;

function IsFolderEnvironmentVariable(const AName: string): Boolean;
const
  FolderVariables: array[0..10] of string = (
    'APPDATA', 'LOCALAPPDATA', 'USERPROFILE', 'TEMP', 'TMP', 'HOME',
    'PROGRAMDATA', 'PUBLIC', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME');
begin
  for var Name in FolderVariables do
    if SameText(AName, Name) then
      Exit(True);

  Result := False;
end;

function PathExists(const APath: string): Boolean;
begin
  Result := TDirectory.Exists(APath) or TFile.Exists(APath);
end;

function HostJunctionBackupPath(const AHostPath: string): string;
begin
  Result := AHostPath + '_host_backup';
end;

procedure CleanupLog(const ALog: TProc<string>; const AMessage: string);
begin
  if Assigned(ALog) then
    ALog(AMessage);
end;

function ExportKeysToRegistryFile(const AOps: IPortappixRegistryOps;
  const AKeys: TArray<string>; const ADataDir: string;
  const ALog: TProc<string>): Boolean;
var
  TemporaryFiles: TList<string>;
  ExportedFiles: TList<string>;
begin
  Result := True;
  if (Length(AKeys) = 0) or (ADataDir = '') or not Assigned(AOps) then
    Exit;

  ForceDirectories(ADataDir);
  TemporaryFiles := TList<string>.Create;
  ExportedFiles := TList<string>.Create;
  try
    var Index := 0;
    for var Key in AKeys do
    begin
      if not AOps.KeyExists(Key) then
      begin
        CleanupLog(ALog, 'Registry key is not present after run: ' + Key);
        Continue;
      end;

      var TemporaryFile := TPath.Combine(ADataDir,
        Format('registry.export.%u.%d.reg', [GetCurrentProcessId, Index]));
      Inc(Index);
      TemporaryFiles.Add(TemporaryFile);
      if TFile.Exists(TemporaryFile) then
        TFile.Delete(TemporaryFile);

      if AOps.ExportKey(Key, TemporaryFile) then
        ExportedFiles.Add(TemporaryFile)
      else
      begin
        Result := False;
        CleanupLog(ALog, 'Unable to export registry key: ' + Key);
      end;
    end;

    if Result and (ExportedFiles.Count > 0) then
    begin
      if MergeRegistryFiles(ExportedFiles.ToArray,
        TPath.Combine(ADataDir, 'registry.reg')) then
        CleanupLog(ALog, 'Portable registry saved: ' + TPath.Combine(ADataDir, 'registry.reg'))
      else
      begin
        Result := False;
        CleanupLog(ALog, 'Unable to merge exported registry keys into registry.reg.');
      end
    end
    else if Result then
      CleanupLog(ALog, 'No registry keys were available to export.');
  finally
    for var TemporaryFile in TemporaryFiles do
      if TFile.Exists(TemporaryFile) then
        try
          TFile.Delete(TemporaryFile);
        except
          on E: Exception do
            CleanupLog(ALog, Format('Unable to delete temporary registry export "%s": %s',
              [TemporaryFile, E.Message]));
        end;
    TemporaryFiles.Free;
    ExportedFiles.Free;
  end;
end;

procedure DeleteKeysWithOps(const AOps: IPortappixRegistryOps;
  const AKeys: TArray<string>; const ALog: TProc<string>);
begin
  for var Key in AKeys do
  begin
    try
      if not AOps.KeyExists(Key) then
        Continue;
      if AOps.DeleteKey(Key) then
        CleanupLog(ALog, 'Removed registry key from host: ' + Key)
      else
        CleanupLog(ALog, 'Registry key was not removed: ' + Key);
    except
      on E: Exception do
        CleanupLog(ALog, Format('Error deleting registry key "%s": %s', [Key, E.Message]));
    end;
  end;
end;

procedure RestoreBackupsWithOps(const AOps: IPortappixRegistryOps;
  const AKeys: TArray<string>; const ADataDir: string; const ALog: TProc<string>);
begin
  if ADataDir = '' then
    Exit;

  for var Index := 0 to High(AKeys) do
  begin
    var FileName := TPath.Combine(ADataDir, Format('host_backup_%d.reg', [Index]));
    if not TFile.Exists(FileName) then
      Continue;

    CleanupLog(ALog, 'Restoring host registry backup: ' + FileName);
    try
      if AOps.ImportFile(FileName) then
      begin
        if TFile.Exists(FileName) then
          TFile.Delete(FileName);
      end
      else
        CleanupLog(ALog, 'Host registry backup was not removed so it can be retried: ' +
          FileName);
    except
      on E: Exception do
        CleanupLog(ALog, Format('Unable to restore host registry backup "%s": %s',
          [FileName, E.Message]));
    end;
  end;
end;

function RemoveJunctionsWithLogOps(const AJunctions: TArray<string>;
  const ALog: TProc<string>; const AOps: IPortappixHostPathOps): Boolean; forward;

function RemoveJunctionsWithLog(const AJunctions: TArray<string>;
  const ALog: TProc<string>): Boolean;
begin
  Result := RemoveJunctionsWithLogOps(AJunctions, ALog, nil);
end;

function RemoveJunctionsWithLogOps(const AJunctions: TArray<string>;
  const ALog: TProc<string>; const AOps: IPortappixHostPathOps): Boolean;

  function OpPathExists(const APath: string): Boolean;
  begin
    if AOps <> nil then
      Result := AOps.PathExists(APath)
    else
      Result := PathExists(APath);
  end;

  function OpIsReparsePoint(const APath: string): Boolean;
  begin
    if AOps <> nil then
      Result := AOps.IsReparsePoint(APath)
    else
      Result := IsReparsePoint(APath);
  end;

  function OpDeleteJunction(const APath: string): Boolean;
  begin
    if AOps <> nil then
      Result := AOps.DeleteJunction(APath)
    else
      Result := DeleteJunction(APath);
  end;

  function OpRename(const AFrom, ATo: string): Boolean;
  begin
    if AOps <> nil then
      Result := AOps.RenamePath(AFrom, ATo)
    else
      Result := RenameFile(AFrom, ATo);
  end;

begin
  Result := True;
  for var Index := High(AJunctions) downto 0 do
  begin
    var HostPath := AJunctions[Index];
    var BackupPath := HostJunctionBackupPath(HostPath);
    try
      if OpPathExists(HostPath) then
      begin
        if OpIsReparsePoint(HostPath) then
        begin
          CleanupLog(ALog, 'Removing junction: ' + HostPath);
          if not OpDeleteJunction(HostPath) then
          begin
            Result := False;
            CleanupLog(ALog, 'Unable to remove junction: ' + HostPath);
          end;
        end
        else
          CleanupLog(ALog, 'Host path is not a junction; leaving it in place: ' + HostPath);
      end;

      if not OpPathExists(HostPath) and TDirectory.Exists(BackupPath) and
         not OpIsReparsePoint(BackupPath) then
      begin
        CleanupLog(ALog, 'Restoring host directory backup: ' + BackupPath);
        if not OpRename(BackupPath, HostPath) then
          CleanupLog(ALog, Format('Unable to restore host directory "%s": %s',
            [HostPath, SysErrorMessage(Integer(GetLastError))]));
      end;
    except
      on E: Exception do
        CleanupLog(ALog, Format('Error cleaning up junction "%s": %s', [HostPath, E.Message]));
    end;
  end;
end;

constructor TPortableAppRunner.Create(const AManifestPath: string;
  const ARootPath: string);
begin
  Create(AManifestPath, nil, ARootPath, nil);
end;

constructor TPortableAppRunner.Create(const AManifestPath: string;
  const AJournal: IPortappixJournal; const ARootPath: string);
begin
  Create(AManifestPath, AJournal, ARootPath, nil);
end;

constructor TPortableAppRunner.Create(const AManifestPath: string;
  const AJournal: IPortappixJournal; const ARootPath: string;
  const ARegistryOps: IPortappixRegistryOps);
begin
  inherited Create;
  FJournal := AJournal;
  FRegistryOps := ARegistryOps;
  if not Assigned(FRegistryOps) then
    FRegistryOps := TPortappixRegistryOps.Create;
  FHostPathOps := TPortappixHostPathOps.Create;

  try
    FRootPath := ResolveRootPath(ARootPath);
    FManifestPath := ResolveFromRoot(FRootPath, AManifestPath);
    FManifest := TPortappixManifest.LoadFromFile(FManifestPath);
    FAppDir := TPath.GetDirectoryName(FManifestPath);
    FEnvironment := TDictionary<string, string>.Create(TIStringComparer.Ordinal);
    FJunctions := TDictionary<string, string>.Create(TIStringComparer.Ordinal);
    FJunctionOriginalKind := TDictionary<string, string>.Create(TIStringComparer.Ordinal);
    ResolvePaths;
  except
    FJournal := nil;
    FreeAndNil(FJunctionOriginalKind);
    FreeAndNil(FJunctions);
    FreeAndNil(FEnvironment);
    FreeAndNil(FManifest);
    raise;
  end;
end;

destructor TPortableAppRunner.Destroy;
begin
  FreeAndNil(FJunctionOriginalKind);
  FreeAndNil(FJunctions);
  FreeAndNil(FEnvironment);
  FreeAndNil(FManifest);
  FJournal := nil;
  FRegistryOps := nil;
  FHostPathOps := nil;
  inherited;
end;

procedure TPortableAppRunner.Log(const AMessage: string);
begin
  if Assigned(FOnLog) then
    FOnLog(AMessage);
end;

function TPortableAppRunner.Run: Cardinal;
var
  EnvironmentBlock: string;
  Transaction: IPortappixTransaction;
  Pair: TPair<string, string>;
  Key: string;
begin
  FExitCode := Cardinal(-1);

  var Policy := TPortappixPolicy.ValidateManifest(FManifest);
  try
    if not Policy.Allowed then
      raise EPortappixPolicyError.CreateFmt(
        'Manifest "%s" failed policy validation.' + sLineBreak + '%s',
        [FManifestPath, Policy.Summary]);
  finally
    Policy.Free;
  end;

  if not TFile.Exists(FExePath) then
    raise EPortappixRunnerError.CreateFmt('Executable not found: "%s".', [FExePath]);

  // Journal intent is durably persisted BEFORE any host mutation. If the
  // journal cannot be created or written, the run aborts here.
  if FJournal = nil then
    raise EPortappixRunnerError.Create(
      'No crash journal was provided; refusing to modify host state.');
  Transaction := FJournal.BeginTransaction(FManifest.Id);
  Log(Format('Transaction %s started for "%s".', [Transaction.GetTxId, FManifest.Id]));

  try
    PrepareDataDirectories;
      // Record which data schema version last wrote here (used by update
      // downgrade protection). A declared dataVersion of 0 writes nothing.
      try
        TPortappixManifest.WriteDataVersion(FDataDir, FManifest.Id, FManifest.DataVersion);
      except
        on E: Exception do
          Log('Unable to record the data version: ' + E.Message);
      end;
      BuildEnvironment;
      EnvironmentBlock := BuildEnvironmentBlock;

      // Phase 1 (prepared): make host paths safe and back them up. Each
      // operation is durably recorded before it is performed.
      for Pair in FJunctions do
        PrepareJunctionHost(Transaction, Pair.Key, Pair.Value);
      for Key in FRegistryKeys do
        BackupRegistryKey(Transaction, Key);
      Transaction.SetState(txHostBackupComplete);

      // Phase 2 (hostStateChanging): the destructive mutations.
      Transaction.SetState(txHostStateChanging);
      for Pair in FJunctions do
        CreateJunctionJournaled(Transaction, Pair.Key, Pair.Value);
      DeleteHostKeysJournaled(Transaction);
      ImportPortableRegistry;

      Transaction.SetState(txHostStateChanged);
      Transaction.SetState(txRunning);

      Log(Format('Launching "%s".', [FExePath]));
      try
        FExitCode := LaunchProcess(EnvironmentBlock);
      finally
        CleanupTransaction(Transaction);
      end;
  except
    on E: Exception do
    begin
      // A durable error note unless cleanup already completed the
      // transaction; recovery reconciles whatever is left on next start.
      try
        if Transaction.GetState <> txCompleted then
          Transaction.SetError(E.Message);
      except
        on EInner: Exception do
          Log('Unable to persist the transaction error: ' + EInner.Message);
      end;
      Log(Format('Run failed: %s', [E.Message]));
      raise;
    end;
  end;

  Log(Format('Application exited with code %u.', [FExitCode]));
  Result := FExitCode;
end;

procedure TPortableAppRunner.ResolvePaths;
var
  ExeValue: string;
  HostPath: string;
  TargetPath: string;
begin
  FDataDir := TPath.GetFullPath(
    TPath.Combine(TPath.Combine(FRootPath, 'Data'), FManifest.Id));

  ExeValue := StringReplace(ExpandTokens(FManifest.Exe), '/', '\', [rfReplaceAll]);
  if IsRelativePath(ExeValue) then
    FExePath := TPath.GetFullPath(TPath.Combine(FAppDir, ExeValue))
  else
    FExePath := TPath.GetFullPath(ExeValue);

  ResolveRegistryKeys;

  FJunctions.Clear;
  for var Pair in FManifest.Junctions do
  begin
    HostPath := StringReplace(ExpandTokens(Pair.Key), '/', '\', [rfReplaceAll]);
    // Host paths may carry %VAR% references (the policy engine validates
    // the expanded form); expand them so the junction lands where the
    // policy checked it.
    HostPath := ExpandPercentVariables(HostPath);
    if IsRelativePath(HostPath) then
      HostPath := TPath.GetFullPath(TPath.Combine(FRootPath, HostPath))
    else
      HostPath := TPath.GetFullPath(HostPath);
    HostPath := TrimTrailingPathDelimiter(HostPath);

    TargetPath := StringReplace(ExpandTokens(Pair.Value), '/', '\', [rfReplaceAll]);
    if IsRelativePath(TargetPath) then
      TargetPath := TPath.GetFullPath(TPath.Combine(FDataDir, TargetPath))
    else
      TargetPath := TPath.GetFullPath(TargetPath);
    TargetPath := TrimTrailingPathDelimiter(TargetPath);

    if SameText(HostPath, TargetPath) then
      raise EPortappixRunnerError.CreateFmt(
        'Junction host and target must be different: "%s".', [HostPath]);

    FJunctions.AddOrSetValue(HostPath, TargetPath);
  end;
end;

procedure TPortableAppRunner.ResolveRegistryKeys;
var
  Keys: TList<string>;
begin
  Keys := TList<string>.Create;
  try
    for var Key in FManifest.RegistryKeys do
      Keys.Add(NormalizeRegistryPath(Key));
    FRegistryKeys := Keys.ToArray;
  finally
    Keys.Free;
  end;
end;

procedure TPortableAppRunner.PrepareDataDirectories;
begin
  ForceDirectories(FDataDir);
  for var Pair in FJunctions do
    ForceDirectories(Pair.Value);
end;

procedure TPortableAppRunner.PrepareJunctionHost(
  const ATx: IPortappixTransaction; const AHostPath, ATargetPath: string);
var
  BackupPath: string;
  OldTarget: string;
  Index: Integer;
  Inspection: TPortappixPathInspection;
begin
  BackupPath := HostJunctionBackupPath(AHostPath);

  if FHostPathOps.PathExists(BackupPath) then
    raise EPortappixRunnerError.CreateFmt(
      'Cannot create junction for "%s" because a host backup path already exists: "%s".',
      [AHostPath, BackupPath]);

  // Classify the existing object WITHOUT following any reparse point; every
  // case below either records safe restoration metadata or refuses.
  Inspection := FHostPathOps.InspectPath(AHostPath);
  case Inspection.Kind of
    rkMissing:
      // Case A: the path was absent — persisted on the create operation
      // (expectedOriginal='absent') so restoration can verify the absent
      // state is regained.
      FJunctionOriginalKind.AddOrSetValue(AHostPath, 'absent');

    rkDirectory:
      begin
        // Case B: an ordinary directory is never deleted; renaming it to
        // <path>_host_backup preserves it (contents included) and the
        // rename is reversed after the run.
        FJunctionOriginalKind.AddOrSetValue(AHostPath, 'directory');
        Index := ATx.RecordOperation(TPortappixTransaction.MakeOperation(
          okHostDirBackup, AHostPath, '', BackupPath, ''));
        Log('Backing up existing host directory: ' + AHostPath);
        if not FHostPathOps.RenamePath(AHostPath, BackupPath) then
        begin
          ATx.MarkOperation(Index, opFailed);
          raise EPortappixRunnerError.CreateFmt(
            'Unable to rename host directory "%s" to "%s": %s',
            [AHostPath, BackupPath, SysErrorMessage(Integer(GetLastError))]);
        end;
        ATx.MarkOperation(Index, opDone);
      end;

    rkJunction:
      begin
        // Case C: capture the original junction's full identity (mount-point
        // tag + target) BEFORE anything is removed; the durable record is
        // the preserved copy and restoration recreates the junction from it.
        if not Inspection.TargetParsed then
          raise EPortappixRunnerError.CreateFmt(
            'Unable to safely record the target of the existing junction "%s": %s. ' +
            'Refusing to remove it.',
            [AHostPath, Inspection.ErrorMessage]);
        OldTarget := Inspection.Target;
        FJunctionOriginalKind.AddOrSetValue(AHostPath, 'junction');
        Index := ATx.RecordOperation(TPortappixTransaction.MakeJunctionOperation(
          okJunctionRemoveOld, AHostPath, OldTarget, 'junction'));
        Log('Removing existing junction/reparse point before launch: ' + AHostPath);
        if not FHostPathOps.DeleteJunction(AHostPath) then
        begin
          ATx.MarkOperation(Index, opFailed);
          raise EPortappixRunnerError.CreateFmt(
            'Unable to remove existing junction "%s".', [AHostPath]);
        end;
        Inspection := FHostPathOps.InspectPath(AHostPath);
        if Inspection.Kind <> rkMissing then
        begin
          ATx.MarkOperation(Index, opFailed);
          raise EPortappixRunnerError.CreateFmt(
            'Existing junction was not removed: "%s".', [AHostPath]);
        end;
        ATx.MarkOperation(Index, opDone);
      end;

    rkSymlink:
      // Case D: symbolic links are never treated as junctions and never
      // removed.
      raise EPortappixRunnerError.CreateFmt(
        'Cannot create the junction for "%s": the path holds a symbolic link ' +
        '(%s). Portappix never replaces symbolic links.',
        [AHostPath, Inspection.Target]);

    rkOtherReparse:
      // Case E: unsupported reparse points are rejected untouched.
      raise EPortappixRunnerError.CreateFmt(
        'Cannot create the junction for "%s": the path holds an unsupported ' +
        'reparse point (%s). Portappix never replaces unsupported reparse points.',
        [AHostPath, Inspection.ErrorMessage]);

    rkFile:
      raise EPortappixRunnerError.CreateFmt(
        'Cannot create junction because a file exists at host path "%s".', [AHostPath]);

    rkInspectionFailed:
      // Case F: fail closed; no host mutation without a verified picture.
      raise EPortappixRunnerError.CreateFmt(
        'Cannot inspect the host path "%s": %s. Refusing to modify it.',
        [AHostPath, Inspection.ErrorMessage]);
  end;
end;

procedure TPortableAppRunner.BackupRegistryKey(const ATx: IPortappixTransaction;
  const AKey: string);
var
  BackupFile: string;
  Index: Integer;
begin
  ForceDirectories(FDataDir);

  // The intent record is created without a file name; the transaction owns
  // the naming and assigns registry_backup_<index>.reg at record time.
  Index := ATx.RecordOperation(TPortappixTransaction.MakeOperation(
    okRegistryBackup, '', '', '', AKey));
  BackupFile := ATx.GetOperation(Index).BackupPath;

  if not FRegistryOps.KeyExists(AKey) then
  begin
    // The key does not exist on the host: record that so recovery knows the
    // original state contained no values for it.
    ATx.MarkOperation(Index, opAbsent);
    Exit;
  end;

  Log('Backing up host registry key: ' + AKey);
  if not FRegistryOps.ExportKey(AKey, BackupFile) then
  begin
    ATx.MarkOperation(Index, opFailed);
    raise EPortappixRunnerError.CreateFmt(
      'Unable to export host registry key backup for "%s".', [AKey]);
  end;
  if not TFile.Exists(BackupFile) then
  begin
    ATx.MarkOperation(Index, opFailed);
    raise EPortappixRunnerError.CreateFmt(
      'The host registry backup for "%s" was not written.', [AKey]);
  end;
  ATx.MarkOperation(Index, opDone);
end;

procedure TPortableAppRunner.CreateJunctionJournaled(
  const ATx: IPortappixTransaction; const AHostPath, ATargetPath: string);
var
  Index: Integer;
  Inspection: TPortappixPathInspection;
  ExpectedOriginal: string;
begin
  ForceDirectories(TPath.GetDirectoryName(AHostPath));
  ForceDirectories(ATargetPath);

  if not FJunctionOriginalKind.TryGetValue(AHostPath, ExpectedOriginal) then
    ExpectedOriginal := 'absent';

  Log(Format('Creating junction "%s" -> "%s".', [AHostPath, ATargetPath]));
  Index := ATx.RecordOperation(TPortappixTransaction.MakeJunctionOperation(
    okJunctionCreate, AHostPath, ATargetPath, ExpectedOriginal));
  if not FHostPathOps.CreateJunction(AHostPath, ATargetPath) then
  begin
    ATx.MarkOperation(Index, opFailed);
    raise EPortappixRunnerError.CreateFmt(
      'Unable to create junction "%s" -> "%s": %s',
      [AHostPath, ATargetPath, SysErrorMessage(Integer(GetLastError))]);
  end;

  // TEST-ONLY crash point between the junction object existing on disk and
  // MarkJunctionCreated durably persisting its filesystem identity: the
  // exact ownership-verification window the Phase 3 remediation closes.
  // Recovery for this state refuses removal of the junction (ownership
  // cannot be established without the recorded identity) and marks the
  // transaction recoveryRequired. Never used outside test environments.
  CheckCrashPoint(Format('op:%d:created', [Index]));

  // Verify the created object: it must be a mount-point junction with
  // exactly the recorded target, and its filesystem identity is captured
  // into the transaction for later ownership verification.
  Inspection := FHostPathOps.InspectPath(AHostPath);
  if (Inspection.Kind <> rkJunction) or not Inspection.TargetParsed or
     not TPortappixTransaction.SameCanonicalPath(Inspection.Target, ATargetPath) then
  begin
    ATx.MarkOperation(Index, opFailed);
    raise EPortappixRunnerError.CreateFmt(
      'The junction "%s" was not created with the recorded target.', [AHostPath]);
  end;
  ATx.MarkJunctionCreated(Index, IntToHex(Inspection.ReparseTag, 8),
    Inspection.Identity);
end;

procedure TPortableAppRunner.DeleteHostKeysJournaled(
  const ATx: IPortappixTransaction);
var
  Index: Integer;
  Operation: TPortappixTxOperation;
  DeleteIndex: Integer;
begin
  // Delete every host key that was backed up, so host values cannot leak
  // into the portable registry. Each delete is recorded (with the backup it
  // can be restored from) before it is performed.
  for Index := 0 to ATx.OperationCount - 1 do
  begin
    Operation := ATx.GetOperation(Index);
    if (Operation.Kind <> okRegistryBackup) or (Operation.Status <> opDone) then
      Continue;

    if not FRegistryOps.KeyExists(Operation.RegistryKey) then
      Continue; // vanished between backup and delete; the backup still rules

    Log('Clearing host registry key: ' + Operation.RegistryKey);
    DeleteIndex := ATx.RecordOperation(TPortappixTransaction.MakeOperation(
      okRegistryDelete, '', '', Operation.BackupPath, Operation.RegistryKey));
    if not FRegistryOps.DeleteKey(Operation.RegistryKey) then
    begin
      ATx.MarkOperation(DeleteIndex, opFailed);
      raise EPortappixRunnerError.CreateFmt(
        'Unable to clear host registry key "%s".', [Operation.RegistryKey]);
    end;
    ATx.MarkOperation(DeleteIndex, opDone);
  end;
end;

procedure TPortableAppRunner.CleanupTransaction(const ATx: IPortappixTransaction);
var
  ExportSucceeded: Boolean;
  Reconciler: TPortappixTransactionReconciler;
begin
  if ATx.GetState <> txCleaning then
  begin
    try
      ATx.SetState(txCleaning);
    except
      on E: Exception do
      begin
        // Without a durable cleaning record the host must not be touched;
        // recovery reconciles from the last durable state instead.
        Log('Unable to persist the cleanup state: ' + E.Message);
        Exit;
      end;
    end;
  end;

  // Capture what the app wrote (portable data) BEFORE undoing host state.
  ExportSucceeded := False;
  try
    ExportSucceeded := ExportPortableRegistry;
  except
    on E: Exception do
      Log('Failed to export the portable registry: ' + E.Message);
  end;
  if not ExportSucceeded then
    Log('Host registry keys were left in place because the portable registry ' +
      'could not be saved.');

  // Undo every recorded operation in reverse order (idempotent, verified).
  // The hard cast is safe: the interface reference held by Run keeps the
  // transaction object alive for the whole run.
  Reconciler := TPortappixTransactionReconciler.Create(FRegistryOps, FHostPathOps, FOnLog);
  try
    try
      if not Reconciler.ReconcileTransaction(TPortappixTransaction(ATx)) then
        Log('Cleanup incomplete: ' + Reconciler.LastError);
    except
      on E: Exception do
      begin
        Log('Cleanup reconciliation failed: ' + E.Message);
      end;
    end;
  finally
    Reconciler.Free;
  end;

  if ATx.AllOperationsResolved then
  begin
    try
      ATx.CompleteAndRemove;
      Log(Format('Transaction %s completed; host state restored.', [ATx.GetTxId]));
    except
      on E: Exception do
        Log('Unable to complete the transaction: ' + E.Message);
    end;
  end
  else
  begin
    ATx.SetError('Cleanup incomplete; the transaction will be recovered on the next start.');
    Log('Transaction left for recovery; some operations are not resolved.');
  end;
end;

procedure TPortableAppRunner.ImportPortableRegistry;
var
  RegistryFile: string;
begin
  if Length(FRegistryKeys) = 0 then
    Exit;

  RegistryFile := GetPortableRegistryFile;
  if not TFile.Exists(RegistryFile) then
  begin
    Log('No portable registry file found; skipping import: ' + RegistryFile);
    Exit;
  end;

  Log('Importing portable registry: ' + RegistryFile);
  if not FRegistryOps.ImportFile(RegistryFile) then
    raise EPortappixRunnerError.CreateFmt('reg.exe import failed for "%s".', [RegistryFile]);
end;

function TPortableAppRunner.ExportPortableRegistry: Boolean;
begin
  Result := ExportKeysToRegistryFile(FRegistryOps, FRegistryKeys, FDataDir, FOnLog);
end;

procedure TPortableAppRunner.BuildEnvironment;
var
  HostEnvironment: TDictionary<string, string>;
begin
  HostEnvironment := GetHostEnvironment;
  try
    FEnvironment.Clear;
    for var HostPair in HostEnvironment do
      FEnvironment.AddOrSetValue(HostPair.Key, HostPair.Value);

    for var ManifestPair in FManifest.Environment do
    begin
      var Value := ExpandTokens(ManifestPair.Value);
      Value := ExpandPercentVariables(Value);
      FEnvironment.AddOrSetValue(ManifestPair.Key, Value);
    end;
  finally
    HostEnvironment.Free;
  end;

  EnsureEnvironmentDirectories;
end;

procedure TPortableAppRunner.EnsureEnvironmentDirectories;
var
  DataPrefix: string;
begin
  ForceDirectories(FDataDir);
  DataPrefix := IncludeTrailingPathDelimiter(FDataDir);

  for var Pair in FManifest.Environment do
  begin
    if not IsFolderEnvironmentVariable(Pair.Key) then
      Continue;

    var Value: string;
    if not FEnvironment.TryGetValue(Pair.Key, Value) then
      Continue;
    if (Value = '') or (Pos(';', Value) > 0) then
      Continue;
    if TextStartsWith(Value, DataPrefix) then
      ForceDirectories(TrimTrailingPathDelimiter(Value));
  end;
end;

function TPortableAppRunner.ExpandTokens(const AValue: string): string;
begin
  Result := ExpandManifestTokens(AValue, FRootPath, FAppDir, FDataDir, FManifest.Id);
end;

function TPortableAppRunner.BuildEnvironmentBlock: string;
var
  Entries: TStringList;
  Builder: TStringBuilder;
begin
  Entries := TStringList.Create;
  try
    Entries.Sorted := True;
    Entries.CaseSensitive := False;

    for var Pair in FEnvironment do
      if Pair.Key <> '' then
        Entries.Add(Pair.Key + '=' + Pair.Value);

    Builder := TStringBuilder.Create;
    try
      for var Entry in Entries do
        Builder.Append(Entry).Append(#0);
      if Entries.Count = 0 then
        Builder.Append(#0);
      Builder.Append(#0);
      Result := Builder.ToString;
    finally
      Builder.Free;
    end;
  finally
    Entries.Free;
  end;
end;

function TPortableAppRunner.LaunchProcess(const AEnvironmentBlock: string): Cardinal;
var
  StartupInfo: TStartupInfo;
  ProcessInfo: TProcessInformation;
  CommandLine: string;
  CurrentDirectory: string;
  CurrentDirectoryPointer: PChar;
  EnvironmentBlock: string;
  ProcessExitCode: DWORD;
  LastError: DWORD;
  Job: TPortappixJob;
  Created: Boolean;
begin
  FillChar(StartupInfo, SizeOf(StartupInfo), 0);
  StartupInfo.cb := SizeOf(StartupInfo);

  CommandLine := QuoteArgument(FExePath);
  if FManifest.Args.Trim <> '' then
    CommandLine := CommandLine + ' ' + FManifest.Args;

  CurrentDirectory := TPath.GetDirectoryName(FExePath);
  CurrentDirectoryPointer := nil;
  if CurrentDirectory <> '' then
    CurrentDirectoryPointer := PChar(CurrentDirectory);

  EnvironmentBlock := AEnvironmentBlock;
  UniqueString(CommandLine);
  UniqueString(EnvironmentBlock);

  Job := TPortappixJob.Create;
  try
    Created := CreateProcess(nil, PChar(CommandLine), nil, nil, False,
      CREATE_SUSPENDED or CREATE_UNICODE_ENVIRONMENT, Pointer(PChar(EnvironmentBlock)),
      CurrentDirectoryPointer, StartupInfo, ProcessInfo);
    if not Created then
    begin
      LastError := GetLastError;
      if LastError = ERROR_ELEVATION_REQUIRED then
        raise EPortappixElevationRequired.CreateFmt(
          '"%s" requires administrator elevation. Portappix cannot redirect its environment ' +
          'when it runs elevated; run the launcher elevated or use a non-elevated build. ' +
          '(Error %u)', [FExePath, LastError]);
      raise EPortappixRunnerError.CreateFmt('Unable to start "%s": %s',
        [FExePath, SysErrorMessage(Integer(LastError))]);
    end;

    try
      if not Job.IsValid then
        Log('Job objects are not available; waiting for the main process only.')
      else if not Job.AssignProcess(ProcessInfo.hProcess) then
        Log('Unable to assign the process to a job object; waiting for the main process only.');

      if ResumeThread(ProcessInfo.hThread) = Cardinal(-1) then
        raise EPortappixRunnerError.CreateFmt('Unable to resume "%s": %s',
          [FExePath, SysErrorMessage(Integer(GetLastError))]);

      if Job.IsValid then
      begin
        if not Job.WaitForEmpty(INFINITE) then
          raise EPortappixRunnerError.CreateFmt(
            'Unable to wait for the process tree of "%s" to exit.', [FExePath]);
      end
      else if WaitForSingleObject(ProcessInfo.hProcess, INFINITE) <> WAIT_OBJECT_0 then
      begin
        LastError := GetLastError;
        raise EPortappixRunnerError.CreateFmt('Failed while waiting for "%s": %s',
          [FExePath, SysErrorMessage(Integer(LastError))]);
      end;

      if not GetExitCodeProcess(ProcessInfo.hProcess, ProcessExitCode) then
      begin
        LastError := GetLastError;
        raise EPortappixRunnerError.CreateFmt('Unable to read the exit code for "%s": %s',
          [FExePath, SysErrorMessage(Integer(LastError))]);
      end;

      Result := ProcessExitCode;
    finally
      CloseHandle(ProcessInfo.hThread);
      CloseHandle(ProcessInfo.hProcess);
    end;
  finally
    Job.Free;
  end;
end;

function TPortableAppRunner.RegistryKeyExists(const AKey: string): Boolean;
begin
  Result := FRegistryOps.KeyExists(AKey);
end;

function TPortableAppRunner.GetPortableRegistryFile: string;
begin
  Result := TPath.Combine(FDataDir, 'registry.reg');
end;

class procedure TPortableAppRunner.PerformCleanup(const AAppId: string;
  const AHijackedKeys: TArray<string>; const ADataDir: string;
  const ALog: TProc<string>);
var
  EmptyJunctions: TArray<string>;
begin
  SetLength(EmptyJunctions, 0);
  PerformCleanup(AAppId, AHijackedKeys, EmptyJunctions, ADataDir, ALog, nil);
end;

class procedure TPortableAppRunner.PerformCleanup(const AAppId: string;
  const AHijackedKeys: TArray<string>; const AJunctions: TArray<string>;
  const ADataDir: string; const ALog: TProc<string>;
  const ARegistryOps: IPortappixRegistryOps;
  const AHostPathOps: IPortappixHostPathOps);
var
  Ops: IPortappixRegistryOps;
  ExportSucceeded: Boolean;
begin
  if AAppId <> '' then
    CleanupLog(ALog, 'Cleaning up app state: ' + AAppId);

  Ops := ARegistryOps;
  if not Assigned(Ops) then
    Ops := TPortappixRegistryOps.Create;

  ExportSucceeded := True;
  if Length(AHijackedKeys) > 0 then
    ExportSucceeded := ExportKeysToRegistryFile(Ops, AHijackedKeys, ADataDir, ALog);

  if ExportSucceeded then
    DeleteKeysWithOps(Ops, AHijackedKeys, ALog)
  else
    CleanupLog(ALog, 'Host registry keys were left in place because the portable registry ' +
      'could not be saved; they will be retried.');

  RestoreBackupsWithOps(Ops, AHijackedKeys, ADataDir, ALog);
  RemoveJunctionsWithLogOps(AJunctions, ALog, AHostPathOps);
end;

end.