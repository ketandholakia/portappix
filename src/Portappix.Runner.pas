unit Portappix.Runner;

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
    ['{B8A13E7E-3A9D-4B0B-9C13-6F4E9E2C4D51}']
    procedure AddActiveApp(const AAppId: string; const AHijackedKeys: TArray<string>;
      const AJunctions: TArray<string>);
    procedure RemoveActiveApp(const AAppId: string);
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
    FCreatedJunctions: TArray<string>;
    FExitCode: Cardinal;
    FOnLog: TProc<string>;
    FJournal: IPortappixJournal;
    FRegistryOps: IPortappixRegistryOps;
    procedure Log(const AMessage: string);
    procedure ResolvePaths;
    procedure ResolveRegistryKeys;
    procedure PrepareDataDirectories;
    procedure BuildEnvironment;
    procedure EnsureEnvironmentDirectories;
    function ExpandTokens(const AValue: string): string;
    function BuildEnvironmentBlock: string;
    function LaunchProcess(const AEnvironmentBlock: string): Cardinal;
    procedure CreateJunctions;
    procedure RemoveJunctions;
    procedure ImportPortableRegistry;
    function ExportPortableRegistry: Boolean;
    procedure CleanupHostRegistry;
    procedure DeleteHostRegistryKeys;
    function HostBackupFile(const AIndex: Integer): string;
    procedure BackupHostRegistryKeys;
    procedure RestoreHostRegistryBackups;
    function RegistryKeyExists(const AKey: string): Boolean;
    function GetPortableRegistryFile: string;
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
      const ARegistryOps: IPortappixRegistryOps = nil); overload; static;
    property Manifest: TPortappixManifest read FManifest;
    property ManifestPath: string read FManifestPath;
    property RootPath: string read FRootPath;
    property AppDirectory: string read FAppDir;
    property DataDirectory: string read FDataDir;
    property ExecutablePath: string read FExePath;
    property ExitCode: Cardinal read FExitCode;
    property OnLog: TProc<string> read FOnLog write FOnLog;
    property RegistryOps: IPortappixRegistryOps read FRegistryOps write FRegistryOps;
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
      end;
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
        CleanupLog(ALog, 'Host registry backup was not removed so it can be retried: ' + FileName);
    except
      on E: Exception do
        CleanupLog(ALog, Format('Unable to restore host registry backup "%s": %s',
          [FileName, E.Message]));
    end;
  end;
end;

function RemoveJunctionsWithLog(const AJunctions: TArray<string>;
  const ALog: TProc<string>): Boolean;
begin
  Result := True;
  for var Index := High(AJunctions) downto 0 do
  begin
    var HostPath := AJunctions[Index];
    var BackupPath := HostJunctionBackupPath(HostPath);
    try
      if PathExists(HostPath) then
      begin
        if IsReparsePoint(HostPath) then
        begin
          CleanupLog(ALog, 'Removing junction: ' + HostPath);
          if not DeleteJunction(HostPath) then
          begin
            Result := False;
            CleanupLog(ALog, 'Unable to remove junction: ' + HostPath);
          end;
        end
        else
          CleanupLog(ALog, 'Host path is not a junction; leaving it in place: ' + HostPath);
      end;

      if not PathExists(HostPath) and TDirectory.Exists(BackupPath) and
         not IsReparsePoint(BackupPath) then
      begin
        CleanupLog(ALog, 'Restoring host directory backup: ' + BackupPath);
        if not RenameFile(BackupPath, HostPath) then
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

  try
    FRootPath := ResolveRootPath(ARootPath);
    FManifestPath := ResolveFromRoot(FRootPath, AManifestPath);
    FManifest := TPortappixManifest.LoadFromFile(FManifestPath);
    FAppDir := TPath.GetDirectoryName(FManifestPath);
    FEnvironment := TDictionary<string, string>.Create(TIStringComparer.Ordinal);
    FJunctions := TDictionary<string, string>.Create(TIStringComparer.Ordinal);
    ResolvePaths;
  except
    FJournal := nil;
    FreeAndNil(FJunctions);
    FreeAndNil(FEnvironment);
    FreeAndNil(FManifest);
    raise;
  end;
end;

destructor TPortableAppRunner.Destroy;
begin
  FreeAndNil(FJunctions);
  FreeAndNil(FEnvironment);
  FreeAndNil(FManifest);
  FJournal := nil;
  FRegistryOps := nil;
  inherited;
end;

function TPortableAppRunner.Run: Cardinal;
var
  EnvironmentBlock: string;
  Journaled: Boolean;
  Policy: TPolicyResult;
begin
  FExitCode := Cardinal(-1);
  Journaled := False;

  Policy := TPortappixPolicy.ValidateManifest(FManifest);
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

  PrepareDataDirectories;
  BuildEnvironment;
  EnvironmentBlock := BuildEnvironmentBlock;
  try
    CreateJunctions;
    BackupHostRegistryKeys;
    DeleteHostRegistryKeys;
    ImportPortableRegistry;
  except
    try
      RemoveJunctions;
      RestoreHostRegistryBackups;
    except
      on E: Exception do
        Log('Failed to roll back pre-launch state: ' + E.Message);
    end;
    raise;
  end;

  if Assigned(FJournal) then
  begin
    try
      FJournal.AddActiveApp(FManifest.Id, FRegistryKeys, FCreatedJunctions);
      Journaled := True;
    except
      on E: Exception do
        Log('Unable to record the active app in the journal: ' + E.Message);
    end;
  end;

  Log(Format('Launching "%s".', [FExePath]));
  try
    FExitCode := LaunchProcess(EnvironmentBlock);
  finally
    try
      CleanupHostRegistry;
      RemoveJunctions;
    finally
      if Journaled and Assigned(FJournal) then
        try
          FJournal.RemoveActiveApp(FManifest.Id);
        except
          on E: Exception do
            Log('Unable to remove the active app from the journal: ' + E.Message);
        end;
    end;
  end;

  Log(Format('Application exited with code %u.', [FExitCode]));
  Result := FExitCode;
end;

procedure TPortableAppRunner.Log(const AMessage: string);
begin
  if Assigned(FOnLog) then
    FOnLog(AMessage);
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

  SetLength(FCreatedJunctions, 0);
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

procedure TPortableAppRunner.CreateJunctions;
var
  Created: TList<string>;
  BackupPath: string;
begin
  SetLength(FCreatedJunctions, 0);
  if FJunctions.Count = 0 then
    Exit;

  Created := TList<string>.Create;
  try
    try
      for var Pair in FJunctions do
      begin
        var HostPath := TrimTrailingPathDelimiter(Pair.Key);
        var TargetPath := TrimTrailingPathDelimiter(Pair.Value);
        BackupPath := HostJunctionBackupPath(HostPath);

        if PathExists(BackupPath) then
          raise EPortappixRunnerError.CreateFmt(
            'Cannot create junction for "%s" because a host backup path already exists: "%s".',
            [HostPath, BackupPath]);

        if PathExists(HostPath) then
        begin
          if IsReparsePoint(HostPath) then
          begin
            Log('Removing existing junction/reparse point before launch: ' + HostPath);
            if not DeleteJunction(HostPath) then
              raise EPortappixRunnerError.CreateFmt(
                'Unable to remove existing junction "%s".', [HostPath]);
            if PathExists(HostPath) then
              raise EPortappixRunnerError.CreateFmt(
                'Existing junction was not removed: "%s".', [HostPath]);
          end
          else if TDirectory.Exists(HostPath) then
          begin
            Log('Backing up existing host directory: ' + HostPath);
            if not RenameFile(HostPath, BackupPath) then
              raise EPortappixRunnerError.CreateFmt(
                'Unable to rename host directory "%s" to "%s": %s',
                [HostPath, BackupPath, SysErrorMessage(Integer(GetLastError))]);
          end
          else
            raise EPortappixRunnerError.CreateFmt(
              'Cannot create junction because a file exists at host path "%s".', [HostPath]);
        end;

        ForceDirectories(TPath.GetDirectoryName(HostPath));
        ForceDirectories(TargetPath);

        Log(Format('Creating junction "%s" -> "%s".', [HostPath, TargetPath]));
        if not CreateJunction(HostPath, TargetPath) then
          raise EPortappixRunnerError.CreateFmt(
            'Unable to create junction "%s" -> "%s": %s',
            [HostPath, TargetPath, SysErrorMessage(Integer(GetLastError))]);

        Created.Add(HostPath);
      end;

      FCreatedJunctions := Created.ToArray;
    except
      FCreatedJunctions := Created.ToArray;
      try
        RemoveJunctions;
      except
        on E: Exception do
          Log('Failed to roll back junctions: ' + E.Message);
      end;
      raise;
    end;
  finally
    Created.Free;
  end;
end;

procedure TPortableAppRunner.RemoveJunctions;
begin
  if Length(FCreatedJunctions) = 0 then
    Exit;
  try
    RemoveJunctionsWithLog(FCreatedJunctions, FOnLog);
  finally
    SetLength(FCreatedJunctions, 0);
  end;
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

procedure TPortableAppRunner.CleanupHostRegistry;
var
  ExportSucceeded: Boolean;
begin
  ExportSucceeded := False;
  try
    ExportSucceeded := ExportPortableRegistry;
  except
    on E: Exception do
      Log('Failed to export the portable registry: ' + E.Message);
  end;

  if ExportSucceeded then
  begin
    try
      DeleteHostRegistryKeys;
    except
      on E: Exception do
        Log('Failed to delete host registry keys: ' + E.Message);
    end;
  end
  else
    Log('Host registry keys were left in place because the portable registry could not be saved.');

  RestoreHostRegistryBackups;
end;

procedure TPortableAppRunner.DeleteHostRegistryKeys;
begin
  if Length(FRegistryKeys) = 0 then
    Exit;

  for var Key in FRegistryKeys do
  begin
    if not RegistryKeyExists(Key) then
      Continue;
    Log('Clearing host registry key: ' + Key);
    if not FRegistryOps.DeleteKey(Key) then
      raise EPortappixRunnerError.CreateFmt(
        'Unable to clear host registry key "%s".', [Key]);
  end;
end;

function TPortableAppRunner.RegistryKeyExists(const AKey: string): Boolean;
begin
  Result := FRegistryOps.KeyExists(AKey);
end;

function TPortableAppRunner.HostBackupFile(const AIndex: Integer): string;
begin
  Result := TPath.Combine(FDataDir, Format('host_backup_%d.reg', [AIndex]));
end;

procedure TPortableAppRunner.BackupHostRegistryKeys;
begin
  if Length(FRegistryKeys) = 0 then
    Exit;

  ForceDirectories(FDataDir);

  for var Index := 0 to High(FRegistryKeys) do
  begin
    var Key := FRegistryKeys[Index];
    var BackupFile := HostBackupFile(Index);

    try
      if TFile.Exists(BackupFile) then
        raise EPortappixRunnerError.CreateFmt(
          'A host registry backup from a previous run already exists: "%s". ' +
          'Recover it before launching this app again.', [BackupFile]);

      if not RegistryKeyExists(Key) then
        Continue;

      Log('Backing up host registry key: ' + Key);
      if not FRegistryOps.ExportKey(Key, BackupFile) then
        raise EPortappixRunnerError.CreateFmt(
          'Unable to export host registry key backup for "%s".', [Key]);
    except
      on E: Exception do
      begin
        Log('Host registry backup failed; restoring any completed backups.');
        RestoreHostRegistryBackups;
        raise EPortappixRunnerError.CreateFmt(
          'Unable to back up host registry key "%s": %s', [Key, E.Message]);
      end;
    end;
  end;
end;

procedure TPortableAppRunner.RestoreHostRegistryBackups;
begin
  RestoreBackupsWithOps(FRegistryOps, FRegistryKeys, FDataDir, FOnLog);
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
  const ARegistryOps: IPortappixRegistryOps);
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
  RemoveJunctionsWithLog(AJunctions, ALog);
end;

end.
