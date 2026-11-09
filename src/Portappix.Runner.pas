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
  System.Win.Registry,
  Portappix.Manifest;

type
  EPortappixRunnerError = class(Exception);

  IPortappixJournal = interface
    ['{B8A13E7E-3A9D-4B0B-9C13-6F4E9E2C4D51}']
    procedure AddActiveApp(const AAppId: string; const AHijackedKeys: TArray<string>;
      const AJunctions: TArray<string>);
    procedure RemoveActiveApp(const AAppId: string);
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
    procedure CleanupHostRegistry;
    procedure DeleteRegistryKeys(const AKeys: TArray<string>);
    function HostBackupFile(const AIndex: Integer): string;
    procedure BackupHostRegistryKeys;
    procedure RestoreHostRegistryBackups;
    function ImportRegistryFile(const AFileName: string): Boolean;
    function DeleteRegistryFile(const AFileName: string): Boolean;
    function RegistryKeyExists(const AKey: string): Boolean;
    function GetPortableRegistryFile: string;
    function ExportRegistryKey(const AKey, AFileName: string): Boolean;
    function MergeRegistryFiles(const AFiles: TArray<string>;
      const ADestination: string): Boolean;
  public
    constructor Create(const AManifestPath: string; const ARootPath: string = '');
      overload;
    constructor Create(const AManifestPath: string; const AJournal: IPortappixJournal;
      const ARootPath: string = ''); overload;
    destructor Destroy; override;
    function Run: Cardinal;
    class procedure PerformCleanup(const AAppId: string; const AHijackedKeys: TArray<string>;
      const ADataDir: string; const ALog: TProc<string> = nil); overload; static;
    class procedure PerformCleanup(const AAppId: string; const AHijackedKeys: TArray<string>;
      const AJunctions: TArray<string>; const ADataDir: string;
      const ALog: TProc<string> = nil); overload; static;
    property Manifest: TPortappixManifest read FManifest;
    property ManifestPath: string read FManifestPath;
    property RootPath: string read FRootPath;
    property AppDirectory: string read FAppDir;
    property DataDirectory: string read FDataDir;
    property ExecutablePath: string read FExePath;
    property ExitCode: Cardinal read FExitCode;
    property OnLog: TProc<string> read FOnLog write FOnLog;
  end;

implementation

const
  RegistryFileHeader = 'Windows Registry Editor Version 5.00';

function QuoteArgument(const AValue: string): string;
begin
  Result := '"' + StringReplace(AValue, '"', '\"', [rfReplaceAll]) + '"';
end;

function TrimTrailingPathDelimiter(const APath: string): string;
begin
  Result := APath;
  if (Length(Result) <= 1) or (Result[Length(Result)] <> '\') then
    Exit;

  if (Length(Result) = 3) and (Result[2] = ':') then
    Exit;

  Result := Copy(Result, 1, Length(Result) - 1);
end;

function LauncherDirectory: string;
begin
  Result := TPath.GetDirectoryName(ParamStr(0));
  if Result = '' then
    Result := GetCurrentDir;
end;

function IsRelativePath(const APath: string): Boolean;
begin
  if APath = '' then
    Exit(True);
  if (Length(APath) >= 2) and (APath[2] = ':') then
    Exit(False);
  if (Length(APath) >= 2) and (APath[1] = '\') and (APath[2] = '\') then
    Exit(False);
  if APath[1] = '\' then
    Exit(False);

  Result := True;
end;

function ResolveFromLauncher(const APath: string): string;
begin
  if IsRelativePath(APath) then
    Result := TPath.GetFullPath(TPath.Combine(LauncherDirectory, APath))
  else
    Result := TPath.GetFullPath(APath);
end;

function RegExePath: string;
var
  WindowsDirectory: array[0..MAX_PATH] of Char;
  WindowsPath: string;
begin
  if GetWindowsDirectory(WindowsDirectory, MAX_PATH) > 0 then
  begin
    WindowsPath := PChar(@WindowsDirectory[0]);
    Result := TPath.Combine(WindowsPath, 'System32\reg.exe');
  end
  else
    Result := 'reg.exe';
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

function IsReparsePoint(const APath: string): Boolean;
var
  Attributes: DWORD;
begin
  Attributes := GetFileAttributes(PChar(APath));
  Result := (Attributes <> INVALID_FILE_ATTRIBUTES) and
    ((Attributes and FILE_ATTRIBUTE_REPARSE_POINT) <> 0);
end;

function HostJunctionBackupPath(const AHostPath: string): string;
begin
  Result := AHostPath + '_host_backup';
end;

function MakeDirectoryJunction(const AHostPath, ATargetPath: string;
  out AExitCode: Cardinal): Boolean;
begin
  Result := RunHiddenProcess(
    'cmd.exe /c mklink /J ' + QuoteArgument(AHostPath) + ' ' + QuoteArgument(ATargetPath),
    AExitCode);
end;

function RemoveDirectoryJunction(const AHostPath: string; out AExitCode: Cardinal): Boolean;
begin
  Result := RunHiddenProcess('cmd.exe /c rmdir ' + QuoteArgument(AHostPath), AExitCode);
  if not Result or (AExitCode <> 0) then
    if TDirectory.Exists(AHostPath) and IsReparsePoint(AHostPath) then
      Result := RemoveDir(AHostPath);
end;

function ParseRegistryPath(const APath: string; out ARootKey: HKEY;
  out ASubKey: string): Boolean;
var
  Value: string;
  RootName: string;
  SeparatorPosition: Integer;
begin
  Result := False;
  ARootKey := 0;
  ASubKey := '';

  Value := APath.Trim;
  if Value = '' then
    Exit;

  SeparatorPosition := Pos('\', Value);
  if SeparatorPosition > 0 then
  begin
    RootName := Copy(Value, 1, SeparatorPosition - 1);
    ASubKey := Copy(Value, SeparatorPosition + 1, MaxInt);
  end
  else
  begin
    RootName := Value;
    ASubKey := '';
  end;

  if SameText(RootName, 'HKCU') or SameText(RootName, 'HKEY_CURRENT_USER') then
    ARootKey := HKEY_CURRENT_USER
  else if SameText(RootName, 'HKLM') or SameText(RootName, 'HKEY_LOCAL_MACHINE') then
    ARootKey := HKEY_LOCAL_MACHINE
  else if SameText(RootName, 'HKCR') or SameText(RootName, 'HKEY_CLASSES_ROOT') then
    ARootKey := HKEY_CLASSES_ROOT
  else if SameText(RootName, 'HKU') or SameText(RootName, 'HKEY_USERS') then
    ARootKey := HKEY_USERS
  else if SameText(RootName, 'HKCC') or SameText(RootName, 'HKEY_CURRENT_CONFIG') then
    ARootKey := HKEY_CURRENT_CONFIG
  else
    Exit;

  ASubKey := ASubKey.Trim(['\']);
  Result := ASubKey <> '';
end;

function RegistryRootText(const ARootKey: HKEY): string;
begin
  if ARootKey = HKEY_CURRENT_USER then
    Result := 'HKCU'
  else if ARootKey = HKEY_LOCAL_MACHINE then
    Result := 'HKLM'
  else if ARootKey = HKEY_CLASSES_ROOT then
    Result := 'HKCR'
  else if ARootKey = HKEY_USERS then
    Result := 'HKU'
  else if ARootKey = HKEY_CURRENT_CONFIG then
    Result := 'HKCC'
  else
    Result := '';
end;

function NormalizeRegistryPath(const APath: string): string;
var
  RootKey: HKEY;
  SubKey: string;
begin
  if APath.IndexOf(#0) >= 0 then
    raise EPortappixRunnerError.CreateFmt('Registry path contains a null character: "%s".', [APath]);

  Result := APath.Trim;
  while (Length(Result) > 0) and (Result[Length(Result)] = '\') do
    Delete(Result, Length(Result), 1);

  if not ParseRegistryPath(Result, RootKey, SubKey) then
    raise EPortappixRunnerError.CreateFmt('Invalid registry path in manifest: "%s".', [APath]);

  while Pos('\\', SubKey) > 0 do
    SubKey := StringReplace(SubKey, '\\', '\', [rfReplaceAll]);

  Result := RegistryRootText(RootKey) + '\' + SubKey;
end;

function GetHostEnvironment: TDictionary<string, string>;
var
  EnvironmentBlock: PChar;
  Entry: PChar;
  EntryText: string;
  SeparatorPosition: Integer;
begin
  Result := TDictionary<string, string>.Create(TStringComparer.OrdinalIgnoreCase);
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

function ExpandPercentVariables(const AValue: string;
  const AEnvironment: TDictionary<string, string>): string;
var
  StartPosition: Integer;
  EndPosition: Integer;
  VariableName: string;
  Replacement: string;
begin
  Result := AValue;
  StartPosition := 1;

  while StartPosition <= Length(Result) do
  begin
    if Result[StartPosition] <> '%' then
    begin
      Inc(StartPosition);
      Continue;
    end;

    EndPosition := PosEx('%', Result, StartPosition + 1);
    if EndPosition = 0 then
      Break;

    VariableName := Copy(Result, StartPosition + 1, EndPosition - StartPosition - 1);
    if (VariableName <> '') and AEnvironment.TryGetValue(VariableName, Replacement) then
    begin
      Result := Copy(Result, 1, StartPosition - 1) + Replacement +
        Copy(Result, EndPosition + 1, MaxInt);
      Inc(StartPosition, Length(Replacement));
    end
    else
      Inc(StartPosition, EndPosition - StartPosition + 1);
  end;
end;

function RunHiddenProcess(const ACommandLine: string; out AExitCode: Cardinal): Boolean;
var
  StartupInfo: TStartupInfo;
  ProcessInfo: TProcessInformation;
  CommandLine: string;
  ProcessExitCode: DWORD;
begin
  AExitCode := Cardinal(-1);

  FillChar(StartupInfo, SizeOf(StartupInfo), 0);
  StartupInfo.cb := SizeOf(StartupInfo);
  StartupInfo.dwFlags := STARTF_USESHOWWINDOW;
  StartupInfo.wShowWindow := SW_HIDE;

  CommandLine := ACommandLine;
  UniqueString(CommandLine);

  Result := CreateProcess(nil, PChar(CommandLine), nil, nil, False,
    CREATE_NO_WINDOW, nil, nil, StartupInfo, ProcessInfo);
  if not Result then
    Exit;

  try
    if WaitForSingleObject(ProcessInfo.hProcess, INFINITE) <> WAIT_OBJECT_0 then
    begin
      Result := False;
      Exit;
    end;

    if GetExitCodeProcess(ProcessInfo.hProcess, ProcessExitCode) then
      AExitCode := ProcessExitCode
    else
      Result := False;
  finally
    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
  end;
end;

constructor TPortableAppRunner.Create(const AManifestPath: string;
  const ARootPath: string);
begin
  Create(AManifestPath, nil, ARootPath);
end;

constructor TPortableAppRunner.Create(const AManifestPath: string;
  const AJournal: IPortappixJournal; const ARootPath: string);
begin
  inherited Create;
  FJournal := AJournal;
  try
    FManifestPath := ResolveFromLauncher(AManifestPath);

    if ARootPath = '' then
      FRootPath := LauncherDirectory
    else
      FRootPath := ResolveFromLauncher(ARootPath);

    FManifest := TPortappixManifest.LoadFromFile(FManifestPath);
    FAppDir := TPath.GetDirectoryName(FManifestPath);
    FEnvironment := TDictionary<string, string>.Create(TStringComparer.OrdinalIgnoreCase);
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
  inherited;
end;

function TPortableAppRunner.Run: Cardinal;
var
  EnvironmentBlock: string;
  Journaled: Boolean;
begin
  FExitCode := Cardinal(-1);
  Journaled := False;

  if not TFile.Exists(FExePath) then
    raise EPortappixRunnerError.CreateFmt('Executable not found: "%s".', [FExePath]);

  PrepareDataDirectories;
  BuildEnvironment;
  EnvironmentBlock := BuildEnvironmentBlock;
  try
    CreateJunctions;
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
    FExePath := TPath.GetFullPath(TPath.Combine(FRootPath, ExeValue))
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
  ExitCode: Cardinal;
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
            if not RemoveDirectoryJunction(HostPath, ExitCode) then
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
                [HostPath, BackupPath, SysErrorMessage(GetLastError)]);
          end
          else
            raise EPortappixRunnerError.CreateFmt(
              'Cannot create junction because a file exists at host path "%s".', [HostPath]);
        end;

        ForceDirectories(TPath.GetDirectoryName(HostPath));
        ForceDirectories(TargetPath);

        Log(Format('Creating junction "%s" -> "%s".', [HostPath, TargetPath]));
        if not MakeDirectoryJunction(HostPath, TargetPath, ExitCode) or (ExitCode <> 0) then
          raise EPortappixRunnerError.CreateFmt(
            'Unable to create junction "%s" -> "%s" (exit code %u).',
            [HostPath, TargetPath, ExitCode]);

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
var
  ExitCode: Cardinal;
  HostPath: string;
  BackupPath: string;
begin
  if Length(FCreatedJunctions) = 0 then
    Exit;

  try
    for var Index := High(FCreatedJunctions) downto 0 do
    begin
      HostPath := FCreatedJunctions[Index];
      BackupPath := HostJunctionBackupPath(HostPath);

      try
        if PathExists(HostPath) then
        begin
          if IsReparsePoint(HostPath) then
          begin
            Log('Removing junction: ' + HostPath);
            if not RemoveDirectoryJunction(HostPath, ExitCode) then
              Log('Unable to remove junction: ' + HostPath)
            else if PathExists(HostPath) then
              Log('Junction still exists after removal attempt: ' + HostPath);
          end
          else
            Log('Host path is not a junction; leaving it in place: ' + HostPath);
        end;

        if not PathExists(HostPath) and TDirectory.Exists(BackupPath) and
           not IsReparsePoint(BackupPath) then
        begin
          Log('Restoring host directory backup: ' + BackupPath);
          if not RenameFile(BackupPath, HostPath) then
            Log(Format('Unable to restore host directory "%s": %s',
              [HostPath, SysErrorMessage(GetLastError)]));
        end;
      except
        on E: Exception do
          Log(Format('Error cleaning up junction "%s": %s', [HostPath, E.Message]));
      end;
    end;
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
      Value := ExpandPercentVariables(Value, HostEnvironment);
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
    if Value.StartsWith(DataPrefix, True) then
      ForceDirectories(TrimTrailingPathDelimiter(Value));
  end;
end;

function TPortableAppRunner.ExpandTokens(const AValue: string): string;
begin
  Result := AValue;
  Result := StringReplace(Result, '{root}', TrimTrailingPathDelimiter(FRootPath),
    [rfReplaceAll, rfIgnoreCase]);
  Result := StringReplace(Result, '{app}', TrimTrailingPathDelimiter(FAppDir),
    [rfReplaceAll, rfIgnoreCase]);
  Result := StringReplace(Result, '{data}', TrimTrailingPathDelimiter(FDataDir),
    [rfReplaceAll, rfIgnoreCase]);
  Result := StringReplace(Result, '{id}', FManifest.Id, [rfReplaceAll, rfIgnoreCase]);
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
begin
  FillChar(StartupInfo, SizeOf(StartupInfo), 0);
  StartupInfo.cb := SizeOf(StartupInfo);

  CommandLine := QuoteArgument(FExePath);

  CurrentDirectory := TPath.GetDirectoryName(FExePath);
  CurrentDirectoryPointer := nil;
  if CurrentDirectory <> '' then
    CurrentDirectoryPointer := PChar(CurrentDirectory);

  EnvironmentBlock := AEnvironmentBlock;
  UniqueString(CommandLine);
  UniqueString(EnvironmentBlock);

  if not CreateProcess(nil, PChar(CommandLine), nil, nil, False,
    CREATE_UNICODE_ENVIRONMENT, Pointer(PChar(EnvironmentBlock)),
    CurrentDirectoryPointer, StartupInfo, ProcessInfo) then
  begin
    LastError := GetLastError;
    raise EPortappixRunnerError.CreateFmt('Unable to start "%s": %s',
      [FExePath, SysErrorMessage(Integer(LastError))]);
  end;

  try
    if WaitForSingleObject(ProcessInfo.hProcess, INFINITE) <> WAIT_OBJECT_0 then
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
end;

procedure TPortableAppRunner.ImportPortableRegistry;
var
  RegistryFile: string;
  ExitCode: Cardinal;
begin
  if Length(FRegistryKeys) = 0 then
    Exit;

  BackupHostRegistryKeys;

  RegistryFile := GetPortableRegistryFile;
  if not TFile.Exists(RegistryFile) then
  begin
    Log('No portable registry file found; skipping import: ' + RegistryFile);
    Exit;
  end;

  Log('Importing portable registry: ' + RegistryFile);
  if not RunHiddenProcess(Format('%s import %s',
    [QuoteArgument(RegExePath), QuoteArgument(RegistryFile)]), ExitCode) then
    raise EPortappixRunnerError.CreateFmt('Unable to start reg.exe to import "%s".',
      [RegistryFile]);

  if ExitCode <> 0 then
    raise EPortappixRunnerError.CreateFmt('reg.exe import failed for "%s" (exit code %u).',
      [RegistryFile, ExitCode]);
end;

function TPortableAppRunner.ExportPortableRegistry: Boolean;
var
  TemporaryFiles: TList<string>;
  ExportedFiles: TList<string>;
begin
  Result := True;
  if Length(FRegistryKeys) = 0 then
    Exit;

  ForceDirectories(FDataDir);
  TemporaryFiles := TList<string>.Create;
  ExportedFiles := TList<string>.Create;
  try
    var Index := 0;
    for var Key in FRegistryKeys do
    begin
      try
        if not RegistryKeyExists(Key) then
        begin
          Log('Registry key is not present after run: ' + Key);
          Continue;
        end;
      except
        on E: Exception do
        begin
          Result := False;
          Log(Format('Unable to check registry key "%s": %s', [Key, E.Message]));
          Continue;
        end;
      end;

      var TemporaryFile := TPath.Combine(FDataDir,
        Format('registry.export.%u.%d.reg', [GetCurrentProcessId, Index]));
      Inc(Index);
      TemporaryFiles.Add(TemporaryFile);
      if TFile.Exists(TemporaryFile) then
        TFile.Delete(TemporaryFile);

      if ExportRegistryKey(Key, TemporaryFile) then
        ExportedFiles.Add(TemporaryFile)
      else
      begin
        Result := False;
        Log('Unable to export registry key: ' + Key);
      end;
    end;

    if ExportedFiles.Count > 0 then
    begin
      if MergeRegistryFiles(ExportedFiles.ToArray, GetPortableRegistryFile) then
        Log('Portable registry saved: ' + GetPortableRegistryFile)
      else
        Log('Registry keys contained no data to save.');
    end
    else
      Log('No registry keys were available to export.');
  finally
    for var TemporaryFile in TemporaryFiles do
      if TFile.Exists(TemporaryFile) then
        try
          TFile.Delete(TemporaryFile);
        except
          on E: Exception do
            Log('Unable to delete temporary registry export "%s": %s',
              [TemporaryFile, E.Message]);
        end;
    TemporaryFiles.Free;
    ExportedFiles.Free;
  end;
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
      DeleteRegistryKeys(FRegistryKeys);
    except
      on E: Exception do
        Log('Failed to delete host registry keys: ' + E.Message);
    end;
  end
  else
    Log('Host registry keys were left in place because the portable registry could not be saved.');

  RestoreHostRegistryBackups;
end;

procedure TPortableAppRunner.DeleteRegistryKeys(const AKeys: TArray<string>);
var
  ExitCode: Cardinal;
begin
  for var Key in AKeys do
  begin
    try
      if not RunHiddenProcess(Format('%s delete %s /f',
        [QuoteArgument(RegExePath), QuoteArgument(Key)]), ExitCode) then
      begin
        Log('Unable to start reg.exe to delete registry key: ' + Key);
        Continue;
      end;

      if ExitCode = 0 then
        Log('Removed registry key from host: ' + Key)
      else
        Log(Format('Registry key not removed (exit code %u): %s', [ExitCode, Key]));
    except
      on E: Exception do
        Log(Format('Error deleting registry key "%s": %s', [Key, E.Message]));
    end;
  end;
end;

function TPortableAppRunner.RegistryKeyExists(const AKey: string): Boolean;
var
  RootKey: HKEY;
  SubKey: string;
begin
  if not ParseRegistryPath(AKey, RootKey, SubKey) then
    raise EPortappixRunnerError.CreateFmt('Invalid registry path: "%s".', [AKey]);

  var Registry := TRegistry.Create(KEY_READ);
  try
    Registry.RootKey := RootKey;
    Result := Registry.KeyExists(SubKey);
  finally
    Registry.Free;
  end;
end;

function TPortableAppRunner.HostBackupFile(const AIndex: Integer): string;
begin
  Result := TPath.Combine(FDataDir, Format('host_backup_%d.reg', [AIndex]));
end;

function TPortableAppRunner.ImportRegistryFile(const AFileName: string): Boolean;
var
  ExitCode: Cardinal;
begin
  if not RunHiddenProcess(Format('%s import %s',
    [QuoteArgument(RegExePath), QuoteArgument(AFileName)]), ExitCode) then
  begin
    Log('Unable to start reg.exe to import registry file: ' + AFileName);
    Exit(False);
  end;

  Result := ExitCode = 0;
  if not Result then
    Log(Format('reg.exe import failed for "%s" (exit code %u).', [AFileName, ExitCode]));
end;

function TPortableAppRunner.DeleteRegistryFile(const AFileName: string): Boolean;
begin
  try
    if TFile.Exists(AFileName) then
      TFile.Delete(AFileName);
    Result := True;
  except
    on E: Exception do
    begin
      Log(Format('Unable to delete registry file "%s": %s', [AFileName, E.Message]));
      Result := False;
    end;
  end;
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
      if TFile.Exists(BackupFile) and not DeleteRegistryFile(BackupFile) then
        raise EPortappixRunnerError.CreateFmt(
          'Unable to replace existing host registry backup "%s".', [BackupFile]);

      if not RegistryKeyExists(Key) then
        Continue;

      Log('Backing up host registry key: ' + Key);
      if not ExportRegistryKey(Key, BackupFile) then
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

class procedure TPortableAppRunner.PerformCleanup(const AAppId: string;
  const AHijackedKeys: TArray<string>; const ADataDir: string;
  const ALog: TProc<string>);
var
  EmptyJunctions: TArray<string>;
begin
  SetLength(EmptyJunctions, 0);
  PerformCleanup(AAppId, AHijackedKeys, EmptyJunctions, ADataDir, ALog);
end;

class procedure TPortableAppRunner.PerformCleanup(const AAppId: string;
  const AHijackedKeys: TArray<string>; const AJunctions: TArray<string>;
  const ADataDir: string; const ALog: TProc<string>);

  procedure WriteLog(const AMessage: string);
  begin
    if Assigned(ALog) then
      ALog(AMessage);
  end;

  function BackupFile(const AIndex: Integer): string;
  begin
    Result := TPath.Combine(ADataDir, Format('host_backup_%d.reg', [AIndex]));
  end;

  function ImportBackup(const AFileName: string): Boolean;
  var
    ExitCode: Cardinal;
  begin
    if not RunHiddenProcess(Format('%s import %s',
      [QuoteArgument(RegExePath), QuoteArgument(AFileName)]), ExitCode) then
    begin
      WriteLog('Unable to start reg.exe to import registry backup: ' + AFileName);
      Exit(False);
    end;

    Result := ExitCode = 0;
    if not Result then
      WriteLog(Format('reg.exe import failed for "%s" (exit code %u).', [AFileName, ExitCode]));
  end;

  function DeleteFileQuiet(const AFileName: string): Boolean;
  begin
    try
      if TFile.Exists(AFileName) then
        TFile.Delete(AFileName);
      Result := True;
    except
      on E: Exception do
      begin
        WriteLog(Format('Unable to delete file "%s": %s', [AFileName, E.Message]));
        Result := False;
      end;
    end;
  end;

  procedure DeleteKeys;
  var
    ExitCode: Cardinal;
  begin
    for var Key in AHijackedKeys do
    begin
      try
        if not RunHiddenProcess(Format('%s delete %s /f',
          [QuoteArgument(RegExePath), QuoteArgument(Key)]), ExitCode) then
        begin
          WriteLog('Unable to start reg.exe to delete registry key: ' + Key);
          Continue;
        end;

        if ExitCode = 0 then
          WriteLog('Removed registry key from host: ' + Key)
        else
          WriteLog(Format('Registry key not removed (exit code %u): %s', [ExitCode, Key]));
      except
        on E: Exception do
          WriteLog(Format('Error deleting registry key "%s": %s', [Key, E.Message]));
      end;
    end;
  end;

  function JunctionBackupPath(const AHostPath: string): string;
  begin
    Result := AHostPath + '_host_backup';
  end;

  function IsReparse(const APath: string): Boolean;
  var
    Attributes: DWORD;
  begin
    Attributes := GetFileAttributes(PChar(APath));
    Result := (Attributes <> INVALID_FILE_ATTRIBUTES) and
      ((Attributes and FILE_ATTRIBUTE_REPARSE_POINT) <> 0);
  end;

  procedure RestoreBackups;
  begin
    for var Index := 0 to High(AHijackedKeys) do
    begin
      var FileName := BackupFile(Index);
      if not TFile.Exists(FileName) then
        Continue;

      WriteLog('Restoring host registry backup: ' + FileName);
      if ImportBackup(FileName) then
        DeleteFileQuiet(FileName)
      else
        WriteLog('Host registry backup was not removed so it can be retried: ' + FileName);
    end;
  end;

  procedure RemoveJunctions;
  var
    ExitCode: Cardinal;
  begin
    for var Index := High(AJunctions) downto 0 do
    begin
      var HostPath := AJunctions[Index];
      var BackupPath := JunctionBackupPath(HostPath);
      try
        if TDirectory.Exists(HostPath) or TFile.Exists(HostPath) then
        begin
          if IsReparse(HostPath) then
          begin
            WriteLog('Removing junction: ' + HostPath);
            if not RunHiddenProcess('cmd.exe /c rmdir ' + QuoteArgument(HostPath), ExitCode) then
              WriteLog('Unable to start junction removal for: ' + HostPath)
            else if (ExitCode <> 0) and IsReparse(HostPath) then
              if not RemoveDir(HostPath) then
                WriteLog(Format('Junction not removed (exit code %u): %s', [ExitCode, HostPath]));
            if TDirectory.Exists(HostPath) and IsReparse(HostPath) then
              WriteLog('Junction still exists after removal attempt: ' + HostPath);
          end
          else
            WriteLog('Host path is not a junction; leaving it in place: ' + HostPath);
        end;

        if not (TDirectory.Exists(HostPath) or TFile.Exists(HostPath)) and
           TDirectory.Exists(BackupPath) and not IsReparse(BackupPath) then
        begin
          WriteLog('Restoring host directory backup: ' + BackupPath);
          if not RenameFile(BackupPath, HostPath) then
            WriteLog(Format('Unable to restore host directory "%s": %s',
              [HostPath, SysErrorMessage(GetLastError)]));
        end;
      except
        on E: Exception do
          WriteLog(Format('Error cleaning up junction "%s": %s', [HostPath, E.Message]));
      end;
    end;
  end;

begin
  if AAppId <> '' then
    WriteLog('Cleaning up app state: ' + AAppId);

  RemoveJunctions;
  DeleteKeys;
  if ADataDir <> '' then
    RestoreBackups;
end;

procedure TPortableAppRunner.RestoreHostRegistryBackups;
begin
  PerformCleanup(FManifest.Id, FRegistryKeys, [], FDataDir, FOnLog);
end;

function TPortableAppRunner.GetPortableRegistryFile: string;
begin
  Result := TPath.Combine(FDataDir, 'registry.reg');
end;

function TPortableAppRunner.ExportRegistryKey(const AKey, AFileName: string): Boolean;
var
  ExitCode: Cardinal;
begin
  if not RunHiddenProcess(Format('%s export %s %s /y',
    [QuoteArgument(RegExePath), QuoteArgument(AKey), QuoteArgument(AFileName)]),
    ExitCode) then
    Exit(False);

  Result := ExitCode = 0;
end;

function TPortableAppRunner.MergeRegistryFiles(const AFiles: TArray<string>;
  const ADestination: string): Boolean;
var
  Builder: TStringBuilder;
  Lines: TStringList;
  Content: string;
  HasContent: Boolean;
begin
  Result := False;
  Builder := TStringBuilder.Create;
  Lines := TStringList.Create;
  try
    Builder.AppendLine(RegistryFileHeader);
    Builder.AppendLine;
    HasContent := False;

    for var FileName in AFiles do
    begin
      Content := TFile.ReadAllText(FileName, TEncoding.Unicode);
      if (Content <> '') and (Content[1] = #$FEFF) then
        Content := Content.Substring(1);

      Lines.Text := Content;
      var StartLine := 0;
      if (Lines.Count > 0) and
         (Lines[0].Trim.StartsWith('Windows Registry Editor', True) or
          SameText(Lines[0].Trim, 'REGEDIT4')) then
        StartLine := 1;

      while (StartLine < Lines.Count) and (Lines[StartLine].Trim = '') do
        Inc(StartLine);

      if StartLine < Lines.Count then
      begin
        HasContent := True;
        for var LineIndex := StartLine to Lines.Count - 1 do
          Builder.AppendLine(Lines[LineIndex]);
        Builder.AppendLine;
      end;
    end;

    if HasContent then
    begin
      TFile.WriteAllText(ADestination, Builder.ToString, TEncoding.Unicode);
      Result := True;
    end;
  finally
    Lines.Free;
    Builder.Free;
  end;
end;

end.
