unit Portappix.State;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes,
  System.DateUtils,
  System.IOUtils,
  System.JSON,
  System.Generics.Collections,
  Portappix.Runner;

type
  EPortappixStateError = class(Exception);

  TPortappixJournal = class(TInterfacedObject, IPortappixJournal)
  private
    FRootPath: string;
    FStateFile: string;
    FOnLog: TProc<string>;
    procedure Log(const AMessage: string);
    function LoadState: TJSONObject;
    procedure SaveState(const AState: TJSONObject);
    function GetAppsObject(const AState: TJSONObject; const ACreate: Boolean): TJSONObject;
    function ReadStringArray(const AEntry: TJSONObject; const AName: string): TArray<string>;
    function ReadHijackedKeys(const AEntry: TJSONObject): TArray<string>;
    function ReadJunctions(const AEntry: TJSONObject): TArray<string>;
    function ResolveDataDir(const AAppId: string; const AEntry: TJSONObject): string;
    procedure RestoreScannedBackups(const ADataDir: string);
    function IsSafeAppId(const AAppId: string): Boolean;
  public
    constructor Create(const ARootPath: string = '');
    procedure AddActiveApp(const AAppId: string; const AHijackedKeys: TArray<string>;
      const AJunctions: TArray<string>);
    procedure RemoveActiveApp(const AAppId: string);
    procedure RecoverPendingCleanups;
    property RootPath: string read FRootPath;
    property StateFile: string read FStateFile;
    property OnLog: TProc<string> read FOnLog write FOnLog;
  end;

implementation

function TryGetObjectValue(const AObject: TJSONObject; const AName: string;
  out AValue: TJSONObject): Boolean;
var
  Value: TJSONValue;
begin
  AValue := nil;
  if AObject = nil then
    Exit(False);

  Value := AObject.GetValue(AName);
  Result := (Value <> nil) and (Value is TJSONObject);
  if Result then
    AValue := TJSONObject(Value);
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

function ResolveRootPath(const APath: string): string;
begin
  if APath = '' then
    Exit(TPath.GetFullPath(LauncherDirectory));

  if IsRelativePath(APath) then
    Result := TPath.GetFullPath(TPath.Combine(LauncherDirectory, APath))
  else
    Result := TPath.GetFullPath(APath);
end;

function IsSafeFileComponent(const AValue: string): Boolean;
const
  InvalidCharacters: TSysCharSet = ['\', '/', ':', '*', '?', '"', '<', '>', '|'];
begin
  Result := (AValue <> '') and (AValue <> '.') and (AValue <> '..');
  if not Result then
    Exit;

  for var Character in AValue do
    if (Character < ' ') or CharInSet(Character, InvalidCharacters) then
      Exit(False);
end;

function StateDirectory(const AStateFile: string): string;
begin
  Result := TPath.GetDirectoryName(AStateFile);
  if Result <> '' then
    ForceDirectories(Result);
end;

constructor TPortappixJournal.Create(const ARootPath: string);
begin
  inherited Create;
  FRootPath := ResolveRootPath(ARootPath);
  FStateFile := TPath.Combine(FRootPath, 'run_state.json');
end;

procedure TPortappixJournal.Log(const AMessage: string);
begin
  if Assigned(FOnLog) then
    FOnLog(AMessage);
end;

function TPortappixJournal.IsSafeAppId(const AAppId: string): Boolean;
begin
  Result := IsSafeFileComponent(AAppId);
end;

function TPortappixJournal.LoadState: TJSONObject;
var
  Content: string;
  Value: TJSONValue;
begin
  if not TFile.Exists(FStateFile) then
    Exit(TJSONObject.Create);

  try
    Content := TFile.ReadAllText(FStateFile, TEncoding.UTF8);
  except
    on E: Exception do
    begin
      Log('Unable to read run_state.json: ' + E.Message);
      Exit(TJSONObject.Create);
    end;
  end;

  if Content.Trim = '' then
    Exit(TJSONObject.Create);

  Value := nil;
  try
    try
      Value := TJSONObject.ParseJSONValue(Content);
    except
      on E: Exception do
      begin
        Log('Unable to parse run_state.json: ' + E.Message);
        Exit(TJSONObject.Create);
      end;
    end;

    if (Value <> nil) and (Value is TJSONObject) then
      Result := TJSONObject(Value)
    else
    begin
      Value.Free;
      Result := TJSONObject.Create;
    end;
  except
    Value.Free;
    raise;
  end;
end;

procedure TPortappixJournal.SaveState(const AState: TJSONObject);
var
  TemporaryFile: string;
begin
  StateDirectory(FStateFile);
  TemporaryFile := FStateFile + '.tmp';

  TFile.WriteAllText(TemporaryFile, AState.ToJSON, TEncoding.UTF8);
  if TFile.Exists(FStateFile) then
    TFile.Delete(FStateFile);
  TFile.Move(TemporaryFile, FStateFile);
end;

function TPortappixJournal.GetAppsObject(const AState: TJSONObject;
  const ACreate: Boolean): TJSONObject;
var
  Value: TJSONValue;
begin
  Result := nil;
  Value := AState.GetValue('apps');
  if (Value <> nil) and (Value is TJSONObject) then
    Result := TJSONObject(Value)
  else if ACreate then
  begin
    if Value <> nil then
      AState.RemovePair('apps').Free;
    Result := TJSONObject.Create;
    AState.AddPair('apps', Result);
  end;
end;

function TPortappixJournal.ReadStringArray(const AEntry: TJSONObject;
  const AName: string): TArray<string>;
var
  Value: TJSONValue;
  ValuesArray: TJSONArray;
  Item: TJSONValue;
  Values: TList<string>;
begin
  SetLength(Result, 0);
  if AEntry = nil then
    Exit;

  Value := AEntry.GetValue(AName);
  if (Value = nil) or not (Value is TJSONArray) then
    Exit;

  ValuesArray := TJSONArray(Value);
  Values := TList<string>.Create;
  try
    for var Index := 0 to ValuesArray.Count - 1 do
    begin
      Item := ValuesArray.Items[Index];
      if (Item is TJSONString) and (Item.Value.Trim <> '') then
        Values.Add(Item.Value.Trim);
    end;
    Result := Values.ToArray;
  finally
    Values.Free;
  end;
end;

function TPortappixJournal.ReadHijackedKeys(const AEntry: TJSONObject): TArray<string>;
begin
  Result := ReadStringArray(AEntry, 'hijackedKeys');
end;

function TPortappixJournal.ReadJunctions(const AEntry: TJSONObject): TArray<string>;
begin
  Result := ReadStringArray(AEntry, 'junctions');
end;

function TPortappixJournal.ResolveDataDir(const AAppId: string;
  const AEntry: TJSONObject): string;
var
  Value: TJSONValue;
begin
  Result := '';
  if (AEntry <> nil) then
  begin
    Value := AEntry.GetValue('dataDir');
    if (Value is TJSONString) and (TJSONString(Value).Value.Trim <> '') then
    begin
      var DataDir := TJSONString(Value).Value;
      if IsRelativePath(DataDir) then
        Result := TPath.GetFullPath(TPath.Combine(FRootPath, DataDir))
      else
        Result := TPath.GetFullPath(DataDir);
      Exit;
    end;
  end;

  if IsSafeAppId(AAppId) then
    Result := TPath.GetFullPath(TPath.Combine(TPath.Combine(FRootPath, 'Data'), AAppId));
end;

procedure TPortappixJournal.AddActiveApp(const AAppId: string;
  const AHijackedKeys: TArray<string>; const AJunctions: TArray<string>);
var
  State: TJSONObject;
  Apps: TJSONObject;
  Entry: TJSONObject;
  KeysArray: TJSONArray;
  JunctionsArray: TJSONArray;
begin
  if AAppId.Trim = '' then
    raise EPortappixStateError.Create('Active app id must not be empty.');
  if not IsSafeAppId(AAppId) then
    raise EPortappixStateError.CreateFmt('Active app id "%s" is not a valid folder name.',
      [AAppId]);

  State := LoadState;
  try
    Apps := GetAppsObject(State, True);

    if TryGetObjectValue(Apps, AAppId, Entry) then
      Apps.RemovePair(AAppId).Free;

    Entry := TJSONObject.Create;
    Entry.AddPair('active', TJSONBool.Create(True));
    Entry.AddPair('dataDir', TPath.Combine(TPath.Combine(FRootPath, 'Data'), AAppId));
    Entry.AddPair('startedAt', TDateTime.NowUtc.ToISO8601);

    KeysArray := TJSONArray.Create;
    for var Key in AHijackedKeys do
      if Key.Trim <> '' then
        KeysArray.Add(Key.Trim);
    Entry.AddPair('hijackedKeys', KeysArray);

    JunctionsArray := TJSONArray.Create;
    for var Junction in AJunctions do
      if Junction.Trim <> '' then
        JunctionsArray.Add(Junction.Trim);
    Entry.AddPair('junctions', JunctionsArray);

    Apps.AddPair(AAppId, Entry);
    SaveState(State);
  finally
    State.Free;
  end;
end;

procedure TPortappixJournal.RemoveActiveApp(const AAppId: string);
var
  State: TJSONObject;
  Apps: TJSONObject;
  Entry: TJSONObject;
begin
  State := LoadState;
  try
    Apps := GetAppsObject(State, False);
    if (Apps = nil) or not TryGetObjectValue(Apps, AAppId, Entry) then
      Exit;

    Apps.RemovePair(AAppId).Free;
    if Apps.Count = 0 then
      State.RemovePair('apps').Free;

    SaveState(State);
  finally
    State.Free;
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

function RegExePath: string;
var
  WindowsDirectory: array[0..MAX_PATH] of Char;
begin
  if GetWindowsDirectory(WindowsDirectory, MAX_PATH) > 0 then
    Result := TPath.Combine(PChar(@WindowsDirectory[0]), 'System32\reg.exe')
  else
    Result := 'reg.exe';
end;

procedure TPortappixJournal.RestoreScannedBackups(const ADataDir: string);
var
  ExitCode: Cardinal;
begin
  if (ADataDir = '') or not TDirectory.Exists(ADataDir) then
    Exit;

  for var BackupFile in TDirectory.GetFiles(ADataDir, 'host_backup_*.reg') do
  begin
    Log('Restoring scanned host registry backup: ' + BackupFile);
    try
      if not RunHiddenProcess(Format('"%s" import "%s"', [RegExePath, BackupFile]), ExitCode) then
      begin
        Log('Unable to start reg.exe to import backup: ' + BackupFile);
        Continue;
      end;

      if ExitCode = 0 then
      begin
        try
          TFile.Delete(BackupFile);
        except
          on E: Exception do
            Log('Unable to delete restored backup "' + BackupFile + '": ' + E.Message);
        end;
      end
      else
        Log(Format('reg.exe import failed for "%s" (exit code %u).', [BackupFile, ExitCode]));
    except
      on E: Exception do
        Log('Unable to restore scanned host registry backup "' + BackupFile + '": ' + E.Message);
    end;
  end;
end;

procedure TPortappixJournal.RecoverPendingCleanups;
var
  State: TJSONObject;
  Apps: TJSONObject;
  Pair: TJSONPair;
  Entry: TJSONObject;
  Keys: TArray<string>;
  Junctions: TArray<string>;
  DataDir: string;
  BackupFiles: TArray<string>;
begin
  State := LoadState;
  try
    Apps := GetAppsObject(State, False);
    if Apps = nil then
      Exit;

    Log('Recovering pending Portappix cleanups from ' + FStateFile);
    var AppIds: TArray<string>;
    SetLength(AppIds, Apps.Count);
    for var Index := 0 to Apps.Count - 1 do
    begin
      Pair := Apps.Pairs[Index];
      if (Pair <> nil) and (Pair.JsonString <> nil) then
        AppIds[Index] := Pair.JsonString.Value
      else
        AppIds[Index] := '';
    end;

    for var AppId in AppIds do
    begin
      if AppId = '' then
        Continue;
      if not TryGetObjectValue(Apps, AppId, Entry) then
        Continue;

      Keys := ReadHijackedKeys(Entry);
      Junctions := ReadJunctions(Entry);
      DataDir := ResolveDataDir(AppId, Entry);

      try
        if (Length(Keys) > 0) or (Length(Junctions) > 0) then
          TPortableAppRunner.PerformCleanup(AppId, Keys, Junctions, DataDir, FOnLog)
        else
        begin
          Log('No hijacked state recorded for "' + AppId +
            '"; restoring any host backup files found in its data directory.');
          RestoreScannedBackups(DataDir);
        end;

        if (DataDir <> '') and TDirectory.Exists(DataDir) then
          BackupFiles := TDirectory.GetFiles(DataDir, 'host_backup_*.reg')
        else
          SetLength(BackupFiles, 0);

        if Length(BackupFiles) > 0 then
        begin
          Log('Host backup files remain for "' + AppId +
            '"; keeping its journal entry for a later recovery attempt.');
          Continue;
        end;
      except
        on E: Exception do
        begin
          Log('Pending cleanup failed for "' + AppId + '": ' + E.Message);
          Continue;
        end;
      end;

      Apps.RemovePair(AppId).Free;
    end;

    if Apps.Count = 0 then
      State.RemovePair('apps').Free;
    SaveState(State);
  finally
    State.Free;
  end;
end;

end.
