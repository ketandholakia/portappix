unit Portappix.State;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes,
  System.SyncObjs,
  System.DateUtils,
  System.IOUtils,
  System.JSON,
  System.Generics.Collections,
  Portappix.Common,
  Portappix.Process,
  Portappix.Registry,
  Portappix.Runner;

type
  EPortappixStateError = class(Exception);

  TPortappixJournal = class(TInterfacedObject, IPortappixJournal)
  private
    FRootPath: string;
    FStateFile: string;
    FOnLog: TProc<string>;
    FSync: TCriticalSection;
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
    function GetOnLog: TProc<string>;
    procedure SetOnLog(const AValue: TProc<string>);
  public
    constructor Create(const ARootPath: string = '');
    destructor Destroy; override;
    procedure AddActiveApp(const AAppId: string; const AHijackedKeys: TArray<string>;
      const AJunctions: TArray<string>);
    procedure RemoveActiveApp(const AAppId: string);
    procedure RecoverPendingCleanups;
    property RootPath: string read FRootPath;
    property StateFile: string read FStateFile;
    property OnLog: TProc<string> read GetOnLog write SetOnLog;
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

function StateDirectory(const AStateFile: string): string;
begin
  Result := TPath.GetDirectoryName(AStateFile);
  if Result <> '' then
    ForceDirectories(Result);
end;

constructor TPortappixJournal.Create(const ARootPath: string);
begin
  inherited Create;
  FSync := TCriticalSection.Create;
  FRootPath := ResolveRootPath(ARootPath);
  FStateFile := TPath.Combine(FRootPath, 'run_state.json');
end;

destructor TPortappixJournal.Destroy;
begin
  FSync.Free;
  inherited;
end;

function TPortappixJournal.GetOnLog: TProc<string>;
begin
  Result := FOnLog;
end;

procedure TPortappixJournal.SetOnLog(const AValue: TProc<string>);
begin
  FOnLog := AValue;
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
  BadFile: string;
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
        Value := nil;
      end;
    end;

    if (Value <> nil) and (Value is TJSONObject) then
      Result := TJSONObject(Value)
    else
    begin
      Value.Free;
      BadFile := FStateFile + '.bad';
      if TFile.Exists(BadFile) then
        TFile.Delete(BadFile);
      TFile.Copy(FStateFile, BadFile, True);
      Log('run_state.json was corrupt; a copy was kept at ' + BadFile);
      Result := TJSONObject.Create;
    end;
  except
    Value.Free;
    raise;
  end;
end;

procedure TPortappixJournal.SaveState(const AState: TJSONObject);
begin
  StateDirectory(FStateFile);
  if not WriteTextFileAtomic(FStateFile, AState.ToJSON) then
    raise EPortappixStateError.Create('Unable to write run_state.json atomically.');
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
  if AEntry <> nil then
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

  FSync.Enter;
  try
    State := LoadState;
    try
      Apps := GetAppsObject(State, True);

      if TryGetObjectValue(Apps, AAppId, Entry) then
        Apps.RemovePair(AAppId).Free;

      Entry := TJSONObject.Create;
      Entry.AddPair('active', TJSONBool.Create(True));
      Entry.AddPair('dataDir', TPath.Combine(TPath.Combine(FRootPath, 'Data'), AAppId));
      Entry.AddPair('startedAt', DateToISO8601(Now));

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
  finally
    FSync.Leave;
  end;
end;

procedure TPortappixJournal.RemoveActiveApp(const AAppId: string);
var
  State: TJSONObject;
  Apps: TJSONObject;
  Entry: TJSONObject;
begin
  FSync.Enter;
  try
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
  finally
    FSync.Leave;
  end;
end;

procedure TPortappixJournal.RestoreScannedBackups(const ADataDir: string);
var
  Ops: IPortappixRegistryOps;
begin
  if (ADataDir = '') or not TDirectory.Exists(ADataDir) then
    Exit;

  Ops := TPortappixRegistryOps.Create;
  for var BackupFile in TDirectory.GetFiles(ADataDir, 'host_backup_*.reg') do
  begin
    Log('Restoring scanned host registry backup: ' + BackupFile);
    try
      if Ops.ImportFile(BackupFile) then
      begin
        try
          TFile.Delete(BackupFile);
        except
          on E: Exception do
            Log('Unable to delete restored backup "' + BackupFile + '": ' + E.Message);
        end;
      end
      else
        Log('reg.exe import failed for host backup: ' + BackupFile);
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
  AppIds: TArray<string>;
begin
  FSync.Enter;
  try
    State := LoadState;
    try
      Apps := GetAppsObject(State, False);
      if Apps = nil then
        Exit;

      Log('Recovering pending Portappix cleanups from ' + FStateFile);
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

        if IsAppRunning(FRootPath, AppId) then
        begin
          Log('Skipping recovery for "' + AppId + '" because it is currently running.');
          Continue;
        end;

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
  finally
    FSync.Leave;
  end;
end;

end.
