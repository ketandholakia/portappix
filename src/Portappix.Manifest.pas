unit Portappix.Manifest;

interface

uses
  System.SysUtils,
  System.DateUtils,
  System.IOUtils,
  System.JSON,
  System.StrUtils,
  System.Generics.Collections,
  System.Generics.Defaults,
  Portappix.Common;

type
  EPortappixManifestError = class(Exception);

  TPortappixManifest = class
  private
    FId: string;
    FName: string;
    FExe: string;
    FArgs: string;
    FVersion: string;
    FDataVersion: Integer;
    FCategory: string;
    FSchema: Integer;
    FEnvironment: TDictionary<string, string>;
    FJunctions: TDictionary<string, string>;
    FRegistryKeys: TArray<string>;
    FSourceFile: string;
    FSourceDir: string;
    function ReadString(const AObject: TJSONObject; const AName: string;
      const ARequired: Boolean): string;
    function ReadInteger(const AObject: TJSONObject; const AName: string;
      const ADefault: Integer): Integer;
    procedure ReadStringDictionary(const AObject: TJSONObject; const AName: string;
      const ADestination: TDictionary<string, string>);
    procedure ReadEnvironment(const AObject: TJSONObject);
    procedure ReadJunctions(const AObject: TJSONObject);
    procedure ReadRegistryKeys(const AObject: TJSONObject);
    procedure Parse(const AJson: string);
  public
    constructor Create;
    destructor Destroy; override;
    class function LoadFromFile(const AFileName: string): TPortappixManifest; static;
    class function ReadDataVersion(const ADataDir: string): Integer; static;
    class procedure WriteDataVersion(const ADataDir, AAppId: string;
      ADataVersion: Integer); static;
    property Id: string read FId;
    property Name: string read FName;
    property Exe: string read FExe;
    property Args: string read FArgs;
    property Version: string read FVersion;
    property DataVersion: Integer read FDataVersion;
    property Category: string read FCategory;
    property Schema: Integer read FSchema;
    property Environment: TDictionary<string, string> read FEnvironment;
    property Junctions: TDictionary<string, string> read FJunctions;
    property RegistryKeys: TArray<string> read FRegistryKeys;
    property SourceFile: string read FSourceFile;
    property SourceDir: string read FSourceDir;
  end;

function ManifestIdMatchesFolder(const AManifestPath: string): Boolean;

implementation

constructor TPortappixManifest.Create;
begin
  inherited Create;
  FEnvironment := TDictionary<string, string>.Create(TIStringComparer.Ordinal);
  FJunctions := TDictionary<string, string>.Create(TIStringComparer.Ordinal);
  FCategory := 'Apps';
  FSchema := PortappixManifestSchema;
end;

destructor TPortappixManifest.Destroy;
begin
  FreeAndNil(FEnvironment);
  FreeAndNil(FJunctions);
  inherited;
end;

class function TPortappixManifest.LoadFromFile(const AFileName: string): TPortappixManifest;
begin
  if not TFile.Exists(AFileName) then
    raise EPortappixManifestError.CreateFmt('Manifest file not found: "%s".', [AFileName]);

  Result := TPortappixManifest.Create;
  try
    Result.FSourceFile := TPath.GetFullPath(AFileName);
    Result.FSourceDir := TPath.GetDirectoryName(Result.FSourceFile);
    Result.Parse(TFile.ReadAllText(Result.FSourceFile, TEncoding.UTF8));
  except
    Result.Free;
    raise;
  end;
end;

class function TPortappixManifest.ReadDataVersion(const ADataDir: string): Integer;
var
  FileName: string;
  JsonValue: TJSONValue;
  VersionValue: TJSONValue;
begin
  Result := 0;
  FileName := TPath.Combine(ADataDir, 'data_version.json');
  if not TFile.Exists(FileName) then
    Exit;

  try
    JsonValue := TJSONObject.ParseJSONValue(TFile.ReadAllText(FileName, TEncoding.UTF8));
    try
      if JsonValue = nil then
        Exit;
      VersionValue := JsonValue.FindValue('dataVersion');
      if VersionValue is TJSONNumber then
        Result := TJSONNumber(VersionValue).AsInt;
    finally
      JsonValue.Free;
    end;
  except
    Result := 0;
  end;
end;

class procedure TPortappixManifest.WriteDataVersion(const ADataDir, AAppId: string;
  ADataVersion: Integer);
var
  Json: TJSONObject;
begin
  if ADataVersion <= 0 then
    Exit;

  ForceDirectories(ADataDir);
  Json := TJSONObject.Create;
  try
    Json.AddPair('appId', AAppId);
    Json.AddPair('dataVersion', TJSONNumber.Create(ADataVersion));
    Json.AddPair('writtenAt', DateToISO8601(Now));
    if not WriteTextFileAtomic(TPath.Combine(ADataDir, 'data_version.json'),
      Json.Format(2)) then
      raise EPortappixManifestError.Create('Unable to write data_version.json.');
  finally
    Json.Free;
  end;
end;

function ManifestIdMatchesFolder(const AManifestPath: string): Boolean;
var
  Manifest: TPortappixManifest;
  FolderName: string;
begin
  Manifest := TPortappixManifest.LoadFromFile(AManifestPath);
  try
    FolderName := ExtractFileName(ExcludeTrailingPathDelimiter(Manifest.SourceDir));
    Result := SameText(Manifest.Id, FolderName);
  finally
    Manifest.Free;
  end;
end;

procedure TPortappixManifest.Parse(const AJson: string);
var
  JsonValue: TJSONValue;
  RootObject: TJSONObject;
begin
  JsonValue := nil;
  try
    try
      JsonValue := TJSONObject.ParseJSONValue(AJson);
    except
      on E: Exception do
        raise EPortappixManifestError.CreateFmt('Invalid JSON in "%s": %s',
          [FSourceFile, E.Message]);
    end;

    if JsonValue = nil then
      raise EPortappixManifestError.CreateFmt('Invalid JSON in "%s".', [FSourceFile]);
    if not (JsonValue is TJSONObject) then
      raise EPortappixManifestError.CreateFmt('Manifest "%s" must contain a JSON object.',
        [FSourceFile]);

    RootObject := TJSONObject(JsonValue);

    FId := ReadString(RootObject, 'id', False).Trim;
    if FId = '' then
      FId := ExtractFileName(ExcludeTrailingPathDelimiter(FSourceDir));
    if not IsSafeFileComponent(FId) then
      raise EPortappixManifestError.CreateFmt('Manifest id "%s" is not a valid folder name.',
        [FId]);

    FName := ReadString(RootObject, 'name', False);
    if FName = '' then
      FName := FId;

    FExe := ReadString(RootObject, 'exe', True).Trim;
    FArgs := ReadString(RootObject, 'args', False);
    FVersion := ReadString(RootObject, 'version', False).Trim;
    FDataVersion := ReadInteger(RootObject, 'dataVersion', 0);
    if FDataVersion < 0 then
      raise EPortappixManifestError.CreateFmt(
        'Manifest "%s" has an invalid dataVersion value.', [FSourceFile]);

    FCategory := ReadString(RootObject, 'category', False).Trim;
    if FCategory = '' then
      FCategory := 'Apps';

    FSchema := ReadInteger(RootObject, 'schema', PortappixManifestSchema);
    if FSchema > PortappixManifestSchema then
      raise EPortappixManifestError.CreateFmt(
        'Manifest "%s" uses schema %d but this launcher supports schema %d.',
        [FSourceFile, FSchema, PortappixManifestSchema]);
    if FSchema < 1 then
      raise EPortappixManifestError.CreateFmt('Manifest "%s" has an invalid schema value.',
        [FSourceFile]);

    ReadEnvironment(RootObject);
    ReadJunctions(RootObject);
    ReadRegistryKeys(RootObject);
  finally
    JsonValue.Free;
  end;
end;

function TPortappixManifest.ReadString(const AObject: TJSONObject;
  const AName: string; const ARequired: Boolean): string;
var
  Value: TJSONValue;
begin
  Result := '';
  Value := AObject.GetValue(AName);
  if Value = nil then
  begin
    if ARequired then
      raise EPortappixManifestError.CreateFmt('Missing required property "%s".', [AName]);
    Exit;
  end;

  if not (Value is TJSONString) then
    raise EPortappixManifestError.CreateFmt('Property "%s" must be a string.', [AName]);

  Result := Value.Value;
  if Result.IndexOf(#0) >= 0 then
    raise EPortappixManifestError.CreateFmt('Property "%s" contains a null character.', [AName]);
  if ARequired and (Result.Trim = '') then
    raise EPortappixManifestError.CreateFmt('Property "%s" must not be empty.', [AName]);
end;

function TPortappixManifest.ReadInteger(const AObject: TJSONObject;
  const AName: string; const ADefault: Integer): Integer;
var
  Value: TJSONValue;
begin
  Result := ADefault;
  Value := AObject.GetValue(AName);
  if Value = nil then
    Exit;
  if not (Value is TJSONNumber) then
    raise EPortappixManifestError.CreateFmt('Property "%s" must be a number.', [AName]);
  Result := TJSONNumber(Value).AsInt;
end;

procedure TPortappixManifest.ReadStringDictionary(const AObject: TJSONObject;
  const AName: string; const ADestination: TDictionary<string, string>);
var
  Value: TJSONValue;
  ValueObject: TJSONObject;
  Pair: TJSONPair;
  Item: TJSONValue;
  Name: string;
begin
  ADestination.Clear;
  Value := AObject.GetValue(AName);
  if Value = nil then
    Exit;

  if not (Value is TJSONObject) then
    raise EPortappixManifestError.CreateFmt('Property "%s" must be a JSON object.', [AName]);

  ValueObject := TJSONObject(Value);
  for var Index := 0 to ValueObject.Count - 1 do
  begin
    Pair := ValueObject.Pairs[Index];
    if Pair.JsonString = nil then
      Continue;

    Name := Pair.JsonString.Value.Trim;
    if (Name = '') or (Name.IndexOf(#0) >= 0) then
      raise EPortappixManifestError.CreateFmt('Invalid key in "%s": "%s".', [AName, Name]);

    Item := Pair.JsonValue;
    if not (Item is TJSONString) then
      raise EPortappixManifestError.CreateFmt('Value for "%s" in "%s" must be a string.',
        [Name, AName]);
    if Item.Value.IndexOf(#0) >= 0 then
      raise EPortappixManifestError.CreateFmt('Value for "%s" in "%s" contains a null character.',
        [Name, AName]);

    ADestination.AddOrSetValue(Name, Item.Value);
  end;
end;

procedure TPortappixManifest.ReadEnvironment(const AObject: TJSONObject);
begin
  ReadStringDictionary(AObject, 'env', FEnvironment);
  for var Pair in FEnvironment.ToArray do
    if ContainsStr(Pair.Key, '=') then
      raise EPortappixManifestError.CreateFmt('Invalid environment variable name: "%s".',
        [Pair.Key]);
end;

procedure TPortappixManifest.ReadJunctions(const AObject: TJSONObject);
begin
  ReadStringDictionary(AObject, 'junctions', FJunctions);
  for var Pair in FJunctions do
    if Pair.Value.Trim = '' then
      raise EPortappixManifestError.CreateFmt(
        'Junction target for "%s" must not be empty.', [Pair.Key]);
end;

procedure TPortappixManifest.ReadRegistryKeys(const AObject: TJSONObject);
var
  RegistryValue: TJSONValue;
  RegistryArray: TJSONArray;
  Item: TJSONValue;
  Keys: TList<string>;
begin
  SetLength(FRegistryKeys, 0);
  RegistryValue := AObject.GetValue('registry');
  if RegistryValue = nil then
    Exit;

  if not (RegistryValue is TJSONArray) then
    raise EPortappixManifestError.Create('Property "registry" must be an array of registry paths.');

  RegistryArray := TJSONArray(RegistryValue);
  Keys := TList<string>.Create;
  try
    for var Index := 0 to RegistryArray.Count - 1 do
    begin
      Item := RegistryArray.Items[Index];
      if not (Item is TJSONString) then
        raise EPortappixManifestError.Create('Every entry in "registry" must be a string.');

      if Item.Value.Trim <> '' then
        Keys.Add(Item.Value.Trim);
    end;

    FRegistryKeys := Keys.ToArray;
  finally
    Keys.Free;
  end;
end;

end.
