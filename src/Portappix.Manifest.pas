unit Portappix.Manifest;

interface

uses
  System.SysUtils,
  System.IOUtils,
  System.JSON,
  System.StrUtils,
  System.Generics.Collections,
  System.Generics.Defaults;

type
  EPortappixManifestError = class(Exception);

  TPortappixManifest = class
  private
    FId: string;
    FName: string;
    FExe: string;
    FEnvironment: TDictionary<string, string>;
    FJunctions: TDictionary<string, string>;
    FRegistryKeys: TArray<string>;
    FSourceFile: string;
    FSourceDir: string;
    function ReadString(const AObject: TJSONObject; const AName: string;
      const ARequired: Boolean): string;
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
    property Id: string read FId;
    property Name: string read FName;
    property Exe: string read FExe;
    property Environment: TDictionary<string, string> read FEnvironment;
    property Junctions: TDictionary<string, string> read FJunctions;
    property RegistryKeys: TArray<string> read FRegistryKeys;
    property SourceFile: string read FSourceFile;
    property SourceDir: string read FSourceDir;
  end;

implementation

function IsSafeFolderName(const AValue: string): Boolean;
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

constructor TPortappixManifest.Create;
begin
  inherited Create;
  FEnvironment := TDictionary<string, string>.Create(TStringComparer.OrdinalIgnoreCase);
  FJunctions := TDictionary<string, string>.Create(TIStringComparer.Ordinal);
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
    if not IsSafeFolderName(FId) then
      raise EPortappixManifestError.CreateFmt('Manifest id "%s" is not a valid folder name.',
        [FId]);

    FName := ReadString(RootObject, 'name', False);
    if FName = '' then
      FName := FId;

    FExe := ReadString(RootObject, 'exe', True).Trim;

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
