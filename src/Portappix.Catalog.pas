unit Portappix.Catalog;

interface

uses
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  System.JSON,
  System.Generics.Collections,
  System.Net.HttpClient;

type
  EPortappixCatalogError = class(Exception);

  TCatalogApp = class
  private
    FId: string;
    FName: string;
    FVersion: string;
    FCategory: string;
    FUrl: string;
    FSha256: string;
    FSize: Int64;
  public
    property Id: string read FId write FId;
    property Name: string read FName write FName;
    property Version: string read FVersion write FVersion;
    property Category: string read FCategory write FCategory;
    property Url: string read FUrl write FUrl;
    property Sha256: string read FSha256 write FSha256;
    property Size: Int64 read FSize write FSize;
  end;

  TPortappixCatalog = class
  private
    FApps: TObjectList<TCatalogApp>;
    FSource: string;
    function ReadRequiredString(const AObject: TJSONObject; const AName: string): string;
    function ReadOptionalString(const AObject: TJSONObject; const AName: string): string;
    function ReadSize(const AObject: TJSONObject): Int64;
    procedure ClearApps;
    procedure Parse(const AJson: string);
    function NormalizeSha256(const AValue: string): string;
  public
    constructor Create;
    destructor Destroy; override;
    procedure LoadFromJson(const AJson: string);
    procedure LoadFromFile(const AFileName: string);
    procedure LoadFromUrl(const AUrl: string; const ACacheFileName: string = '');
    function FindById(const AId: string): TCatalogApp;
    property Apps: TObjectList<TCatalogApp> read FApps;
    property Source: string read FSource;
  end;

implementation

function IsSafeIdentifier(const AValue: string): Boolean;
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

constructor TPortappixCatalog.Create;
begin
  inherited Create;
  FApps := TObjectList<TCatalogApp>.Create(True);
end;

destructor TPortappixCatalog.Destroy;
begin
  FApps.Free;
  inherited;
end;

procedure TPortappixCatalog.ClearApps;
begin
  FApps.Clear;
end;

function TPortappixCatalog.NormalizeSha256(const AValue: string): string;
begin
  Result := AValue.Trim.ToLower;
  if Result = '' then
    raise EPortappixCatalogError.Create('Catalog app sha256 must not be empty.');
  if Result.Length <> 64 then
    raise EPortappixCatalogError.CreateFmt('Catalog app sha256 must be 64 hex characters: "%s".',
      [AValue]);
  for var Character in Result do
    if not CharInSet(Character, ['0'..'9', 'a'..'f']) then
      raise EPortappixCatalogError.CreateFmt('Catalog app sha256 must be hexadecimal: "%s".',
        [AValue]);
end;

function TPortappixCatalog.ReadRequiredString(const AObject: TJSONObject;
  const AName: string): string;
var
  Value: TJSONValue;
begin
  Value := AObject.GetValue(AName);
  if Value = nil then
    raise EPortappixCatalogError.CreateFmt('Missing required catalog property "%s".', [AName]);
  if not (Value is TJSONString) then
    raise EPortappixCatalogError.CreateFmt('Catalog property "%s" must be a string.', [AName]);

  Result := TJSONString(Value).Value;
  if Result.IndexOf(#0) >= 0 then
    raise EPortappixCatalogError.CreateFmt('Catalog property "%s" contains a null character.', [AName]);
  if Result.Trim = '' then
    raise EPortappixCatalogError.CreateFmt('Catalog property "%s" must not be empty.', [AName]);
end;

function TPortappixCatalog.ReadOptionalString(const AObject: TJSONObject;
  const AName: string): string;
var
  Value: TJSONValue;
begin
  Result := '';
  Value := AObject.GetValue(AName);
  if Value = nil then
    Exit;
  if not (Value is TJSONString) then
    raise EPortappixCatalogError.CreateFmt('Catalog property "%s" must be a string.', [AName]);
  Result := TJSONString(Value).Value;
  if Result.IndexOf(#0) >= 0 then
    raise EPortappixCatalogError.CreateFmt('Catalog property "%s" contains a null character.', [AName]);
end;

function TPortappixCatalog.ReadSize(const AObject: TJSONObject): Int64;
var
  Value: TJSONValue;
  Number: TJSONNumber;
begin
  Result := 0;
  Value := AObject.GetValue('size');
  if Value = nil then
    Exit;
  if not (Value is TJSONNumber) then
    raise EPortappixCatalogError.Create('Catalog property "size" must be a number.');
  Number := TJSONNumber(Value);
  Result := Number.AsInt64;
  if Result < 0 then
    raise EPortappixCatalogError.Create('Catalog property "size" must not be negative.');
end;

procedure TPortappixCatalog.Parse(const AJson: string);
var
  JsonValue: TJSONValue;
  RootObject: TJSONObject;
  AppsValue: TJSONValue;
  AppsArray: TJSONArray;
  Item: TJSONValue;
  AppObject: TJSONObject;
  App: TCatalogApp;
begin
  ClearApps;

  JsonValue := TJSONObject.ParseJSONValue(AJson);
  if JsonValue = nil then
    raise EPortappixCatalogError.Create('Invalid catalog JSON.');
  try
    if not (JsonValue is TJSONObject) then
      raise EPortappixCatalogError.Create('Catalog JSON must contain an object.');

    RootObject := TJSONObject(JsonValue);
    AppsValue := RootObject.GetValue('apps');
    if AppsValue = nil then
      raise EPortappixCatalogError.Create('Catalog JSON must contain an "apps" array.');
    if not (AppsValue is TJSONArray) then
      raise EPortappixCatalogError.Create('Catalog property "apps" must be an array.');

    AppsArray := TJSONArray(AppsValue);
    for var Index := 0 to AppsArray.Count - 1 do
    begin
      Item := AppsArray.Items[Index];
      if not (Item is TJSONObject) then
        raise EPortappixCatalogError.Create('Each entry in "apps" must be an object.');

      AppObject := TJSONObject(Item);
      App := TCatalogApp.Create;
      try
        App.Id := ReadRequiredString(AppObject, 'id').Trim;
        if not IsSafeIdentifier(App.Id) then
          raise EPortappixCatalogError.CreateFmt('Catalog app id "%s" is not a valid identifier.',
            [App.Id]);
        App.Name := ReadRequiredString(AppObject, 'name');
        App.Version := ReadRequiredString(AppObject, 'version');
        App.Category := ReadOptionalString(AppObject, 'category');
        App.Url := ReadRequiredString(AppObject, 'url');
        App.Sha256 := NormalizeSha256(ReadRequiredString(AppObject, 'sha256'));
        App.Size := ReadSize(AppObject);

        if FindById(App.Id) <> nil then
          raise EPortappixCatalogError.CreateFmt('Duplicate catalog app id "%s".', [App.Id]);

        FApps.Add(App);
        App := nil;
      finally
        App.Free;
      end;
    end;
  finally
    JsonValue.Free;
  end;
end;

procedure TPortappixCatalog.LoadFromJson(const AJson: string);
begin
  FSource := '';
  Parse(AJson);
end;

procedure TPortappixCatalog.LoadFromFile(const AFileName: string);
var
  FullPath: string;
begin
  FullPath := TPath.GetFullPath(AFileName);
  if not TFile.Exists(FullPath) then
    raise EPortappixCatalogError.CreateFmt('Catalog file not found: "%s".', [FullPath]);

  FSource := FullPath;
  Parse(TFile.ReadAllText(FullPath, TEncoding.UTF8));
end;

procedure TPortappixCatalog.LoadFromUrl(const AUrl: string; const ACacheFileName: string);
var
  Client: THTTPClient;
  Response: IHTTPResponse;
  Content: string;
  CachePath: string;
begin
  if AUrl.Trim = '' then
    raise EPortappixCatalogError.Create('Catalog URL must not be empty.');

  Client := THTTPClient.Create;
  try
    Client.UserAgent := 'Portappix';
    Response := Client.Get(AUrl);
    if (Response = nil) or (Response.StatusCode < 200) or (Response.StatusCode >= 300) then
      raise EPortappixCatalogError.CreateFmt('Unable to download catalog "%s" (HTTP %d).',
        [AUrl, Response.StatusCode]);

    Content := Response.ContentAsString(TEncoding.UTF8);
  finally
    Client.Free;
  end;

  FSource := AUrl;
  Parse(Content);

  CachePath := ACacheFileName.Trim;
  if CachePath <> '' then
  begin
    CachePath := TPath.GetFullPath(CachePath);
    ForceDirectories(TPath.GetDirectoryName(CachePath));
    TFile.WriteAllText(CachePath, Content, TEncoding.UTF8);
  end;
end;

function TPortappixCatalog.FindById(const AId: string): TCatalogApp;
begin
  for var App in FApps do
    if SameText(App.Id, AId) then
      Exit(App);
  Result := nil;
end;

end.
