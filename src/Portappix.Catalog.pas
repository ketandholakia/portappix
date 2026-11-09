unit Portappix.Catalog;

interface

uses
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  System.JSON,
  System.Generics.Collections,
  System.Net.HttpClient,
  System.Net.URLClient,
  Portappix.Common,
  Portappix.Signature;

type
  EPortappixCatalogError = class(Exception);

  TCatalogApp = class
  private
    FId: string;
    FName: string;
    FPublisher: string;
    FVersion: string;
    FCategory: string;
    FUrl: string;
    FSha256: string;
    FSize: Int64;
  public
    property Id: string read FId write FId;
    property Name: string read FName write FName;
    property Publisher: string read FPublisher write FPublisher;
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
    FSignatureVerified: Boolean;
    function ReadRequiredString(const AObject: TJSONObject; const AName: string): string;
    function ReadOptionalString(const AObject: TJSONObject; const AName: string): string;
    function ReadSize(const AObject: TJSONObject): Int64;
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
    property SignatureVerified: Boolean read FSignatureVerified;
  end;

var
  AllowUnsignedCatalogs: Boolean = False;

function IsHttpsUrl(const AUrl: string): Boolean;
function DownloadToBytes(const AUrl: string): TBytes;

implementation

function IsHttpsUrl(const AUrl: string): Boolean;
begin
  Result := TextStartsWith(AUrl.Trim, 'https://');
end;

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

function DownloadToBytes(const AUrl: string): TBytes;
var
  Client: THTTPClient;
  Response: IHTTPResponse;
  Source: TStream;
  Buffer: TMemoryStream;
begin
  Client := THTTPClient.Create;
  try
    Client.UserAgent := 'Portappix';
    Response := Client.Get(AUrl);
    if Response = nil then
      raise EPortappixCatalogError.CreateFmt('Unable to download "%s".', [AUrl]);
    if (Response.StatusCode < 200) or (Response.StatusCode >= 300) then
      raise EPortappixCatalogError.CreateFmt('Unable to download "%s" (HTTP %d).',
        [AUrl, Response.StatusCode]);

    Source := Response.ContentStream;
    if Source = nil then
      Exit(nil);

    Buffer := TMemoryStream.Create;
    try
      Source.Position := 0;
      Buffer.CopyFrom(Source, 0);
      SetLength(Result, Buffer.Size);
      Buffer.Position := 0;
      if Length(Result) > 0 then
        Buffer.ReadBuffer(Result[0], Length(Result));
    finally
      Buffer.Free;
    end;
  finally
    Client.Free;
  end;
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
    raise EPortappixCatalogError.CreateFmt('Catalog property "%s" contains a null character.',
      [AName]);
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
    raise EPortappixCatalogError.CreateFmt('Catalog property "%s" contains a null character.',
      [AName]);
end;

function TPortappixCatalog.ReadSize(const AObject: TJSONObject): Int64;
var
  Value: TJSONValue;
begin
  Result := 0;
  Value := AObject.GetValue('size');
  if Value = nil then
    Exit;
  if not (Value is TJSONNumber) then
    raise EPortappixCatalogError.Create('Catalog property "size" must be a number.');
  Result := TJSONNumber(Value).AsInt64;
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
  NewApps: TObjectList<TCatalogApp>;

  function NewListContainsId(const AId: string): Boolean;
  begin
    for var Existing in NewApps do
      if SameText(Existing.Id, AId) then
        Exit(True);
    Result := False;
  end;

begin
  JsonValue := TJSONObject.ParseJSONValue(AJson);
  if JsonValue = nil then
    raise EPortappixCatalogError.Create('Invalid catalog JSON.');

  try
    NewApps := TObjectList<TCatalogApp>.Create(True);
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
            raise EPortappixCatalogError.CreateFmt(
              'Catalog app id "%s" is not a valid identifier.', [App.Id]);
          App.Name := ReadRequiredString(AppObject, 'name');
          App.Publisher := ReadOptionalString(AppObject, 'publisher');
          App.Version := ReadRequiredString(AppObject, 'version');
          App.Category := ReadOptionalString(AppObject, 'category');
          App.Url := ReadRequiredString(AppObject, 'url');
          if not IsHttpsUrl(App.Url) then
            raise EPortappixCatalogError.CreateFmt(
              'Catalog app "%s" must use an https:// package URL.', [App.Id]);
          App.Sha256 := NormalizeSha256(ReadRequiredString(AppObject, 'sha256'));
          App.Size := ReadSize(AppObject);

          if NewListContainsId(App.Id) then
            raise EPortappixCatalogError.CreateFmt('Duplicate catalog app id "%s".', [App.Id]);

          NewApps.Add(App);
          App := nil;
        finally
          App.Free;
        end;
      end;

      FApps.Free;
      FApps := NewApps;
      NewApps := nil;
    finally
      NewApps.Free;
    end;
  finally
    JsonValue.Free;
  end;
end;

procedure TPortappixCatalog.LoadFromJson(const AJson: string);
begin
  FSource := '';
  FSignatureVerified := False;
  Parse(AJson);
end;

procedure TPortappixCatalog.LoadFromFile(const AFileName: string);
var
  FullPath: string;
  SignaturePath: string;
  Content: TBytes;
begin
  FullPath := TPath.GetFullPath(AFileName);
  if not TFile.Exists(FullPath) then
    raise EPortappixCatalogError.CreateFmt('Catalog file not found: "%s".', [FullPath]);

  Content := TFile.ReadAllBytes(FullPath);
  SignaturePath := FullPath + '.sig';
  FSignatureVerified := False;

  if TFile.Exists(SignaturePath) then
  begin
    if not VerifySignatureForCatalog(Content, TFile.ReadAllBytes(SignaturePath)) then
      raise EPortappixCatalogError.CreateFmt('Catalog signature verification failed: "%s".',
        [FullPath]);
    FSignatureVerified := True;
  end
  else if not AllowUnsignedCatalogs then
    raise EPortappixCatalogError.CreateFmt(
      'Catalog "%s" is not signed. Set AllowUnsignedCatalogs for development builds.',
      [FullPath]);

  FSource := FullPath;
  Parse(TEncoding.UTF8.GetString(Content));
end;

procedure TPortappixCatalog.LoadFromUrl(const AUrl: string; const ACacheFileName: string);
var
  Content: TBytes;
  SignatureBytes: TBytes;
  SignatureUrl: string;
  CachePath: string;
  SignatureCachePath: string;
begin
  if AUrl.Trim = '' then
    raise EPortappixCatalogError.Create('Catalog URL must not be empty.');
  if not IsHttpsUrl(AUrl) then
    raise EPortappixCatalogError.CreateFmt('Catalog URL must use https://: "%s".', [AUrl]);

  Content := DownloadToBytes(AUrl);
  if Length(Content) = 0 then
    raise EPortappixCatalogError.CreateFmt('Catalog "%s" is empty.', [AUrl]);

  SignatureUrl := AUrl + '.sig';
  SignatureBytes := nil;
  try
    SignatureBytes := DownloadToBytes(SignatureUrl);
  except
    on E: EPortappixCatalogError do
      SignatureBytes := nil;
  end;

  FSignatureVerified := False;
  if (Length(SignatureBytes) > 0) and VerifySignatureForCatalog(Content, SignatureBytes) then
    FSignatureVerified := True
  else if not AllowUnsignedCatalogs then
    raise EPortappixCatalogError.CreateFmt(
      'Catalog "%s" is not correctly signed. Set AllowUnsignedCatalogs for development builds.',
      [AUrl]);

  Parse(TEncoding.UTF8.GetString(Content));

  CachePath := ACacheFileName.Trim;
  if CachePath <> '' then
  begin
    CachePath := TPath.GetFullPath(CachePath);
    ForceDirectories(TPath.GetDirectoryName(CachePath));
    TFile.WriteAllBytes(CachePath, Content);

    SignatureCachePath := CachePath + '.sig';
    if Length(SignatureBytes) > 0 then
      TFile.WriteAllBytes(SignatureCachePath, SignatureBytes)
    else if TFile.Exists(SignatureCachePath) then
      TFile.Delete(SignatureCachePath);
  end;

  FSource := AUrl;
end;

function TPortappixCatalog.FindById(const AId: string): TCatalogApp;
begin
  for var App in FApps do
    if SameText(App.Id, AId) then
      Exit(App);
  Result := nil;
end;

end.
