unit Portappix.Consent;

interface

uses
  System.SysUtils,
  System.Classes,
  System.DateUtils,
  System.IOUtils,
  System.JSON,
  Portappix.Common,
  Portappix.Manifest,
  Portappix.Policy;

type
  TPortappixConsent = class
  private
    FRootPath: string;
    function ConsentFileFor(const AAppId: string): string;
    function ReadStoredHash(const AAppId: string): string;
  public
    constructor Create(const ARootPath: string);
    function ManifestHash(const AManifest: TPortappixManifest): string;
    function NeedsConsent(const AManifest: TPortappixManifest): Boolean;
    function ApprovalDescription(const AManifest: TPortappixManifest): string;
    procedure Approve(const AManifest: TPortappixManifest);
    property RootPath: string read FRootPath;
  end;

implementation

constructor TPortappixConsent.Create(const ARootPath: string);
begin
  inherited Create;
  FRootPath := ResolveRootPath(ARootPath);
end;

function TPortappixConsent.ConsentFileFor(const AAppId: string): string;
begin
  Result := TPath.Combine(TPath.Combine(TPath.Combine(FRootPath, 'Data'), AAppId),
    'policy_consent.json');
end;

function TPortappixConsent.ManifestHash(const AManifest: TPortappixManifest): string;
begin
  if (AManifest = nil) or not TFile.Exists(AManifest.SourceFile) then
    Exit('');
  Result := Sha256File(AManifest.SourceFile);
end;

function TPortappixConsent.ReadStoredHash(const AAppId: string): string;
var
  FileName: string;
  Value: TJSONValue;
  ObjectValue: TJSONObject;
  HashValue: TJSONValue;
begin
  Result := '';
  FileName := ConsentFileFor(AAppId);
  if not TFile.Exists(FileName) then
    Exit;

  Value := nil;
  try
    try
      Value := TJSONObject.ParseJSONValue(TFile.ReadAllText(FileName, TEncoding.UTF8));
    except
      Exit('');
    end;
    if (Value <> nil) and (Value is TJSONObject) then
    begin
      ObjectValue := TJSONObject(Value);
      HashValue := ObjectValue.GetValue('manifestHash');
      if (HashValue <> nil) and (HashValue is TJSONString) then
        Result := TJSONString(HashValue).Value.Trim;
    end;
  finally
    Value.Free;
  end;
end;

function TPortappixConsent.NeedsConsent(const AManifest: TPortappixManifest): Boolean;
var
  Hash: string;
begin
  if AManifest = nil then
    Exit(True);
  if (Length(AManifest.RegistryKeys) = 0) and (AManifest.Junctions.Count = 0) and
     (AManifest.Environment.Count = 0) then
    Exit(False);

  Hash := ManifestHash(AManifest);
  Result := (Hash = '') or not SameText(ReadStoredHash(AManifest.Id), Hash);
end;

function TPortappixConsent.ApprovalDescription(const AManifest: TPortappixManifest): string;
var
  Policy: TPolicyResult;
begin
  if AManifest = nil then
    Exit('(unknown manifest)');

  Result := TPortappixPolicy.DescribeManifest(AManifest);
  Policy := TPortappixPolicy.ValidateManifest(AManifest);
  try
    if not Policy.Allowed then
      Result := Result + sLineBreak + sLineBreak + 'Policy warnings:' + sLineBreak +
        Policy.Summary;
  finally
    Policy.Free;
  end;
end;

procedure TPortappixConsent.Approve(const AManifest: TPortappixManifest);
var
  FileName: string;
  Json: TJSONObject;
begin
  if AManifest = nil then
    Exit;
  FileName := ConsentFileFor(AManifest.Id);
  ForceDirectories(TPath.GetDirectoryName(FileName));

  Json := TJSONObject.Create;
  try
    Json.AddPair('appId', AManifest.Id);
    Json.AddPair('manifestHash', ManifestHash(AManifest));
    Json.AddPair('approvedAt', DateToISO8601(Now));
    WriteTextFileAtomic(FileName, Json.Format(2));
  finally
    Json.Free;
  end;
end;

end.
