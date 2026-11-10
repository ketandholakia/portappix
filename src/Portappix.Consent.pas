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
    procedure ReadStoredHashes(const AAppId: string;
      out AStoredManifestHash, AStoredExeHash: string);
  public
    constructor Create(const ARootPath: string);
    function ExePathFor(const AManifest: TPortappixManifest): string;
    function ExeHash(const AManifest: TPortappixManifest): string;
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

function TPortappixConsent.ExePathFor(const AManifest: TPortappixManifest): string;
var
  AppDir: string;
  ExeValue: string;
begin
  if (AManifest = nil) or (AManifest.Exe.Trim = '') then
    Exit('');
  AppDir := TPath.Combine(TPath.Combine(FRootPath, 'Apps'), AManifest.Id);
  ExeValue := StringReplace(AManifest.Exe.Trim, '/', '\', [rfReplaceAll]);
  ExeValue := StringReplace(ExeValue, '{app}', AppDir, [rfIgnoreCase, rfReplaceAll]);
  ExeValue := StringReplace(ExeValue, '{root}', FRootPath, [rfIgnoreCase, rfReplaceAll]);
  if not TPath.IsPathRooted(ExeValue) then
    ExeValue := TPath.Combine(AppDir, ExeValue);
  Result := TPath.GetFullPath(ExeValue);
end;

function TPortappixConsent.ExeHash(const AManifest: TPortappixManifest): string;
var
  Path: string;
begin
  Path := ExePathFor(AManifest);
  if (Path = '') or not TFile.Exists(Path) then
    Exit('');
  Result := Sha256File(Path);
end;

function TPortappixConsent.ManifestHash(const AManifest: TPortappixManifest): string;
begin
  if (AManifest = nil) or not TFile.Exists(AManifest.SourceFile) then
    Exit('');
  Result := Sha256File(AManifest.SourceFile);
end;

procedure TPortappixConsent.ReadStoredHashes(const AAppId: string;
  out AStoredManifestHash, AStoredExeHash: string);
var
  FileName: string;
  Value: TJSONValue;
  ObjectValue: TJSONObject;
  Item: TJSONValue;
begin
  AStoredManifestHash := '';
  AStoredExeHash := '';
  FileName := ConsentFileFor(AAppId);
  if not TFile.Exists(FileName) then
    Exit;

  try
    Value := TJSONObject.ParseJSONValue(TFile.ReadAllText(FileName, TEncoding.UTF8));
    try
      if (Value <> nil) and (Value is TJSONObject) then
      begin
        ObjectValue := TJSONObject(Value);
        Item := ObjectValue.GetValue('manifestHash');
        if (Item <> nil) and (Item is TJSONString) then
          AStoredManifestHash := TJSONString(Item).Value.Trim;
        Item := ObjectValue.GetValue('exeHash');
        if (Item <> nil) and (Item is TJSONString) then
          AStoredExeHash := TJSONString(Item).Value.Trim;
      end;
    finally
      Value.Free;
    end;
  except
  end;
end;

function TPortappixConsent.NeedsConsent(const AManifest: TPortappixManifest): Boolean;
var
  MHash, EHash: string;
  StoredMHash, StoredEHash: string;
begin
  if AManifest = nil then
    Exit(True);
  if (Length(AManifest.RegistryKeys) = 0) and (AManifest.Junctions.Count = 0) and
     (AManifest.Environment.Count = 0) then
    Exit(False);

  MHash := ManifestHash(AManifest);
  EHash := ExeHash(AManifest);
  ReadStoredHashes(AManifest.Id, StoredMHash, StoredEHash);

  if (MHash = '') or not SameText(StoredMHash, MHash) then
    Exit(True);

  if EHash <> '' then
  begin
    if (StoredEHash = '') or not SameText(StoredEHash, EHash) then
      Exit(True);
  end;

  Result := False;
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
  EHash: string;
begin
  if AManifest = nil then
    Exit;
  FileName := ConsentFileFor(AManifest.Id);
  ForceDirectories(TPath.GetDirectoryName(FileName));

  Json := TJSONObject.Create;
  try
    Json.AddPair('appId', AManifest.Id);
    Json.AddPair('manifestHash', ManifestHash(AManifest));
    EHash := ExeHash(AManifest);
    if EHash <> '' then
      Json.AddPair('exeHash', EHash);
    Json.AddPair('approvedAt', DateToISO8601(Now));
    WriteTextFileAtomic(FileName, Json.Format(2));
  finally
    Json.Free;
  end;
end;

end.
