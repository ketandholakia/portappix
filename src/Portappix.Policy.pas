unit Portappix.Policy;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes,
  System.StrUtils,
  System.IOUtils,
  System.Generics.Collections,
  Portappix.Common,
  Portappix.Manifest,
  Portappix.Registry;

type
  TPolicyResult = class
  private
    FAllowed: Boolean;
    FMessages: TStringList;
  public
    constructor Create;
    destructor Destroy; override;
    procedure AddError(const AMessage: string);
    procedure AddNote(const AMessage: string);
    function Summary: string;
    property Allowed: Boolean read FAllowed;
    property Messages: TStringList read FMessages;
  end;

  TPortappixPolicy = class
  public
    class function ValidateRegistryPath(const AKey: string;
      const AResult: TPolicyResult): Boolean; static;
    class function ValidateJunctionHost(const AHostPath: string;
      const AResult: TPolicyResult): Boolean; static;
    class function ValidateJunctionTarget(const ATargetPath: string;
      const AResult: TPolicyResult): Boolean; static;
    class function ValidateEnvironment(const AEnvironment: TDictionary<string, string>;
      const AResult: TPolicyResult): Boolean; static;
    class function ValidateManifest(const AManifest: TPortappixManifest): TPolicyResult; static;
    class function DescribeManifest(const AManifest: TPortappixManifest): string; static;
  end;

implementation

const
  AllowedEnvironmentVariables: array[0..14] of string = (
    'APPDATA', 'LOCALAPPDATA', 'USERPROFILE', 'TEMP', 'TMP', 'HOME', 'PATH',
    'PATHEXT', 'COMSPEC', 'PROGRAMDATA', 'PUBLIC', 'XDG_CONFIG_HOME',
    'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'USERNAME');

  PathLikeEnvironmentVariables: array[0..1] of string = ('PATH', 'PATHEXT');

  DeniedRegistryVendors: array[0..5] of string = (
    'Microsoft', 'Classes', 'Policies', 'Windows', 'Windows NT', 'CurrentVersion');

  DeniedPathComponents: array[0..7] of string = (
    'Documents', 'Desktop', 'Downloads', 'OneDrive', 'Windows', 'System32',
    'Program Files', 'Program Files (x86)');

constructor TPolicyResult.Create;
begin
  inherited Create;
  FAllowed := True;
  FMessages := TStringList.Create;
end;

destructor TPolicyResult.Destroy;
begin
  FMessages.Free;
  inherited;
end;

procedure TPolicyResult.AddError(const AMessage: string);
begin
  FAllowed := False;
  FMessages.Add(AMessage);
end;

procedure TPolicyResult.AddNote(const AMessage: string);
begin
  FMessages.Add(AMessage);
end;

function TPolicyResult.Summary: string;
begin
  Result := FMessages.Text.Trim;
end;

function IsDeniedVendor(const AName: string): Boolean;
begin
  for var Vendor in DeniedRegistryVendors do
    if SameText(AName, Vendor) then
      Exit(True);
  Result := False;
end;

class function TPortappixPolicy.ValidateRegistryPath(const AKey: string;
  const AResult: TPolicyResult): Boolean;
var
  RootKey: HKEY;
  SubKey: string;
  Parts: TArray<string>;
  Index: Integer;
begin
  Result := False;
  try
    RootKey := 0;
    SubKey := '';
    if not ParseRegistryPath(AKey, RootKey, SubKey) then
    begin
      AResult.AddError(Format('Registry path is invalid: "%s".', [AKey]));
      Exit;
    end;

    if RootKey <> HKEY_CURRENT_USER then
    begin
      AResult.AddError(Format(
        'Registry path "%s" must be under HKCU\Software; other hives are not allowed.', [AKey]));
      Exit;
    end;

    Parts := SubKey.Split(['\']);
    if (Length(Parts) < 3) or not SameText(Parts[0], 'Software') then
    begin
      AResult.AddError(Format(
        'Registry path "%s" must be HKCU\Software\<vendor>\<app> (at least two levels below HKCU\Software).',
        [AKey]));
      Exit;
    end;

    if not IsSafeFileComponent(Parts[1]) or not IsSafeFileComponent(Parts[2]) then
    begin
      AResult.AddError(Format('Registry path "%s" contains an invalid vendor or app name.', [AKey]));
      Exit;
    end;

    if IsDeniedVendor(Parts[1]) then
    begin
      AResult.AddError(Format(
        'Registry path "%s" is reserved (%s is on the deny-list).', [AKey, Parts[1]]));
      Exit;
    end;

    for Index := 1 to High(Parts) do
      if Parts[Index] = '' then
      begin
        AResult.AddError(Format('Registry path "%s" contains an empty component.', [AKey]));
        Exit;
      end;

    Result := True;
  except
    on E: Exception do
      AResult.AddError(Format('Registry path "%s" is invalid: %s', [AKey, E.Message]));
  end;
end;

function FirstRelativeComponent(const APath, ARootPath: string): string;
var
  FullPath: string;
  FullRoot: string;
  Parts: TArray<string>;
begin
  Result := '';
  FullPath := TrimTrailingPathDelimiter(TPath.GetFullPath(APath));
  FullRoot := TrimTrailingPathDelimiter(TPath.GetFullPath(ARootPath));
  if not TextStartsWith(FullPath, FullRoot + '\') then
    Exit;
  Result := FullPath.Substring(Length(FullRoot) + 1);
  Parts := Result.Split(['\']);
  if Length(Parts) > 0 then
    Result := Parts[0]
  else
    Result := '';
end;

class function TPortappixPolicy.ValidateJunctionHost(const AHostPath: string;
  const AResult: TPolicyResult): Boolean;
var
  Expanded: string;
  AppData: string;
  LocalAppData: string;
  ProgramData: string;
  Profile: string;
  UnderProfile: Boolean;
  Relative: string;
begin
  Result := False;
  if AHostPath.Trim = '' then
  begin
    AResult.AddError('Junction host path must not be empty.');
    Exit;
  end;

  if AHostPath.IndexOf('{') >= 0 then
  begin
    AResult.AddError(Format('Junction host path "%s" must not contain manifest tokens.',
      [AHostPath]));
    Exit;
  end;

  if ContainsStr(AHostPath, '..\') or ContainsStr(AHostPath, '../') then
  begin
    AResult.AddError(Format('Junction host path "%s" must not contain path traversal.',
      [AHostPath]));
    Exit;
  end;

  Expanded := ExpandPercentVariables(AHostPath).Trim;
  if (Expanded = '') or not TPath.IsPathRooted(Expanded) then
  begin
    AResult.AddError(Format('Junction host path "%s" must be an absolute path.', [AHostPath]));
    Exit;
  end;

  Expanded := TrimTrailingPathDelimiter(TPath.GetFullPath(Expanded));

  AppData := TrimTrailingPathDelimiter(GetEnvironmentVariable('APPDATA'));
  LocalAppData := TrimTrailingPathDelimiter(GetEnvironmentVariable('LOCALAPPDATA'));
  ProgramData := TrimTrailingPathDelimiter(GetEnvironmentVariable('PROGRAMDATA'));
  Profile := TrimTrailingPathDelimiter(GetEnvironmentVariable('USERPROFILE'));

  for var Component in Expanded.Split(['\']) do
    for var DeniedComponent in DeniedPathComponents do
      if SameText(Component, DeniedComponent) then
      begin
        AResult.AddError(Format(
          'Junction host path "%s" is in a protected system or user folder.', [AHostPath]));
        Exit;
      end;

  if ((AppData <> '') and IsPathUnder(Expanded, AppData + '\Microsoft')) or
     ((LocalAppData <> '') and IsPathUnder(Expanded, LocalAppData + '\Microsoft')) or
     ((ProgramData <> '') and IsPathUnder(Expanded, ProgramData + '\Microsoft')) then
  begin
    AResult.AddError(Format('Junction host path "%s" is in a protected system folder.',
      [AHostPath]));
    Exit;
  end;

  if (AppData <> '') and IsPathUnder(Expanded, AppData) and
     not SameText(Expanded, AppData) then
    Exit(True);
  if (LocalAppData <> '') and IsPathUnder(Expanded, LocalAppData) and
     not SameText(Expanded, LocalAppData) then
    Exit(True);
  if (ProgramData <> '') and IsPathUnder(Expanded, ProgramData) and
     not SameText(Expanded, ProgramData) then
    Exit(True);

  UnderProfile := (Profile <> '') and IsPathUnder(Expanded, Profile) and
    not SameText(Expanded, Profile);
  if UnderProfile then
  begin
    Relative := FirstRelativeComponent(Expanded, Profile);
    if Relative.StartsWith('.') then
      Exit(True);
  end;

  AResult.AddError(Format(
    'Junction host path "%s" must be inside %%APPDATA%%, %%LOCALAPPDATA%%, %%PROGRAMDATA%%, or %%USERPROFILE%%\.<name>.',
    [AHostPath]));
end;

class function TPortappixPolicy.ValidateJunctionTarget(const ATargetPath: string;
  const AResult: TPolicyResult): Boolean;
var
  Normalized: string;
begin
  Result := False;
  if ATargetPath.Trim = '' then
  begin
    AResult.AddError('Junction target path must not be empty.');
    Exit;
  end;

  Normalized := StringReplace(ATargetPath.Trim, '/', '\', [rfReplaceAll]);
  for var Part in Normalized.Split(['\']) do
    if Part = '..' then
    begin
      AResult.AddError(Format('Junction target "%s" must not contain path traversal.', [ATargetPath]));
      Exit;
    end;

  if (Normalized = '..') or ContainsStr(Normalized, '..\') or ContainsStr(Normalized, '\..') then
  begin
    AResult.AddError(Format('Junction target "%s" must not contain path traversal.', [ATargetPath]));
    Exit;
  end;

  if ContainsText(ATargetPath, '{root}') or ContainsText(ATargetPath, '{app}') then
  begin
    AResult.AddError(Format(
      'Junction target "%s" must not reference {root} or {app}; it must live strictly inside {data}.',
      [ATargetPath]));
    Exit;
  end;

  if ContainsText(ATargetPath, '{data}') or IsRelativePath(ATargetPath) then
    Exit(True);

  AResult.AddError(Format('Junction target "%s" must live inside the portable {data} directory.',
    [ATargetPath]));
end;

class function TPortappixPolicy.ValidateEnvironment(
  const AEnvironment: TDictionary<string, string>; const AResult: TPolicyResult): Boolean;
var
  Allowed: Boolean;
  IsPathLike: Boolean;
  Val: string;
begin
  Result := True;
  for var Pair in AEnvironment do
  begin
    Allowed := False;
    for var Name in AllowedEnvironmentVariables do
      if SameText(Pair.Key, Name) then
      begin
        Allowed := True;
        Break;
      end;

    if not Allowed then
    begin
      AResult.AddError(Format(
        'Environment variable "%s" is not in the allow-list; overriding it is not permitted.',
        [Pair.Key]));
      Result := False;
      Continue;
    end;

    Val := Pair.Value;
    if (Val.IndexOf(#0) >= 0) or (Val.IndexOf(#10) >= 0) or (Val.IndexOf(#13) >= 0) then
    begin
      AResult.AddError(Format(
        'Environment variable "%s" contains invalid control characters.', [Pair.Key]));
      Result := False;
      Continue;
    end;

    if (Val = '..') or ContainsStr(Val, '..\') or ContainsStr(Val, '../') or
       ContainsStr(Val, '\..') or ContainsStr(Val, '/..') then
    begin
      AResult.AddError(Format(
        'Environment variable "%s" contains path traversal.', [Pair.Key]));
      Result := False;
      Continue;
    end;

    IsPathLike := False;
    for var Name in PathLikeEnvironmentVariables do
      if SameText(Pair.Key, Name) then
      begin
        IsPathLike := True;
        Break;
      end;

    if IsPathLike and not ContainsText(Pair.Value, '{app}') and
       not ContainsText(Pair.Value, '{data}') then
    begin
      AResult.AddError(Format(
        'Path-like environment variable "%s" must reference {app} or {data} so host PATH is not inherited wholesale.',
        [Pair.Key]));
      Result := False;
    end;
  end;
end;

class function TPortappixPolicy.ValidateManifest(
  const AManifest: TPortappixManifest): TPolicyResult;
begin
  Result := TPolicyResult.Create;
  if AManifest = nil then
  begin
    Result.AddError('Manifest is missing.');
    Exit;
  end;

  for var Key in AManifest.RegistryKeys do
    ValidateRegistryPath(Key, Result);

  for var Pair in AManifest.Junctions do
  begin
    ValidateJunctionHost(Pair.Key, Result);
    ValidateJunctionTarget(Pair.Value, Result);
  end;

  ValidateEnvironment(AManifest.Environment, Result);
end;

class function TPortappixPolicy.DescribeManifest(
  const AManifest: TPortappixManifest): string;
var
  Builder: TStringBuilder;
begin
  Builder := TStringBuilder.Create;
  try
    Builder.AppendLine('Registry keys:');
    if Length(AManifest.RegistryKeys) = 0 then
      Builder.AppendLine('  (none)')
    else
      for var Key in AManifest.RegistryKeys do
        Builder.AppendLine('  ' + Key);

    Builder.AppendLine('Junctions:');
    if AManifest.Junctions.Count = 0 then
      Builder.AppendLine('  (none)')
    else
      for var Pair in AManifest.Junctions do
        Builder.AppendLine('  ' + Pair.Key + ' -> ' + Pair.Value);

    Builder.AppendLine('Environment overrides:');
    if AManifest.Environment.Count = 0 then
      Builder.AppendLine('  (none)')
    else
      for var Pair in AManifest.Environment do
        Builder.AppendLine('  ' + Pair.Key + '=' + Pair.Value);

    Result := Builder.ToString.Trim;
  finally
    Builder.Free;
  end;
end;

end.
