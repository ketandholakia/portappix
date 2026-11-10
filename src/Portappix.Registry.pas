unit Portappix.Registry;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  System.Win.Registry,
  Portappix.Common,
  Portappix.Process;

const
  RegistryFileHeader = 'Windows Registry Editor Version 5.00';

type
  EPortappixRegistryError = class(Exception);

  IPortappixRegistryOps = interface
    ['{4C8B8F4E-2F42-4A6D-9B0E-3A5D2C7F1E90}']
    function KeyExists(const AKey: string): Boolean;
    function ExportKey(const AKey, AFileName: string): Boolean;
    function ImportFile(const AFileName: string): Boolean;
    function DeleteKey(const AKey: string): Boolean;
  end;

  TProcessRunnerFunc = reference to function(const ACommandLine: string; out AExitCode: Cardinal;
    const ACurrentDirectory: string; const ATimeoutMs: DWORD): Boolean;

  TPortappixRegistryOps = class(TInterfacedObject, IPortappixRegistryOps)
  private
    FProcessRunner: TProcessRunnerFunc;
    function Quote(const AValue: string): string;
    function ExecuteProcess(const ACommandLine: string; out AExitCode: Cardinal): Boolean;
  public
    constructor Create(const AProcessRunner: TProcessRunnerFunc = nil);
    function KeyExists(const AKey: string): Boolean;
    function ExportKey(const AKey, AFileName: string): Boolean;
    function ImportFile(const AFileName: string): Boolean;
    function DeleteKey(const AKey: string): Boolean;
  end;

function RegExePath: string;
function ParseRegistryPath(const APath: string; out ARootKey: HKEY;
  out ASubKey: string): Boolean;
function RegistryRootText(const ARootKey: HKEY): string;
function NormalizeRegistryPath(const APath: string): string;
function MergeRegistryFiles(const AFiles: TArray<string>;
  const ADestination: string): Boolean;
function IsSafeRegistryVendor(const AVendor: string): Boolean;
function ValidateRegistryKeyDepthAndVendor(const AKey: string; out AError: string): Boolean;

implementation

function RegExePath: string;
var
  WindowsDirectory: array[0..MAX_PATH] of Char;
begin
  if GetWindowsDirectory(WindowsDirectory, MAX_PATH) > 0 then
    Result := TPath.Combine(PChar(@WindowsDirectory[0]), 'System32\reg.exe')
  else
    Result := 'reg.exe';
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

  while (Length(ASubKey) > 0) and (ASubKey[1] = '\') do
    Delete(ASubKey, 1, 1);
  while (Length(ASubKey) > 0) and (ASubKey[Length(ASubKey)] = '\') do
    Delete(ASubKey, Length(ASubKey), 1);
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
    raise EPortappixRegistryError.CreateFmt('Registry path contains a null character: "%s".',
      [APath]);

  Result := APath.Trim;
  while (Length(Result) > 0) and (Result[Length(Result)] = '\') do
    Delete(Result, Length(Result), 1);

  if not ParseRegistryPath(Result, RootKey, SubKey) then
    raise EPortappixRegistryError.CreateFmt('Invalid registry path: "%s".', [APath]);

  while Pos('\\', SubKey) > 0 do
    SubKey := StringReplace(SubKey, '\\', '\', [rfReplaceAll]);

  Result := RegistryRootText(RootKey) + '\' + SubKey;
end;

function TPortappixRegistryOps.Quote(const AValue: string): string;
begin
  Result := '"' + AValue + '"';
end;

function TPortappixRegistryOps.KeyExists(const AKey: string): Boolean;
var
  RootKey: HKEY;
  SubKey: string;
  Registry: TRegistry;
begin
  if not ParseRegistryPath(AKey, RootKey, SubKey) then
    raise EPortappixRegistryError.CreateFmt('Invalid registry path: "%s".', [AKey]);

  Registry := TRegistry.Create(KEY_READ);
  try
    Registry.RootKey := RootKey;
    Result := Registry.KeyExists(SubKey);
  finally
    Registry.Free;
  end;
end;

constructor TPortappixRegistryOps.Create(const AProcessRunner: TProcessRunnerFunc);
begin
  inherited Create;
  FProcessRunner := AProcessRunner;
end;

function TPortappixRegistryOps.ExecuteProcess(const ACommandLine: string;
  out AExitCode: Cardinal): Boolean;
begin
  if Assigned(FProcessRunner) then
    Result := FProcessRunner(ACommandLine, AExitCode, '', 30000)
  else
    Result := RunHiddenProcess(ACommandLine, AExitCode, '', 30000);
end;

function TPortappixRegistryOps.ExportKey(const AKey, AFileName: string): Boolean;
var
  ExitCode: Cardinal;
begin
  if not ExecuteProcess(Format('%s export %s %s /y',
    [Quote(RegExePath), Quote(AKey), Quote(AFileName)]), ExitCode) then
    Exit(False);
  Result := ExitCode = 0;
end;

function TPortappixRegistryOps.ImportFile(const AFileName: string): Boolean;
var
  ExitCode: Cardinal;
begin
  if not ExecuteProcess(Format('%s import %s',
    [Quote(RegExePath), Quote(AFileName)]), ExitCode) then
    Exit(False);
  Result := ExitCode = 0;
end;

function TPortappixRegistryOps.DeleteKey(const AKey: string): Boolean;
var
  ExitCode: Cardinal;
begin
  if not ExecuteProcess(Format('%s delete %s /f',
    [Quote(RegExePath), Quote(AKey)]), ExitCode) then
    Exit(False);
  Result := ExitCode = 0;
end;

function MergeRegistryFiles(const AFiles: TArray<string>;
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
         (TextStartsWith(Lines[0].Trim, 'Windows Registry Editor') or
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

const
  DeniedRegistryVendors: array[0..5] of string = (
    'Microsoft', 'Classes', 'Policies', 'Windows', 'Windows NT', 'CurrentVersion');

function IsSafeRegistryVendor(const AVendor: string): Boolean;
begin
  for var Vendor in DeniedRegistryVendors do
    if SameText(AVendor, Vendor) then
      Exit(False);
  Result := True;
end;

function ValidateRegistryKeyDepthAndVendor(const AKey: string; out AError: string): Boolean;
var
  RootKey: HKEY;
  SubKey: string;
  Parts: TArray<string>;
  Index: Integer;
begin
  Result := False;
  AError := '';
  if AKey.Trim = '' then
  begin
    AError := 'Registry path must not be empty.';
    Exit;
  end;
  if (AKey.IndexOf('..') >= 0) or (AKey.IndexOf(#0) >= 0) then
  begin
    AError := Format('Registry path "%s" contains traversal or null characters.', [AKey]);
    Exit;
  end;
  if not ParseRegistryPath(AKey, RootKey, SubKey) then
  begin
    AError := Format('Registry path is invalid: "%s".', [AKey]);
    Exit;
  end;
  if RootKey <> HKEY_CURRENT_USER then
  begin
    AError := Format('Registry path "%s" must be under HKCU\Software; other hives are not allowed.', [AKey]);
    Exit;
  end;

  Parts := SubKey.Split(['\']);
  if (Length(Parts) < 3) or not SameText(Parts[0], 'Software') then
  begin
    AError := Format('Registry path "%s" must be HKCU\Software\<vendor>\<app> (at least two levels below HKCU\Software).', [AKey]);
    Exit;
  end;

  if not IsSafeFileComponent(Parts[1]) or not IsSafeFileComponent(Parts[2]) then
  begin
    AError := Format('Registry path "%s" contains an invalid vendor or app name.', [AKey]);
    Exit;
  end;

  if not IsSafeRegistryVendor(Parts[1]) then
  begin
    AError := Format('Registry path "%s" is reserved (%s is on the deny-list).', [AKey, Parts[1]]);
    Exit;
  end;

  for Index := 1 to High(Parts) do
    if (Parts[Index] = '') or not IsSafeFileComponent(Parts[Index]) then
    begin
      AError := Format('Registry path "%s" contains an invalid or empty component.', [AKey]);
      Exit;
    end;

  Result := True;
end;

end.
