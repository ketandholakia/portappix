unit Portappix.Registry;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  System.Win.Registry,
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

  TPortappixRegistryOps = class(TInterfacedObject, IPortappixRegistryOps)
  private
    function Quote(const AValue: string): string;
  public
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

  ASubKey := ASubKey.Trim(['\']);
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

function TPortappixRegistryOps.ExportKey(const AKey, AFileName: string): Boolean;
var
  ExitCode: Cardinal;
begin
  if not RunHiddenProcess(Format('%s export %s %s /y',
    [Quote(RegExePath), Quote(AKey), Quote(AFileName)]), ExitCode) then
    Exit(False);
  Result := ExitCode = 0;
end;

function TPortappixRegistryOps.ImportFile(const AFileName: string): Boolean;
var
  ExitCode: Cardinal;
begin
  if not RunHiddenProcess(Format('%s import %s',
    [Quote(RegExePath), Quote(AFileName)]), ExitCode) then
    Exit(False);
  Result := ExitCode = 0;
end;

function TPortappixRegistryOps.DeleteKey(const AKey: string): Boolean;
var
  ExitCode: Cardinal;
begin
  if not RunHiddenProcess(Format('%s delete %s /f',
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
         (Lines[0].Trim.StartsWith('Windows Registry Editor', True) or
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

end.
