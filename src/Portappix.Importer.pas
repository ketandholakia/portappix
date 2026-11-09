unit Portappix.Importer;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  System.JSON;

type
  EPortappixImporterError = class(Exception);

  TPortappixImporter = class
  private
    FRootPath: string;
    function ResolvePath(const APath: string): string;
    function ResolveRootPath(const APath: string): string;
    function QueryVersionString(const AExePath, AValueName: string): string;
    function GetExeFileVersion(const AExePath: string): string;
    function MakeId(const ABaseName: string): string;
    function MakeRelativeExePath(const ASourceFolder, ATargetExe: string): string;
    procedure CopyDirectory(const ASourceDir, ADestinationDir: string);
  public
    constructor Create(const ARootPath: string = '');
    class function GenerateManifest(const SourceFolder, TargetExe: string): Boolean; overload; static;
    function GenerateManifest(const SourceFolder, TargetExe: string;
      const APublisher: string = ''): Boolean; overload;
    function GenerateManifest(const SourceFolder, TargetExe: string;
      const APublisher: string; out AManifestPath, AAppId: string): Boolean; overload;
    function ImportToApps(const SourceFolder, TargetExe: string;
      const APublisher: string = ''; const AAppsRoot: string = ''): string; overload;
    class function ImportToApps(const SourceFolder, TargetExe: string;
      const APublisher, AAppsRoot: string): string; overload; static;
    property RootPath: string read FRootPath;
  end;

implementation

function LauncherDirectory: string;
begin
  Result := TPath.GetDirectoryName(ParamStr(0));
  if Result = '' then
    Result := GetCurrentDir;
end;

function IsRelativePath(const APath: string): Boolean;
begin
  if APath = '' then
    Exit(True);
  if (Length(APath) >= 2) and (APath[2] = ':') then
    Exit(False);
  if (Length(APath) >= 2) and (APath[1] = '\') and (APath[2] = '\') then
    Exit(False);
  if APath[1] = '\' then
    Exit(False);
  Result := True;
end;

constructor TPortappixImporter.Create(const ARootPath: string);
begin
  inherited Create;
  FRootPath := ResolveRootPath(ARootPath);
end;

function TPortappixImporter.ResolveRootPath(const APath: string): string;
begin
  if APath = '' then
    Exit(TPath.GetFullPath(LauncherDirectory));
  if IsRelativePath(APath) then
    Result := TPath.GetFullPath(TPath.Combine(LauncherDirectory, APath))
  else
    Result := TPath.GetFullPath(APath);
end;

function TPortappixImporter.ResolvePath(const APath: string): string;
begin
  if IsRelativePath(APath) then
    Result := TPath.GetFullPath(TPath.Combine(FRootPath, APath))
  else
    Result := TPath.GetFullPath(APath);
end;

function TPortappixImporter.QueryVersionString(const AExePath, AValueName: string): string;
var
  Handle: DWORD;
  Size: DWORD;
  Buffer: TBytes;
  TranslationPtr: Pointer;
  TranslationLength: UINT;
  Language: Word;
  CodePage: Word;
  SubBlock: string;
  ValuePtr: PChar;
  ValueLength: UINT;
begin
  Result := '';
  Handle := 0;
  Size := GetFileVersionInfoSize(PChar(AExePath), Handle);
  if Size = 0 then
    Exit;

  SetLength(Buffer, Size);
  if not GetFileVersionInfo(PChar(AExePath), Handle, Size, Buffer) then
    Exit;

  if not VerQueryValue(Buffer, '\VarFileInfo\Translation', TranslationPtr, TranslationLength) then
    Exit;
  if TranslationLength < SizeOf(DWORD) then
    Exit;

  Language := PWord(TranslationPtr)^;
  CodePage := PWord(NativeUInt(TranslationPtr) + SizeOf(Word))^;
  SubBlock := Format('\StringFileInfo\%.4x%.4x\%s', [Language, CodePage, AValueName]);

  if VerQueryValue(Buffer, PChar(SubBlock), Pointer(ValuePtr), ValueLength) and
     (ValueLength > 0) then
    Result := Trim(ValuePtr);
end;

function TPortappixImporter.GetExeFileVersion(const AExePath: string): string;
var
  Handle: DWORD;
  Size: DWORD;
  Buffer: TBytes;
  FixedInfo: PVSFixedFileInfo;
  FixedLength: UINT;
begin
  Result := QueryVersionString(AExePath, 'FileVersion');
  if Result <> '' then
    Exit;

  Handle := 0;
  Size := GetFileVersionInfoSize(PChar(AExePath), Handle);
  if Size = 0 then
    Exit;

  SetLength(Buffer, Size);
  if not GetFileVersionInfo(PChar(AExePath), Handle, Size, Buffer) then
    Exit;

  if VerQueryValue(Buffer, '\', Pointer(FixedInfo), FixedLength) and
     (FixedLength >= SizeOf(TVSFixedFileInfo)) then
    Result := Format('%d.%d.%d.%d',
      [HiWord(FixedInfo.dwFileVersionMS), LoWord(FixedInfo.dwFileVersionMS),
       HiWord(FixedInfo.dwFileVersionLS), LoWord(FixedInfo.dwFileVersionLS)]);
end;

function TPortappixImporter.MakeId(const ABaseName: string): string;
var
  Source: string;
  PreviousWasSeparator: Boolean;
begin
  Source := ABaseName.Trim.ToLower;
  Result := '';
  PreviousWasSeparator := False;

  for var Character in Source do
  begin
    if CharInSet(Character, ['a'..'z', '0'..'9']) then
    begin
      Result := Result + Character;
      PreviousWasSeparator := False;
    end
    else if not PreviousWasSeparator and (Result <> '') then
    begin
      Result := Result + '-';
      PreviousWasSeparator := True;
    end;
  end;

  while (Result <> '') and (Result[Length(Result)] = '-') do
    Delete(Result, Length(Result), 1);

  if Result = '' then
    Result := 'app';
end;

function TPortappixImporter.MakeRelativeExePath(const ASourceFolder, ATargetExe: string): string;
var
  SourceFolder: string;
  TargetExe: string;
  RelativePath: string;
begin
  SourceFolder := IncludeTrailingPathDelimiter(TPath.GetFullPath(ASourceFolder));
  TargetExe := TPath.GetFullPath(ATargetExe);

  if not TargetExe.ToLower.StartsWith(SourceFolder.ToLower) then
    raise EPortappixImporterError.CreateFmt(
      'Target executable "%s" must be inside source folder "%s".', [ATargetExe, ASourceFolder]);

  RelativePath := ExtractRelativePath(SourceFolder, TargetExe);
  Result := StringReplace(RelativePath, '/', '\', [rfReplaceAll]);
  if Result = '' then
    Result := TPath.GetFileName(TargetExe);
end;

class function TPortappixImporter.GenerateManifest(const SourceFolder, TargetExe: string): Boolean;
var
  Importer: TPortappixImporter;
  ManifestPath: string;
  AppId: string;
begin
  Importer := TPortappixImporter.Create;
  try
    Result := Importer.GenerateManifest(SourceFolder, TargetExe, '', ManifestPath, AppId);
  finally
    Importer.Free;
  end;
end;

function TPortappixImporter.GenerateManifest(const SourceFolder, TargetExe: string;
  const APublisher: string): Boolean;
var
  ManifestPath: string;
  AppId: string;
begin
  Result := GenerateManifest(SourceFolder, TargetExe, APublisher, ManifestPath, AppId);
end;

function TPortappixImporter.GenerateManifest(const SourceFolder, TargetExe: string;
  const APublisher: string; out AManifestPath, AAppId: string): Boolean;
var
  Source: string;
  ExePath: string;
  ProductName: string;
  CompanyName: string;
  Version: string;
  Name: string;
  IdBase: string;
  Publisher: string;
  RelativeExe: string;
  Root: TJSONObject;
  Env: TJSONObject;
  Registry: TJSONArray;
  Junctions: TJSONObject;
begin
  AManifestPath := '';
  AAppId := '';

  Source := ResolvePath(SourceFolder);
  if not TDirectory.Exists(Source) then
    raise EPortappixImporterError.CreateFmt('Source folder not found: "%s".', [Source]);

  if IsRelativePath(TargetExe) then
    ExePath := TPath.GetFullPath(TPath.Combine(Source, TargetExe))
  else
    ExePath := TPath.GetFullPath(TargetExe);

  if not TFile.Exists(ExePath) then
    raise EPortappixImporterError.CreateFmt('Target executable not found: "%s".', [ExePath]);

  ProductName := QueryVersionString(ExePath, 'ProductName');
  CompanyName := QueryVersionString(ExePath, 'CompanyName');
  Version := GetExeFileVersion(ExePath);

  if ProductName = '' then
    Name := TPath.GetFileNameWithoutExtension(ExePath)
  else
    Name := ProductName;

  IdBase := ProductName;
  if IdBase = '' then
    IdBase := TPath.GetFileNameWithoutExtension(ExePath);
  AAppId := MakeId(IdBase);

  Publisher := APublisher.Trim;
  if Publisher = '' then
    Publisher := CompanyName;

  RelativeExe := MakeRelativeExePath(Source, ExePath);

  Root := TJSONObject.Create;
  try
    Root.AddPair('id', AAppId);
    Root.AddPair('name', Name);
    if Publisher <> '' then
      Root.AddPair('publisher', Publisher);
    if Version <> '' then
      Root.AddPair('version', Version);
    Root.AddPair('exe', RelativeExe);

    Env := TJSONObject.Create;
    Env.AddPair('APPDATA', '{data}\AppData');
    Root.AddPair('env', Env);

    Registry := TJSONArray.Create;
    Root.AddPair('registry', Registry);

    Junctions := TJSONObject.Create;
    Root.AddPair('junctions', Junctions);

    AManifestPath := TPath.Combine(Source, 'app.json');
    TFile.WriteAllText(AManifestPath, Root.Format(2), TEncoding.UTF8);
  finally
    Root.Free;
  end;

  Result := True;
end;

procedure TPortappixImporter.CopyDirectory(const ASourceDir, ADestinationDir: string);
begin
  if TDirectory.Exists(ADestinationDir) then
    raise EPortappixImporterError.CreateFmt('Destination directory already exists: "%s".',
      [ADestinationDir]);

  TDirectory.CreateDirectory(ADestinationDir);

  for var Directory in TDirectory.GetDirectories(ASourceDir, '*', TSearchOption.soTopDirectoryOnly) do
    CopyDirectory(Directory, TPath.Combine(ADestinationDir, TPath.GetFileName(Directory)));

  for var FileName in TDirectory.GetFiles(ASourceDir, '*', TSearchOption.soTopDirectoryOnly) do
    TFile.Copy(FileName, TPath.Combine(ADestinationDir, TPath.GetFileName(FileName)), False);
end;

function TPortappixImporter.ImportToApps(const SourceFolder, TargetExe: string;
  const APublisher: string; const AAppsRoot: string): string;
var
  Source: string;
  ManifestPath: string;
  AppId: string;
  AppsRoot: string;
  Destination: string;
begin
  Source := ResolvePath(SourceFolder);

  if not GenerateManifest(Source, TargetExe, APublisher, ManifestPath, AppId) then
    raise EPortappixImporterError.Create('Unable to generate app.json manifest.');

  if AAppsRoot.Trim = '' then
    AppsRoot := TPath.Combine(FRootPath, 'Apps')
  else if IsRelativePath(AAppsRoot) then
    AppsRoot := TPath.GetFullPath(TPath.Combine(FRootPath, AAppsRoot))
  else
    AppsRoot := TPath.GetFullPath(AAppsRoot);

  ForceDirectories(AppsRoot);
  Destination := TPath.Combine(AppsRoot, AppId);
  CopyDirectory(Source, Destination);
  Result := Destination;
end;

class function TPortappixImporter.ImportToApps(const SourceFolder, TargetExe: string;
  const APublisher, AAppsRoot: string): string;
var
  Importer: TPortappixImporter;
  RootPath: string;
begin
  RootPath := LauncherDirectory;
  if AAppsRoot.Trim <> '' then
    RootPath := TPath.GetDirectoryName(TPath.GetFullPath(AAppsRoot));
  Importer := TPortappixImporter.Create(RootPath);
  try
    Result := Importer.ImportToApps(SourceFolder, TargetExe, APublisher, AAppsRoot);
  finally
    Importer.Free;
  end;
end;

end.
