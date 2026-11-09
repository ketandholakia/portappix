unit Portappix.Importer;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  System.JSON,
  Portappix.Common;

type
  EPortappixImporterError = class(Exception);

  TPortappixSourceAnalysis = record
    TotalBytes: Int64;
    FileCount: Int64;
    IsDriveRoot: Boolean;
    ReparsePointsSkipped: Int64;
    function RequiresConfirmation: Boolean;
  end;

  TPortappixImporter = class
  private
    FRootPath: string;
    FOnLog: TProc<string>;
    function ResolvePath(const APath: string): string;
    procedure CopyDirectory(const ASourceDir, ADestinationDir: string;
      var AAnalysis: TPortappixSourceAnalysis);
    procedure WalkSource(const ADirectory: string; var AAnalysis: TPortappixSourceAnalysis);
    procedure Log(const AMessage: string);
  public
    constructor Create(const ARootPath: string = '');
    class function QueryVersionString(const AExePath, AValueName: string): string; static;
    class function GetExeFileVersion(const AExePath: string): string; static;
    class function MakeId(const ABaseName: string): string; static;
    class function MakeRelativeExePath(const ASourceFolder, ATargetExe: string): string; static;
    class function BuildManifestJson(const ASourceFolder, ATargetExe, APublisher: string;
      out AAppId, AName: string): string; static;
    function AnalyzeSource(const ASourceFolder: string): TPortappixSourceAnalysis;
    class function GenerateManifest(const SourceFolder, TargetExe: string): Boolean; overload; static;
    function GenerateManifest(const SourceFolder, TargetExe: string;
      const APublisher: string; out AManifestPath, AAppId: string): Boolean; overload;
    function ImportToApps(const SourceFolder, TargetExe: string;
      const APublisher: string = ''; const AAppsRoot: string = ''): string;
    property RootPath: string read FRootPath;
    property OnLog: TProc<string> read FOnLog write FOnLog;
  end;

implementation

constructor TPortappixImporter.Create(const ARootPath: string);
begin
  inherited Create;
  FRootPath := ResolveRootPath(ARootPath);
end;

procedure TPortappixImporter.Log(const AMessage: string);
begin
  if Assigned(FOnLog) then
    FOnLog(AMessage);
end;

function TPortappixImporter.ResolvePath(const APath: string): string;
begin
  Result := ResolveFromRoot(FRootPath, APath);
end;

function TPortappixSourceAnalysis.RequiresConfirmation: Boolean;
begin
  Result := IsDriveRoot or (TotalBytes > Int64(2) * 1024 * 1024 * 1024) or
    (FileCount > 20000);
end;

class function TPortappixImporter.QueryVersionString(const AExePath,
  AValueName: string): string;
var
  Handle: DWORD;
  Size: DWORD;
  Buffer: TBytes;
  TranslationPtr: Pointer;
  TranslationLength: UINT;
  Language: Word;
  CodePage: Word;
  SubBlock: string;
  RawValue: Pointer;
  ValueLength: UINT;
begin
  Result := '';
  Handle := 0;
  Size := GetFileVersionInfoSize(PChar(AExePath), Handle);
  if Size = 0 then
    Exit;

  SetLength(Buffer, Size);
  if not GetFileVersionInfo(PChar(AExePath), Handle, Size, @Buffer[0]) then
    Exit;

  if not VerQueryValue(@Buffer[0], '\VarFileInfo\Translation', TranslationPtr, TranslationLength) then
    Exit;
  if TranslationLength < SizeOf(DWORD) then
    Exit;

  Language := PWord(TranslationPtr)^;
  CodePage := PWord(NativeUInt(TranslationPtr) + SizeOf(Word))^;
  SubBlock := Format('\StringFileInfo\%.4x%.4x\%s', [Language, CodePage, AValueName]);

  RawValue := nil;
  if VerQueryValue(@Buffer[0], PChar(SubBlock), RawValue, ValueLength) and
     (RawValue <> nil) and (ValueLength > 0) then
    Result := Trim(PChar(RawValue)^);
end;

class function TPortappixImporter.GetExeFileVersion(const AExePath: string): string;
var
  Handle: DWORD;
  Size: DWORD;
  Buffer: TBytes;
  RawValue: Pointer;
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
  if not GetFileVersionInfo(PChar(AExePath), Handle, Size, @Buffer[0]) then
    Exit;

  RawValue := nil;
  if VerQueryValue(@Buffer[0], '\', RawValue, FixedLength) and
     (RawValue <> nil) and (FixedLength >= SizeOf(TVSFixedFileInfo)) then
  begin
    FixedInfo := PVSFixedFileInfo(RawValue);
    Result := Format('%d.%d.%d.%d',
      [HiWord(FixedInfo.dwFileVersionMS), LoWord(FixedInfo.dwFileVersionMS),
       HiWord(FixedInfo.dwFileVersionLS), LoWord(FixedInfo.dwFileVersionLS)]);
  end;
end;

class function TPortappixImporter.MakeId(const ABaseName: string): string;
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

class function TPortappixImporter.MakeRelativeExePath(const ASourceFolder,
  ATargetExe: string): string;
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

class function TPortappixImporter.BuildManifestJson(const ASourceFolder, ATargetExe,
  APublisher: string; out AAppId, AName: string): string;
var
  Source: string;
  ExePath: string;
  ProductName: string;
  CompanyName: string;
  Version: string;
  IdBase: string;
  Publisher: string;
  RelativeExe: string;
  Root: TJSONObject;
  Env: TJSONObject;
  Registry: TJSONArray;
  Junctions: TJSONObject;
begin
  Source := TPath.GetFullPath(ASourceFolder);
  if not TDirectory.Exists(Source) then
    raise EPortappixImporterError.CreateFmt('Source folder not found: "%s".', [Source]);

  if IsRelativePath(ATargetExe) then
    ExePath := TPath.GetFullPath(TPath.Combine(Source, ATargetExe))
  else
    ExePath := TPath.GetFullPath(ATargetExe);

  if not TFile.Exists(ExePath) then
    raise EPortappixImporterError.CreateFmt('Target executable not found: "%s".', [ExePath]);

  ProductName := QueryVersionString(ExePath, 'ProductName');
  CompanyName := QueryVersionString(ExePath, 'CompanyName');
  Version := GetExeFileVersion(ExePath);

  if ProductName = '' then
    AName := TPath.GetFileNameWithoutExtension(ExePath)
  else
    AName := ProductName;

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
    Root.AddPair('schema', TJSONNumber.Create(PortappixManifestSchema));
    Root.AddPair('id', AAppId);
    Root.AddPair('name', AName);
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

    Result := Root.Format(2);
  finally
    Root.Free;
  end;
end;

procedure TPortappixImporter.WalkSource(const ADirectory: string;
  var AAnalysis: TPortappixSourceAnalysis);
var
  Attributes: DWORD;
begin
  for var Directory in TDirectory.GetDirectories(ADirectory, '*',
    TSearchOption.soTopDirectoryOnly) do
  begin
    Attributes := GetFileAttributes(PChar(Directory));
    if (Attributes <> INVALID_FILE_ATTRIBUTES) and
       ((Attributes and FILE_ATTRIBUTE_REPARSE_POINT) <> 0) then
    begin
      Inc(AAnalysis.ReparsePointsSkipped);
      Continue;
    end;
    WalkSource(Directory, AAnalysis);
  end;

  for var FileName in TDirectory.GetFiles(ADirectory, '*', TSearchOption.soTopDirectoryOnly) do
  begin
    Attributes := GetFileAttributes(PChar(FileName));
    if (Attributes <> INVALID_FILE_ATTRIBUTES) and
       ((Attributes and FILE_ATTRIBUTE_REPARSE_POINT) <> 0) then
    begin
      Inc(AAnalysis.ReparsePointsSkipped);
      Continue;
    end;
    Inc(AAnalysis.FileCount);
    AAnalysis.TotalBytes := AAnalysis.TotalBytes + TFile.GetSize(FileName);
  end;
end;

function TPortappixImporter.AnalyzeSource(
  const ASourceFolder: string): TPortappixSourceAnalysis;
var
  Source: string;
begin
  Source := ResolvePath(ASourceFolder);
  FillChar(Result, SizeOf(Result), 0);
  if not TDirectory.Exists(Source) then
    raise EPortappixImporterError.CreateFmt('Source folder not found: "%s".', [Source]);

  Result.IsDriveRoot := SameText(TPath.GetPathRoot(Source),
    IncludeTrailingPathDelimiter(Source));
  WalkSource(Source, Result);
end;

function TPortappixImporter.GenerateManifest(const SourceFolder, TargetExe: string;
  const APublisher: string; out AManifestPath, AAppId: string): Boolean;
var
  Source: string;
  Json: string;
  AppName: string;
begin
  AManifestPath := '';
  AAppId := '';
  Source := ResolvePath(SourceFolder);
  Json := BuildManifestJson(Source, TargetExe, APublisher, AAppId, AppName);
  AManifestPath := TPath.Combine(Source, 'app.json');
  TFile.WriteAllText(AManifestPath, Json, TEncoding.UTF8);
  Result := True;
end;

class function TPortappixImporter.GenerateManifest(const SourceFolder,
  TargetExe: string): Boolean;
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

procedure TPortappixImporter.CopyDirectory(const ASourceDir,
  ADestinationDir: string; var AAnalysis: TPortappixSourceAnalysis);
var
  Attributes: DWORD;
begin
  TDirectory.CreateDirectory(ADestinationDir);

  for var Directory in TDirectory.GetDirectories(ASourceDir, '*',
    TSearchOption.soTopDirectoryOnly) do
  begin
    Attributes := GetFileAttributes(PChar(Directory));
    if (Attributes <> INVALID_FILE_ATTRIBUTES) and
       ((Attributes and FILE_ATTRIBUTE_REPARSE_POINT) <> 0) then
    begin
      Inc(AAnalysis.ReparsePointsSkipped);
      Log('Skipping reparse point: ' + Directory);
      Continue;
    end;
    CopyDirectory(Directory, TPath.Combine(ADestinationDir,
      TPath.GetFileName(Directory)), AAnalysis);
  end;

  for var FileName in TDirectory.GetFiles(ASourceDir, '*',
    TSearchOption.soTopDirectoryOnly) do
  begin
    Attributes := GetFileAttributes(PChar(FileName));
    if (Attributes <> INVALID_FILE_ATTRIBUTES) and
       ((Attributes and FILE_ATTRIBUTE_REPARSE_POINT) <> 0) then
    begin
      Inc(AAnalysis.ReparsePointsSkipped);
      Log('Skipping reparse point: ' + FileName);
      Continue;
    end;
    TFile.Copy(FileName, TPath.Combine(ADestinationDir, TPath.GetFileName(FileName)), False);
  end;
end;

function TPortappixImporter.ImportToApps(const SourceFolder, TargetExe: string;
  const APublisher: string; const AAppsRoot: string): string;
var
  Source: string;
  Json: string;
  AppId: string;
  AppName: string;
  AppsRoot: string;
  Destination: string;
  TempDir: string;
  Analysis: TPortappixSourceAnalysis;

  procedure DeleteTempQuiet;
  begin
    try
      if TDirectory.Exists(TempDir) then
        TDirectory.Delete(TempDir, True);
    except
      on E: Exception do
        Log('Unable to remove partial import directory: ' + E.Message);
    end;
  end;

begin
  Source := ResolvePath(SourceFolder);
  Json := BuildManifestJson(Source, TargetExe, APublisher, AppId, AppName);

  if AAppsRoot.Trim = '' then
    AppsRoot := TPath.Combine(FRootPath, 'Apps')
  else
    AppsRoot := ResolveFromRoot(FRootPath, AAppsRoot);

  ForceDirectories(AppsRoot);
  Destination := TPath.Combine(AppsRoot, AppId);
  TempDir := Destination + '.new';

  if TDirectory.Exists(Destination) then
    raise EPortappixImporterError.CreateFmt('Destination app already exists: "%s".', [Destination]);

  if TDirectory.Exists(TempDir) then
    DeleteTempQuiet;

  FillChar(Analysis, SizeOf(Analysis), 0);
  try
    CopyDirectory(Source, TempDir, Analysis);
    TFile.WriteAllText(TPath.Combine(TempDir, 'app.json'), Json, TEncoding.UTF8);
    if not RenameFile(TempDir, Destination) then
      raise EPortappixImporterError.CreateFmt(
        'Unable to finalize imported app directory "%s": %s',
        [Destination, SysErrorMessage(Integer(GetLastError))]);
  except
    DeleteTempQuiet;
    raise;
  end;

  Log(Format('Imported %s as %s.', [AppName, AppId]));
  Result := Destination;
end;

end.
