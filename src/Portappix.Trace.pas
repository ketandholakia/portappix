unit Portappix.Trace;

{
  "What did this app touch" trace reports.

  A trace runs an installed app WITHOUT virtualization (no environment
  overrides, no junctions, no registry hijack) and compares snapshots of
  well-known host locations taken before and after the run. The diff is
  condensed into:
    - report.json / report.md    what changed on the host
    - suggested_app.json         a draft app.json with the env overrides,
                                 junctions and registry keys that would
                                 sandbox the app

  Trace mode is intended for virtual machines or Windows Sandbox: the app
  runs unrestricted on the host. Reports only ever describe changes; nothing
  is restored or deleted.

  The unit is engine-only (no VCL/Forms). File system and registry access are
  abstracted behind IPortappixFileProbe / IPortappixRegistryProbe so unit
  tests can feed fake data without touching the host. WriteReports can be
  called directly, so tests never launch a process either.
}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  System.StrUtils,
  System.DateUtils,
  System.Math,
  System.Generics.Collections,
  System.Generics.Defaults,
  System.JSON,
  System.Win.Registry,
  Portappix.Common,
  Portappix.Manifest,
  Portappix.Policy,
  Portappix.Registry,
  Portappix.Process;

type
  EPortappixTraceError = class(Exception);
  EPortappixTracePolicyError = class(EPortappixTraceError);
  EPortappixTraceElevationRequired = class(EPortappixTraceError);

  TPortappixRegistryValue = record
    Name: string;
    Kind: Integer;          // ordinal of System.Win.Registry.TRegDataType
    Data: TBytes;
    Truncated: Boolean;     // Data was cut at MaxValueBytes
  end;

  TPortappixFileVisit = reference to procedure(const AFullPath: string;
    ASize: Int64; ALastWriteUtc: TDateTime; var AStop: Boolean);
  TPortappixKeyVisit = reference to procedure(const AKeyPath: string;
    const AValues: TArray<TPortappixRegistryValue>; var AStop: Boolean);

  /// Raw enumeration of files under a root. Implementations must skip
  /// reparse points (junctions/symlinks) and report full paths.
  IPortappixFileProbe = interface
    ['{9E1D2C64-8F0A-4B7E-9C3B-1A6F54D2E7A1}']
    procedure EnumerateFiles(const ARootPath: string; AMaxDepth: Integer;
      const AOnFile: TPortappixFileVisit);
  end;

  /// Raw enumeration of registry keys under a root key path such as
  /// 'HKCU\Software'. Implementations report normalized 'HKCU\...' paths.
  IPortappixRegistryProbe = interface
    ['{C7A4F1B8-3E5D-4D92-8B6C-42F0A9E31D5B}']
    procedure EnumerateKeys(const AKeyPath: string; AMaxDepth: Integer;
      AMaxValueBytes, AMaxValuesPerKey: Integer;
      const AOnKey: TPortappixKeyVisit);
  end;

  TPortappixFileProbe = class(TInterfacedObject, IPortappixFileProbe)
  public
    procedure EnumerateFiles(const ARootPath: string; AMaxDepth: Integer;
      const AOnFile: TPortappixFileVisit); virtual;
  end;

  TPortappixRegistryProbe = class(TInterfacedObject, IPortappixRegistryProbe)
  public
    procedure EnumerateKeys(const AKeyPath: string; AMaxDepth: Integer;
      AMaxValueBytes, AMaxValuesPerKey: Integer;
      const AOnKey: TPortappixKeyVisit); virtual;
  end;

  TPortappixFileRoot = record
    Path: string;           // may contain %VARIABLES%
    MaxDepth: Integer;
    constructor Create(const APath: string; AMaxDepth: Integer);
  end;

  TPortappixTraceOptions = record
    FileRoots: TArray<TPortappixFileRoot>;
    RegistryRoots: TArray<string>;
    RegistryMaxDepth: Integer;
    MaxFiles: Integer;
    MaxKeys: Integer;
    MaxValuesPerKey: Integer;
    MaxFileHashBytes: Integer;   // files larger than this are compared by metadata only
    MaxValueBytes: Integer;      // registry value data is hashed up to this size
    TimeBudgetMs: Int64;         // per snapshot; 0 disables the budget
  end;

  TPortappixSnapshotFile = record
    Path: string;
    Size: Int64;
    Hash: string;           // SHA-256 of the content; '' when not hashed
    LastWriteUtc: TDateTime;
  end;

  TPortappixSnapshotKey = record
    Path: string;           // e.g. HKCU\Software\Vendor\App
    ValuesHash: string;     // SHA-256 over value names, kinds and data
  end;

  TPortappixSnapshot = record
    Files: TArray<TPortappixSnapshotFile>;
    Keys: TArray<TPortappixSnapshotKey>;
    FileRoots: TArray<string>;  // resolved roots that were walked
    Truncated: Boolean;         // a file/key cap or the time budget was hit
    ElapsedMs: Int64;
    function FileCount: Integer;
    function KeyCount: Integer;
  end;

  TPortappixDiffKind = (dkAdded, dkModified, dkDeleted);

  TPortappixFileDiff = record
    Kind: TPortappixDiffKind;
    Path: string;
    SizeBefore: Int64;
    SizeAfter: Int64;
    MetadataOnly: Boolean;  // detected from size/timestamp (content not hashed)
  end;

  TPortappixKeyDiff = record
    Kind: TPortappixDiffKind;
    Path: string;
  end;

  TPortappixDiff = record
    Files: TArray<TPortappixFileDiff>;
    Keys: TArray<TPortappixKeyDiff>;
    function IsEmpty: Boolean;
  end;

  /// Filters known host noise (prefetch, thumbnail caches, Explorer MRUs,
  /// Windows Search index, the launcher's own folders) out of snapshots so
  /// reports only show what the app really did.
  TPortappixTraceNoiseFilter = class
  private
    FFileFragments: TStringList;      // case-insensitive path fragments
    FFileNamePrefixes: TStringList;   // case-insensitive file name prefixes
    FKeyPrefixes: TStringList;        // case-insensitive registry key prefixes
  public
    constructor Create(const ALauncherRoot: string = '');
    destructor Destroy; override;
    procedure AddFileFragment(const AFragment: string);
    procedure AddFileNamePrefix(const APrefix: string);
    procedure AddRegistryPrefix(const APrefix: string);
    function IsNoiseFile(const AFullPath: string): Boolean;
    function IsNoiseKey(const AKeyPath: string): Boolean;
  end;

  TPortappixKnownFolders = record
    AppData: string;
    LocalAppData: string;
    Temp: string;
    ProgramData: string;
    Profile: string;
    Documents: string;
    Desktop: string;
    PublicFolder: string;
  end;

  TPortappixSuggestionKind = (skEnvironment, skJunction, skRegistry,
    skWarning, skManualReview);

  TPortappixSuggestion = record
    Kind: TPortappixSuggestionKind;
    Key: string;     // env var name, junction host, registry key or ''
    Value: string;   // env value, junction target or ''
    Message: string;
    constructor Create(AKind: TPortappixSuggestionKind; const AKey, AValue,
      AMessage: string);
  end;

  TPortappixTrace = class
  public
    class function TakeSnapshot(const AOptions: TPortappixTraceOptions;
      const AFileProbe: IPortappixFileProbe;
      const ARegistryProbe: IPortappixRegistryProbe;
      const ANoise: TPortappixTraceNoiseFilter): TPortappixSnapshot; static;
    class function DiffSnapshots(const ABefore,
      AAfter: TPortappixSnapshot): TPortappixDiff; static;
    class function SuggestFromDiff(const ADiff: TPortappixDiff;
      const AFolders: TPortappixKnownFolders; const ADataDir, AAppDir,
      ALauncherRoot: string): TArray<TPortappixSuggestion>; static;
  end;

  TPortappixTraceResult = record
    ReportDirectory: string;
    ReportJsonFile: string;
    ReportMarkdownFile: string;
    SuggestedManifestFile: string;
    AppExitCode: Cardinal;
    FilesAdded: Integer;
    FilesModified: Integer;
    FilesDeleted: Integer;
    KeysAdded: Integer;
    KeysModified: Integer;
    KeysDeleted: Integer;
    SuggestionCount: Integer;
    WarningCount: Integer;
    ManualReviewCount: Integer;
    Truncated: Boolean;
  end;

  /// Runs one app without virtualization and writes the trace reports into
  /// <root>\Trace\<app-id>_<timestamp>\. Probes can be replaced for tests;
  /// WriteReports can be called directly so tests never launch a process.
  TPortappixTraceRunner = class
  private
    FRootPath: string;
    FManifestPath: string;
    FManifest: TPortappixManifest;
    FAppDir: string;
    FDataDir: string;
    FOptions: TPortappixTraceOptions;
    FNoise: TPortappixTraceNoiseFilter;
    FFileProbe: IPortappixFileProbe;
    FRegistryProbe: IPortappixRegistryProbe;
    FOnLog: TProc<string>;
    procedure Log(const AMessage: string);
    function ExpandTokens(const AValue: string): string;
    function ResolveExePath: string;
    function CreateReportDirectory(const AAppId: string): string;
    function LaunchUnvirtualized(const AExePath: string): Cardinal;
    procedure WriteJsonReport(const AResult: TPortappixTraceResult;
      const ADiff: TPortappixDiff; const ASuggestions: TArray<TPortappixSuggestion>;
      const ABefore, AAfter: TPortappixSnapshot);
    procedure WriteMarkdownReport(const AResult: TPortappixTraceResult;
      const ADiff: TPortappixDiff; const ASuggestions: TArray<TPortappixSuggestion>;
      const ABefore, AAfter: TPortappixSnapshot);
    procedure WriteSuggestedManifest(const AResult: TPortappixTraceResult;
      const ASuggestions: TArray<TPortappixSuggestion>);
  public
    constructor Create(const ARootPath, AManifestPath: string);
    destructor Destroy; override;
    function Execute: TPortappixTraceResult;
    function WriteReports(const AReportDirectory: string;
      const ABefore, AAfter: TPortappixSnapshot; AAppExitCode: Cardinal;
      out ASuggestions: TArray<TPortappixSuggestion>): TPortappixTraceResult;
    property Manifest: TPortappixManifest read FManifest;
    property ManifestPath: string read FManifestPath;
    property RootPath: string read FRootPath;
    property DataDirectory: string read FDataDir;
    property Options: TPortappixTraceOptions read FOptions write FOptions;
    property FileProbe: IPortappixFileProbe read FFileProbe write FFileProbe;
    property RegistryProbe: IPortappixRegistryProbe read FRegistryProbe write FRegistryProbe;
    property NoiseFilter: TPortappixTraceNoiseFilter read FNoise;
    property OnLog: TProc<string> read FOnLog write FOnLog;
  end;

function DefaultTraceOptions: TPortappixTraceOptions;
function KnownFoldersFromEnvironment: TPortappixKnownFolders;

implementation

const
  ERROR_ELEVATION_REQUIRED = 740;

  MaxReportEntriesPerSection = 1000;
  MaxPathsPerWarningMessage = 10;
  MaxProgramDataJunctions = 4;

  DefaultFileFragments: array[0..5] of string = (
    '\prefetch\',
    '\microsoft\windows\explorer\',
    '\microsoft\search\',
    '\recent\',
    '\windows\inetcache\',
    '\crashdumps\');

  DefaultFileNamePrefixes: array[0..3] of string = (
    'thumbcache_', 'iconcache_', 'ntuser.dat', 'usrclass.dat');

  DefaultRegistryPrefixes: array[0..6] of string = (
    'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs',
    'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU',
    'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths',
    'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32',
    'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist',
    'HKCU\Software\Microsoft\Windows\Shell',
    'HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache');

function DiffKindText(AKind: TPortappixDiffKind): string;
begin
  case AKind of
    dkAdded: Result := 'added';
    dkModified: Result := 'modified';
  else
    Result := 'deleted';
  end;
end;

function SuggestionKindText(AKind: TPortappixSuggestionKind): string;
begin
  case AKind of
    skEnvironment: Result := 'environment';
    skJunction: Result := 'junction';
    skRegistry: Result := 'registry';
    skWarning: Result := 'warning';
  else
    Result := 'manualReview';
  end;
end;

function HashRegistryValues(const AValues: TArray<TPortappixRegistryValue>): string;
var
  Builder: TList<Byte>;
  NameBytes: TBytes;
  KindBytes: array[0..3] of Byte;
begin
  Builder := TList<Byte>.Create;
  try
    for var Value in AValues do
    begin
      NameBytes := TEncoding.UTF8.GetBytes(Value.Name.ToLower);
      Builder.AddRange(NameBytes);
      Builder.Add(0);
      Move(Value.Kind, KindBytes[0], SizeOf(KindBytes));
      Builder.AddRange(KindBytes);
      Builder.Add(Byte(Ord(Value.Truncated)));
      Builder.AddRange(Value.Data);
      Builder.Add(0);
    end;
    Result := Sha256Bytes(Builder.ToArray);
  finally
    Builder.Free;
  end;
end;

function IsPrefixOfKey(const APrefix, AKeyPath: string): Boolean;
begin
  Result := TextStartsWith(AKeyPath, APrefix) and
    ((Length(AKeyPath) = Length(APrefix)) or
     (AKeyPath[Length(APrefix) + 1] = '\'));
end;

function RelativeDirectoryUnder(const APath, ARoot: string): string;
var
  FullPath: string;
  FullRoot: string;
begin
  Result := '';
  FullPath := TrimTrailingPathDelimiter(TPath.GetFullPath(APath));
  FullRoot := TrimTrailingPathDelimiter(TPath.GetFullPath(ARoot));
  if not TextStartsWith(FullPath, FullRoot + '\') then
    Exit;
  Result := TPath.GetDirectoryName(FullPath.Substring(Length(FullRoot) + 1));
end;

function CommonRegistryPrefix(const AKeys: TArray<string>): string;
var
  First: TArray<string>;
  Prefix: string;
  ComponentIndex: Integer;
begin
  Result := '';
  if Length(AKeys) = 0 then
    Exit;

  First := AKeys[0].Split(['\']);
  Prefix := '';
  for ComponentIndex := 0 to High(First) do
  begin
    for var Key in AKeys do
    begin
      var Parts := Key.Split(['\']);
      if (ComponentIndex > High(Parts)) or
         not SameText(Parts[ComponentIndex], First[ComponentIndex]) then
        Exit(Prefix);
    end;
    if Prefix = '' then
      Prefix := First[ComponentIndex]
    else
      Prefix := Prefix + '\' + First[ComponentIndex];
  end;
  Result := Prefix;
end;

function PathListText(const APaths: TList<string>): string;
var
  Builder: TStringBuilder;
  Count: Integer;
begin
  Builder := TStringBuilder.Create;
  try
    Count := 0;
    for var PathItem in APaths do
    begin
      Inc(Count);
      if Count > MaxPathsPerWarningMessage then
      begin
        Builder.Append(Format(' (and %d more)', [APaths.Count - MaxPathsPerWarningMessage]));
        Break;
      end;
      if Count > 1 then
        Builder.Append('; ');
      Builder.Append(PathItem);
    end;
    Result := Builder.ToString;
  finally
    Builder.Free;
  end;
end;

function SnapshotStats(const ASnapshot: TPortappixSnapshot): TJSONObject;
var
  RootsArray: TJSONArray;
begin
  Result := TJSONObject.Create;
  Result.AddPair('files', TJSONNumber.Create(ASnapshot.FileCount));
  Result.AddPair('keys', TJSONNumber.Create(ASnapshot.KeyCount));
  Result.AddPair('truncated', TJSONBool.Create(ASnapshot.Truncated));
  Result.AddPair('elapsedMs', TJSONNumber.Create(ASnapshot.ElapsedMs));

  RootsArray := TJSONArray.Create;
  for var RootPath in ASnapshot.FileRoots do
    RootsArray.Add(RootPath);
  Result.AddPair('fileRoots', RootsArray);
end;

function SuggestionsToJson(
  const ASuggestions: TArray<TPortappixSuggestion>): TJSONArray;
begin
  Result := TJSONArray.Create;
  for var Suggestion in ASuggestions do
  begin
    var Entry := TJSONObject.Create;
    Entry.AddPair('kind', SuggestionKindText(Suggestion.Kind));
    Entry.AddPair('key', Suggestion.Key);
    Entry.AddPair('value', Suggestion.Value);
    Entry.AddPair('message', Suggestion.Message);
    Result.Add(Entry);
  end;
end;

function StringsToJsonArray(const AStrings: TStrings): TJSONArray;
begin
  Result := TJSONArray.Create;
  for var Index := 0 to AStrings.Count - 1 do
    Result.Add(AStrings[Index]);
end;

function ParseTraceRootsOverride(const AValue: string): TArray<TPortappixFileRoot>;
var
  Depth: Integer;
  Spec: string;
  EqualsAt: Integer;
begin
  Result := [];
  for var Entry in AValue.Split([';']) do
  begin
    Spec := Entry.Trim;
    if Spec = '' then
      Continue;

    Depth := 6;
    EqualsAt := Spec.LastIndexOf('=');
    if EqualsAt > 0 then
      if TryStrToInt(Spec.Substring(EqualsAt + 1).Trim, Depth) and (Depth >= 1) then
        Spec := Spec.Substring(0, EqualsAt).Trim
      else
        Depth := 6;

    if Spec = '' then
      Continue;
    SetLength(Result, Length(Result) + 1);
    Result[High(Result)] := TPortappixFileRoot.Create(Spec, Depth);
  end;
end;

{ Default options }

constructor TPortappixFileRoot.Create(const APath: string; AMaxDepth: Integer);
begin
  Path := APath;
  MaxDepth := AMaxDepth;
end;

function DefaultTraceOptions: TPortappixTraceOptions;
var
  Roots: TList<TPortappixFileRoot>;
begin
  Roots := TList<TPortappixFileRoot>.Create;
  try
    Roots.Add(TPortappixFileRoot.Create('%APPDATA%', 6));
    Roots.Add(TPortappixFileRoot.Create('%LOCALAPPDATA%', 6));
    Roots.Add(TPortappixFileRoot.Create('%PROGRAMDATA%', 4));
    Roots.Add(TPortappixFileRoot.Create('%USERPROFILE%', 1));
    Roots.Add(TPortappixFileRoot.Create('%USERPROFILE%\Documents', 1));
    Roots.Add(TPortappixFileRoot.Create('%USERPROFILE%\Desktop', 1));
    Roots.Add(TPortappixFileRoot.Create('%USERPROFILE%\Downloads', 1));
    Roots.Add(TPortappixFileRoot.Create('%PUBLIC%', 2));
    Result.FileRoots := Roots.ToArray;
  finally
    Roots.Free;
  end;

  Result.RegistryRoots := TArray<string>.Create('HKCU\Software');
  Result.RegistryMaxDepth := 8;
  Result.MaxFiles := 20000;
  Result.MaxKeys := 20000;
  Result.MaxValuesPerKey := 256;
  Result.MaxFileHashBytes := 1024 * 1024;
  Result.MaxValueBytes := 4096;
  Result.TimeBudgetMs := 5000;

  // Test/tooling hook: replace the default file roots, e.g.
  // PORTAPPIX_TRACE_ROOTS=C:\vm\appdata=6;C:\vm\programdata=4
  var OverrideRoots := GetEnvironmentVariable('PORTAPPIX_TRACE_ROOTS').Trim;
  if OverrideRoots <> '' then
    Result.FileRoots := ParseTraceRootsOverride(OverrideRoots);

  // Test/tooling hook: replace the default registry roots, e.g.
  // PORTAPPIX_TRACE_REGISTRY=HKCU\Software (default) or a VM-only key.
  var OverrideRegistry := GetEnvironmentVariable('PORTAPPIX_TRACE_REGISTRY').Trim;
  if OverrideRegistry <> '' then
    Result.RegistryRoots := OverrideRegistry.Split([';']);
end;

function KnownFoldersFromEnvironment: TPortappixKnownFolders;
var
  Profile: string;
begin
  Profile := TrimTrailingPathDelimiter(GetEnvironmentVariable('USERPROFILE'));
  Result.AppData := TrimTrailingPathDelimiter(GetEnvironmentVariable('APPDATA'));
  Result.LocalAppData := TrimTrailingPathDelimiter(GetEnvironmentVariable('LOCALAPPDATA'));
  Result.Temp := TrimTrailingPathDelimiter(GetEnvironmentVariable('TEMP'));
  Result.ProgramData := TrimTrailingPathDelimiter(GetEnvironmentVariable('PROGRAMDATA'));
  Result.Profile := Profile;
  Result.PublicFolder := TrimTrailingPathDelimiter(GetEnvironmentVariable('PUBLIC'));
  if Profile <> '' then
  begin
    Result.Documents := TPath.Combine(Profile, 'Documents');
    Result.Desktop := TPath.Combine(Profile, 'Desktop');
  end
  else
  begin
    Result.Documents := '';
    Result.Desktop := '';
  end;
end;

{ Probes }

procedure TPortappixFileProbe.EnumerateFiles(const ARootPath: string;
  AMaxDepth: Integer; const AOnFile: TPortappixFileVisit);
{$WARN SYMBOL_PLATFORM OFF}

  function IsReparseAttribute(AAttributes: DWORD): Boolean;
  begin
    Result := (AAttributes <> INVALID_FILE_ATTRIBUTES) and
      (AAttributes and FILE_ATTRIBUTE_REPARSE_POINT <> 0);
  end;

  function FileTimeToDateTime(const AFileTime: TFileTime): TDateTime;
  var
    LocalTime: TFileTime;
    SystemTime: TSystemTime;
  begin
    FileTimeToLocalFileTime(AFileTime, LocalTime);
    FileTimeToSystemTime(LocalTime, SystemTime);
    Result := SystemTimeToDateTime(SystemTime);
  end;

  // Walks one directory level; returns True when the caller asked to stop.
  function WalkDirectory(const ADirectory: string; ADepth: Integer): Boolean;
  var
    SearchRec: TSearchRec;
    FullPath: string;
    Stop: Boolean;
  begin
    Result := False;
    if FindFirst(TPath.Combine(ADirectory, '*'), faAnyFile, SearchRec) <> 0 then
    begin
      FindClose(SearchRec);
      Exit;
    end;
    try
      repeat
        if (SearchRec.Name = '.') or (SearchRec.Name = '..') then
          Continue;
        if SearchRec.Attr and faDirectory <> 0 then
          Continue;
        if SearchRec.Attr and FILE_ATTRIBUTE_REPARSE_POINT <> 0 then
          Continue;

        FullPath := TPath.Combine(ADirectory, SearchRec.Name);
        Stop := False;
        AOnFile(FullPath, SearchRec.Size,
          FileTimeToDateTime(SearchRec.FindData.ftLastWriteTime), Stop);
        if Stop then
          Exit(True);
      until FindNext(SearchRec) <> 0;
    finally
      FindClose(SearchRec);
    end;

    if ADepth >= AMaxDepth then
      Exit;

    if FindFirst(TPath.Combine(ADirectory, '*'), faAnyFile, SearchRec) = 0 then
    try
      repeat
        if (SearchRec.Name = '.') or (SearchRec.Name = '..') then
          Continue;
        if (SearchRec.Attr and faDirectory) = 0 then
          Continue;
        if SearchRec.Attr and FILE_ATTRIBUTE_REPARSE_POINT <> 0 then
          Continue;

        if WalkDirectory(TPath.Combine(ADirectory, SearchRec.Name), ADepth + 1) then
          Exit(True);
      until FindNext(SearchRec) <> 0;
    finally
      FindClose(SearchRec);
    end;
  end;

begin
  if (ARootPath = '') or not TDirectory.Exists(ARootPath) then
    Exit;
  if IsReparseAttribute(FileGetAttr(ARootPath)) then
    Exit;
  if AMaxDepth < 1 then
    AMaxDepth := 1;
  WalkDirectory(ARootPath, 1);
end;
{$WARN SYMBOL_PLATFORM ON}

procedure TPortappixRegistryProbe.EnumerateKeys(const AKeyPath: string;
  AMaxDepth: Integer; AMaxValueBytes, AMaxValuesPerKey: Integer;
  const AOnKey: TPortappixKeyVisit);

  function RegTypeToKind(AWin32Type: DWORD): Integer;
  begin
    case AWin32Type of
      REG_SZ: Result := 1;           // rdString
      REG_EXPAND_SZ: Result := 2;    // rdExpandString
      REG_DWORD: Result := 3;        // rdInteger
      REG_BINARY: Result := 4;       // rdBinary
    else
      Result := 0;                   // unknown (REG_MULTI_SZ, REG_QWORD, ...)
    end;
  end;

  // Reads one value's type and data (capped at AMaxValueBytes).
  function ReadValue(AKeyHandle: HKEY; const AValueName: string;
    out AKind: Integer; out AData: TBytes; out ATruncated: Boolean): Boolean;
  var
    ValueType: DWORD;
    RequiredSize: DWORD;
    Status: LONG;
  begin
    AKind := 0;
    AData := nil;
    ATruncated := False;

    if AMaxValueBytes <= 0 then
      Exit(False);

    SetLength(AData, AMaxValueBytes);
    RequiredSize := DWORD(AMaxValueBytes);
    Status := RegQueryValueEx(AKeyHandle, PChar(AValueName), nil, @ValueType,
      @AData[0], @RequiredSize);
    if Status = ERROR_SUCCESS then
    begin
      SetLength(AData, Integer(RequiredSize));
      AKind := RegTypeToKind(ValueType);
      Exit(True);
    end;

    if Status = ERROR_MORE_DATA then
    begin
      // The first AMaxValueBytes bytes were written; the value is truncated.
      SetLength(AData, AMaxValueBytes);
      AKind := RegTypeToKind(ValueType);
      ATruncated := True;
      Exit(True);
    end;

    SetLength(AData, 0);
    Result := False;
  end;

  // Returns True when the caller asked to stop.
  function WalkKeys(const AFullKeyPath: string; ADepth: Integer): Boolean;
  var
    RootKey: HKEY;
    SubKey: string;
    Registry: TRegistry;
    ValueNames: TStringList;
    SubKeyNames: TStringList;
    Values: TArray<TPortappixRegistryValue>;
    Stop: Boolean;
  begin
    Result := False;
    if not ParseRegistryPath(AFullKeyPath, RootKey, SubKey) then
      Exit;

    Registry := TRegistry.Create(KEY_READ);
    try
      Registry.RootKey := RootKey;
      if (SubKey = '') or not Registry.OpenKeyReadOnly(SubKey) then
        Exit;
      try
        ValueNames := TStringList.Create;
        try
          Registry.GetValueNames(ValueNames);
          SetLength(Values, Min(ValueNames.Count, AMaxValuesPerKey));
          for var Index := 0 to High(Values) do
          begin
            Values[Index].Name := ValueNames[Index];
            Values[Index].Kind := 0;
            Values[Index].Data := nil;
            Values[Index].Truncated := False;
            ReadValue(Registry.CurrentKey, ValueNames[Index], Values[Index].Kind,
              Values[Index].Data, Values[Index].Truncated);
          end;
        finally
          ValueNames.Free;
        end;

        Stop := False;
        AOnKey(AFullKeyPath, Values, Stop);
        if Stop then
          Exit(True);

        if ADepth >= AMaxDepth then
          Exit(False);

        SubKeyNames := TStringList.Create;
        try
          Registry.GetKeyNames(SubKeyNames);
          for var Index := 0 to SubKeyNames.Count - 1 do
            if SubKeyNames[Index] <> '' then
              if WalkKeys(AFullKeyPath + '\' + SubKeyNames[Index], ADepth + 1) then
                Exit(True);
        finally
          SubKeyNames.Free;
        end;
      finally
        Registry.CloseKey;
      end;
    finally
      Registry.Free;
    end;
  end;

begin
  if AKeyPath.Trim = '' then
    Exit;
  if AMaxDepth < 1 then
    AMaxDepth := 1;
  WalkKeys(AKeyPath.Trim, 1);
end;

{ Noise filter }

constructor TPortappixSuggestion.Create(AKind: TPortappixSuggestionKind;
  const AKey, AValue, AMessage: string);
begin
  Kind := AKind;
  Key := AKey;
  Value := AValue;
  Message := AMessage;
end;

constructor TPortappixTraceNoiseFilter.Create(const ALauncherRoot: string);
begin
  inherited Create;
  FFileFragments := TStringList.Create;
  FFileNamePrefixes := TStringList.Create;
  FKeyPrefixes := TStringList.Create;

  for var Fragment in DefaultFileFragments do
    AddFileFragment(Fragment);
  for var Prefix in DefaultFileNamePrefixes do
    AddFileNamePrefix(Prefix);
  for var Prefix in DefaultRegistryPrefixes do
    AddRegistryPrefix(Prefix);

  // Never report the launcher's own files.
  if ALauncherRoot <> '' then
    AddFileFragment(IncludeTrailingPathDelimiter(
      TrimTrailingPathDelimiter(TPath.GetFullPath(ALauncherRoot))).ToLower);
end;

destructor TPortappixTraceNoiseFilter.Destroy;
begin
  FFileFragments.Free;
  FFileNamePrefixes.Free;
  FKeyPrefixes.Free;
  inherited;
end;

procedure TPortappixTraceNoiseFilter.AddFileFragment(const AFragment: string);
begin
  if AFragment.Trim <> '' then
    FFileFragments.Add(AFragment.ToLower);
end;

procedure TPortappixTraceNoiseFilter.AddFileNamePrefix(const APrefix: string);
begin
  if APrefix.Trim <> '' then
    FFileNamePrefixes.Add(APrefix.ToLower);
end;

procedure TPortappixTraceNoiseFilter.AddRegistryPrefix(const APrefix: string);
begin
  if APrefix.Trim <> '' then
    FKeyPrefixes.Add(APrefix.ToLower);
end;

function TPortappixTraceNoiseFilter.IsNoiseFile(const AFullPath: string): Boolean;
var
  LowerPath: string;
  FileName: string;
begin
  LowerPath := AFullPath.ToLower;
  for var Fragment in FFileFragments do
    if Pos(Fragment, LowerPath) > 0 then
      Exit(True);

  FileName := TPath.GetFileName(LowerPath);
  for var Prefix in FFileNamePrefixes do
    if TextStartsWith(FileName, Prefix) then
      Exit(True);

  Result := False;
end;

function TPortappixTraceNoiseFilter.IsNoiseKey(const AKeyPath: string): Boolean;
var
  LowerPath: string;
begin
  LowerPath := AKeyPath.ToLower;
  for var Prefix in FKeyPrefixes do
    if IsPrefixOfKey(Prefix, LowerPath) then
      Exit(True);
  Result := False;
end;

{ Snapshot / diff / suggestions }

procedure SortSnapshotFiles(var AFiles: TArray<TPortappixSnapshotFile>);
begin
  TArray.Sort<TPortappixSnapshotFile>(AFiles,
    TComparer<TPortappixSnapshotFile>.Construct(
      function(const ALeft, ARight: TPortappixSnapshotFile): Integer
      begin
        Result := CompareText(ALeft.Path, ARight.Path);
      end));
end;

procedure SortSnapshotKeys(var AKeys: TArray<TPortappixSnapshotKey>);
begin
  TArray.Sort<TPortappixSnapshotKey>(AKeys,
    TComparer<TPortappixSnapshotKey>.Construct(
      function(const ALeft, ARight: TPortappixSnapshotKey): Integer
      begin
        Result := CompareText(ALeft.Path, ARight.Path);
      end));
end;

function TPortappixSnapshot.FileCount: Integer;
begin
  Result := Length(Files);
end;

function TPortappixSnapshot.KeyCount: Integer;
begin
  Result := Length(Keys);
end;

function TPortappixDiff.IsEmpty: Boolean;
begin
  Result := (Length(Files) = 0) and (Length(Keys) = 0);
end;

class function TPortappixTrace.TakeSnapshot(const AOptions: TPortappixTraceOptions;
  const AFileProbe: IPortappixFileProbe;
  const ARegistryProbe: IPortappixRegistryProbe;
  const ANoise: TPortappixTraceNoiseFilter): TPortappixSnapshot;
var
  Files: TDictionary<string, TPortappixSnapshotFile>;
  Keys: TDictionary<string, TPortappixSnapshotKey>;
  ResolvedRoots: TList<string>;
  Deadline: UInt64;
  Stopped: Boolean;
  StartedAt: UInt64;
begin
  if AFileProbe = nil then
    raise EPortappixTraceError.Create('A file probe is required to take a snapshot.');
  if ARegistryProbe = nil then
    raise EPortappixTraceError.Create('A registry probe is required to take a snapshot.');
  if ANoise = nil then
    raise EPortappixTraceError.Create('A noise filter is required to take a snapshot.');

  Files := TDictionary<string, TPortappixSnapshotFile>.Create(TIStringComparer.Ordinal);
  Keys := TDictionary<string, TPortappixSnapshotKey>.Create(TIStringComparer.Ordinal);
  ResolvedRoots := TList<string>.Create;
  try
    StartedAt := GetTickCount64;
    if AOptions.TimeBudgetMs > 0 then
      Deadline := StartedAt + UInt64(AOptions.TimeBudgetMs)
    else
      Deadline := 0;
    Stopped := False;

    for var Root in AOptions.FileRoots do
    begin
      if Stopped then
        Break;

      var Resolved := TrimTrailingPathDelimiter(TPath.GetFullPath(
        ExpandPercentVariables(Root.Path)));
      if Resolved = '' then
        Continue;
      ResolvedRoots.Add(Resolved);

      AFileProbe.EnumerateFiles(Resolved, Root.MaxDepth,
        procedure(const AFullPath: string; ASize: Int64; ALastWriteUtc: TDateTime;
          var AStop: Boolean)
        var
          Record_: TPortappixSnapshotFile;
        begin
          if Files.Count >= AOptions.MaxFiles then
          begin
            Stopped := True;
            AStop := True;
            Exit;
          end;
          if (Deadline > 0) and (GetTickCount64 > Deadline) then
          begin
            Stopped := True;
            AStop := True;
            Exit;
          end;
          if ANoise.IsNoiseFile(AFullPath) then
            Exit;

          Record_.Path := TPath.GetFullPath(AFullPath);
          Record_.Size := ASize;
          Record_.LastWriteUtc := ALastWriteUtc;
          Record_.Hash := '';
          if (AOptions.MaxFileHashBytes > 0) and (ASize >= 0) and
             (ASize <= AOptions.MaxFileHashBytes) then
            try
              Record_.Hash := Sha256File(AFullPath);
            except
              Record_.Hash := '';
            end;

          Files.AddOrSetValue(Record_.Path, Record_);
        end);
    end;

    for var RegistryRoot in AOptions.RegistryRoots do
    begin
      if Stopped then
        Break;
      if RegistryRoot.Trim = '' then
        Continue;

      ARegistryProbe.EnumerateKeys(RegistryRoot.Trim, AOptions.RegistryMaxDepth,
        AOptions.MaxValueBytes, AOptions.MaxValuesPerKey,
        procedure(const AKeyPath: string;
          const AValues: TArray<TPortappixRegistryValue>; var AStop: Boolean)
        var
          Record_: TPortappixSnapshotKey;
        begin
          if Keys.Count >= AOptions.MaxKeys then
          begin
            Stopped := True;
            AStop := True;
            Exit;
          end;
          if (Deadline > 0) and (GetTickCount64 > Deadline) then
          begin
            Stopped := True;
            AStop := True;
            Exit;
          end;
          if ANoise.IsNoiseKey(AKeyPath) then
            Exit;

          Record_.Path := AKeyPath;
          Record_.ValuesHash := HashRegistryValues(AValues);
          Keys.AddOrSetValue(Record_.Path, Record_);
        end);
    end;

    Result.Files := Files.Values.ToArray;
    Result.Keys := Keys.Values.ToArray;
    Result.FileRoots := ResolvedRoots.ToArray;
    Result.Truncated := Stopped;
    Result.ElapsedMs := Int64(GetTickCount64 - StartedAt);

    SortSnapshotFiles(Result.Files);
    SortSnapshotKeys(Result.Keys);
  finally
    Files.Free;
    Keys.Free;
    ResolvedRoots.Free;
  end;
end;

class function TPortappixTrace.DiffSnapshots(const ABefore,
  AAfter: TPortappixSnapshot): TPortappixDiff;
var
  FileDiffs: TList<TPortappixFileDiff>;
  KeyDiffs: TList<TPortappixKeyDiff>;
  IndexBefore: Integer;
  IndexAfter: Integer;
  Compare: Integer;
begin
  FileDiffs := TList<TPortappixFileDiff>.Create;
  KeyDiffs := TList<TPortappixKeyDiff>.Create;
  try
    IndexBefore := 0;
    IndexAfter := 0;
    while (IndexBefore < Length(ABefore.Files)) or
          (IndexAfter < Length(AAfter.Files)) do
    begin
      if IndexBefore >= Length(ABefore.Files) then
        Compare := 1
      else if IndexAfter >= Length(AAfter.Files) then
        Compare := -1
      else
        Compare := CompareText(ABefore.Files[IndexBefore].Path,
          AAfter.Files[IndexAfter].Path);

      if Compare < 0 then
      begin
        var Diff: TPortappixFileDiff;
        Diff.Kind := dkDeleted;
        Diff.Path := ABefore.Files[IndexBefore].Path;
        Diff.SizeBefore := ABefore.Files[IndexBefore].Size;
        Diff.SizeAfter := 0;
        Diff.MetadataOnly := False;
        FileDiffs.Add(Diff);
        Inc(IndexBefore);
      end
      else if Compare > 0 then
      begin
        var Diff: TPortappixFileDiff;
        Diff.Kind := dkAdded;
        Diff.Path := AAfter.Files[IndexAfter].Path;
        Diff.SizeBefore := 0;
        Diff.SizeAfter := AAfter.Files[IndexAfter].Size;
        Diff.MetadataOnly := False;
        FileDiffs.Add(Diff);
        Inc(IndexAfter);
      end
      else
      begin
        var BeforeFile := ABefore.Files[IndexBefore];
        var AfterFile := AAfter.Files[IndexAfter];
        var Modified: Boolean;
        var MetadataOnly: Boolean;

        if (BeforeFile.Hash <> '') or (AfterFile.Hash <> '') then
        begin
          Modified := not SameText(BeforeFile.Hash, AfterFile.Hash);
          MetadataOnly := (BeforeFile.Hash = '') or (AfterFile.Hash = '');
        end
        else
        begin
          Modified := (BeforeFile.Size <> AfterFile.Size) or
            (BeforeFile.LastWriteUtc <> AfterFile.LastWriteUtc);
          MetadataOnly := True;
        end;

        if Modified then
        begin
          var Diff: TPortappixFileDiff;
          Diff.Kind := dkModified;
          Diff.Path := AfterFile.Path;
          Diff.SizeBefore := BeforeFile.Size;
          Diff.SizeAfter := AfterFile.Size;
          Diff.MetadataOnly := MetadataOnly;
          FileDiffs.Add(Diff);
        end;
        Inc(IndexBefore);
        Inc(IndexAfter);
      end;
    end;

    IndexBefore := 0;
    IndexAfter := 0;
    while (IndexBefore < Length(ABefore.Keys)) or
          (IndexAfter < Length(AAfter.Keys)) do
    begin
      if IndexBefore >= Length(ABefore.Keys) then
        Compare := 1
      else if IndexAfter >= Length(AAfter.Keys) then
        Compare := -1
      else
        Compare := CompareText(ABefore.Keys[IndexBefore].Path,
          AAfter.Keys[IndexAfter].Path);

      if Compare < 0 then
      begin
        var Diff: TPortappixKeyDiff;
        Diff.Kind := dkDeleted;
        Diff.Path := ABefore.Keys[IndexBefore].Path;
        KeyDiffs.Add(Diff);
        Inc(IndexBefore);
      end
      else if Compare > 0 then
      begin
        var Diff: TPortappixKeyDiff;
        Diff.Kind := dkAdded;
        Diff.Path := AAfter.Keys[IndexAfter].Path;
        KeyDiffs.Add(Diff);
        Inc(IndexAfter);
      end
      else
      begin
        if ABefore.Keys[IndexBefore].ValuesHash <>
           AAfter.Keys[IndexAfter].ValuesHash then
        begin
          var Diff: TPortappixKeyDiff;
          Diff.Kind := dkModified;
          Diff.Path := AAfter.Keys[IndexAfter].Path;
          KeyDiffs.Add(Diff);
        end;
        Inc(IndexBefore);
        Inc(IndexAfter);
      end;
    end;

    Result.Files := FileDiffs.ToArray;
    Result.Keys := KeyDiffs.ToArray;
  finally
    FileDiffs.Free;
    KeyDiffs.Free;
  end;
end;

class function TPortappixTrace.SuggestFromDiff(const ADiff: TPortappixDiff;
  const AFolders: TPortappixKnownFolders; const ADataDir, AAppDir,
  ALauncherRoot: string): TArray<TPortappixSuggestion>;
var
  Suggestions: TList<TPortappixSuggestion>;
  Seen: TDictionary<string, Boolean>;
  ProgramDataDirs: TList<string>;
  WarnPaths: TList<string>;
  OtherPaths: TList<string>;
  KeyPaths: TList<string>;
  AppDataTouched: Boolean;
  LocalAppDataTouched: Boolean;
  TempTouched: Boolean;
  DirectProgramDataRootWrites: Integer;

  procedure Add(const ASuggestion: TPortappixSuggestion);
  var
    DedupeKey: string;
    AlreadySeen: Boolean;
  begin
    DedupeKey := SuggestionKindText(ASuggestion.Kind) + '|' +
      ASuggestion.Key.ToLower + '|' + ASuggestion.Value.ToLower + '|' +
      ASuggestion.Message.ToLower;
    if Seen.TryGetValue(DedupeKey, AlreadySeen) then
      Exit;
    Seen.AddOrSetValue(DedupeKey, True);
    Suggestions.Add(ASuggestion);
  end;

  function FirstPathComponent(const ARelative: string): string;
  begin
    if ARelative = '' then
      Exit('');
    var Parts := ARelative.Split(['\']);
    Result := Parts[0];
  end;

begin
  Suggestions := TList<TPortappixSuggestion>.Create;
  Seen := TDictionary<string, Boolean>.Create;
  ProgramDataDirs := TList<string>.Create;
  WarnPaths := TList<string>.Create;
  OtherPaths := TList<string>.Create;
  KeyPaths := TList<string>.Create;
  try
    AppDataTouched := False;
    LocalAppDataTouched := False;
    TempTouched := False;
    DirectProgramDataRootWrites := 0;

    for var FileDiff in ADiff.Files do
    begin
      if FileDiff.Kind = dkDeleted then
        Continue;

      var PathItem := FileDiff.Path;
      if (ALauncherRoot <> '') and IsPathUnder(PathItem, ALauncherRoot) then
        Continue;
      if (ADataDir <> '') and IsPathUnder(PathItem, ADataDir) then
        Continue;
      if (AAppDir <> '') and IsPathUnder(PathItem, AAppDir) then
        Continue;

      if (AFolders.AppData <> '') and IsPathUnder(PathItem, AFolders.AppData) then
        AppDataTouched := True
      else if (AFolders.LocalAppData <> '') and
              IsPathUnder(PathItem, AFolders.LocalAppData) then
      begin
        if (AFolders.Temp <> '') and IsPathUnder(PathItem, AFolders.Temp) then
          TempTouched := True
        else
          LocalAppDataTouched := True;
      end
      else if (AFolders.ProgramData <> '') and
              IsPathUnder(PathItem, AFolders.ProgramData) and
              not SameText(TrimTrailingPathDelimiter(PathItem),
                TrimTrailingPathDelimiter(AFolders.ProgramData)) then
      begin
        var Relative := RelativeDirectoryUnder(PathItem, AFolders.ProgramData);
        if Relative = '' then
          Inc(DirectProgramDataRootWrites)
        else
          ProgramDataDirs.Add(FirstPathComponent(Relative));
      end
      else if ((AFolders.Documents <> '') and IsPathUnder(PathItem, AFolders.Documents)) or
              ((AFolders.Desktop <> '') and IsPathUnder(PathItem, AFolders.Desktop)) or
              ((AFolders.PublicFolder <> '') and IsPathUnder(PathItem, AFolders.PublicFolder)) then
        WarnPaths.Add(PathItem)
      else if (AFolders.Profile <> '') and IsPathUnder(PathItem, AFolders.Profile) and
              SameText(TrimTrailingPathDelimiter(TPath.GetDirectoryName(PathItem)),
                TrimTrailingPathDelimiter(AFolders.Profile)) then
        WarnPaths.Add(PathItem)
      else
        OtherPaths.Add(PathItem);
    end;

    // Environment overrides: the folders Portappix redirects with env vars.
    if AppDataTouched then
      Add(TPortappixSuggestion.Create(skEnvironment, 'APPDATA', '{data}\AppData',
        'The app wrote into %APPDATA%; overriding APPDATA redirects it into the portable data folder.'));
    if LocalAppDataTouched then
      Add(TPortappixSuggestion.Create(skEnvironment, 'LOCALAPPDATA', '{data}\LocalAppData',
        'The app wrote into %LOCALAPPDATA%; overriding LOCALAPPDATA redirects it into the portable data folder.'));
    if TempTouched then
    begin
      Add(TPortappixSuggestion.Create(skEnvironment, 'TEMP', '{data}\Temp',
        'The app wrote into %TEMP%; overriding TEMP redirects it into the portable data folder.'));
      Add(TPortappixSuggestion.Create(skEnvironment, 'TMP', '{data}\Temp',
        'The app wrote into %TEMP%; overriding TMP redirects it into the portable data folder.'));
    end;

    // Junctions for %PROGRAMDATA%: group writes by their top-level folder.
    if DirectProgramDataRootWrites > 0 then
      Add(TPortappixSuggestion.Create(skManualReview, '%PROGRAMDATA%', '',
        Format('The app writes directly into the %PROGRAMDATA% root (%d file(s)); that cannot be redirected with a junction.',
          [DirectProgramDataRootWrites])));

    var DistinctDirs := TList<string>.Create;
    try
      for var Dir in ProgramDataDirs do
        if not DistinctDirs.Contains(Dir) then
          DistinctDirs.Add(Dir);

      if DistinctDirs.Count > MaxProgramDataJunctions then
        Add(TPortappixSuggestion.Create(skManualReview, '', '',
          Format('The app wrote into %d top-level %PROGRAMDATA% folders; pick the ones to redirect manually (%s).',
            [DistinctDirs.Count, PathListText(DistinctDirs)])))
      else
        for var Dir in DistinctDirs do
        begin
          var HostPath := '%PROGRAMDATA%\' + Dir;
          var TargetPath := '{data}\ProgramData\' + Dir;
          var Policy := TPolicyResult.Create;
          try
            var Allowed :=
              TPortappixPolicy.ValidateJunctionHost(HostPath, Policy) and
              TPortappixPolicy.ValidateJunctionTarget(TargetPath, Policy);
            if Allowed then
              Add(TPortappixSuggestion.Create(skJunction, HostPath, TargetPath,
                Format('The app wrote into %%PROGRAMDATA%%\%s; a junction redirects it into the portable data folder.', [Dir])))
            else
              Add(TPortappixSuggestion.Create(skManualReview, HostPath, '',
                Format('Junction host "%s" needs manual review: %s', [HostPath, Policy.Summary])));
          finally
            Policy.Free;
          end;
        end;
    finally
      DistinctDirs.Free;
    end;

    // Registry keys: collapse to the shortest common HKCU\Software prefix.
    for var KeyDiff in ADiff.Keys do
      KeyPaths.Add(KeyDiff.Path);

    var ValidKeys := TList<string>.Create;
    try
      for var KeyPath in KeyPaths do
        if TextStartsWith(KeyPath.ToLower, 'hkcu\software\') then
          ValidKeys.Add(KeyPath)
        else
          Add(TPortappixSuggestion.Create(skManualReview, KeyPath, '',
            Format('Registry key "%s" is outside HKCU\Software; hijacking it needs manual review.', [KeyPath])));

      if ValidKeys.Count > 0 then
      begin
        var Prefix := CommonRegistryPrefix(ValidKeys.ToArray);
        var Policy := TPolicyResult.Create;
        try
          if TPortappixPolicy.ValidateRegistryPath(Prefix, Policy) then
            Add(TPortappixSuggestion.Create(skRegistry, Prefix, '',
              'Changed registry keys live under this key; hijacking it keeps them in the portable registry.'))
          else
            Add(TPortappixSuggestion.Create(skManualReview, Prefix, '',
              Format('Common registry prefix "%s" needs manual review: %s', [Prefix, Policy.Summary])));
        finally
          Policy.Free;
        end;
      end;
    finally
      ValidKeys.Free;
    end;

    // Warnings for folders Portappix cannot or should not redirect.
    if WarnPaths.Count > 0 then
      Add(TPortappixSuggestion.Create(skWarning, '', '',
        'The app wrote into protected user or public folders: ' +
        PathListText(WarnPaths) + '.'));
    if OtherPaths.Count > 0 then
      Add(TPortappixSuggestion.Create(skWarning, '', '',
        'The app wrote outside the folders Portappix can redirect automatically: ' +
        PathListText(OtherPaths) + '.'));

    Result := Suggestions.ToArray;
  finally
    Suggestions.Free;
    Seen.Free;
    ProgramDataDirs.Free;
    WarnPaths.Free;
    OtherPaths.Free;
    KeyPaths.Free;
  end;
end;

{ Trace runner }

constructor TPortappixTraceRunner.Create(const ARootPath, AManifestPath: string);
begin
  inherited Create;
  FRootPath := ResolveRootPath(ARootPath);
  FManifestPath := ResolveFromRoot(FRootPath, AManifestPath);
  FManifest := TPortappixManifest.LoadFromFile(FManifestPath);
  FAppDir := TPath.GetDirectoryName(FManifestPath);
  FDataDir := TPath.GetFullPath(TPath.Combine(TPath.Combine(FRootPath, 'Data'),
    FManifest.Id));

  FOptions := DefaultTraceOptions;
  FNoise := TPortappixTraceNoiseFilter.Create(FRootPath);
  FNoise.AddFileFragment(IncludeTrailingPathDelimiter(FDataDir));
  FNoise.AddFileFragment(IncludeTrailingPathDelimiter(FAppDir));

  FFileProbe := TPortappixFileProbe.Create;
  FRegistryProbe := TPortappixRegistryProbe.Create;
end;

destructor TPortappixTraceRunner.Destroy;
begin
  FFileProbe := nil;
  FRegistryProbe := nil;
  FreeAndNil(FNoise);
  FreeAndNil(FManifest);
  inherited;
end;

procedure TPortappixTraceRunner.Log(const AMessage: string);
begin
  if Assigned(FOnLog) then
    FOnLog(AMessage);
end;

function TPortappixTraceRunner.ExpandTokens(const AValue: string): string;
begin
  Result := ExpandManifestTokens(AValue, FRootPath, FAppDir, FDataDir, FManifest.Id);
end;

function TPortappixTraceRunner.ResolveExePath: string;
var
  ExePath: string;
begin
  ExePath := StringReplace(ExpandTokens(FManifest.Exe), '/', '\', [rfReplaceAll]);
  if IsRelativePath(ExePath) then
    ExePath := TPath.GetFullPath(TPath.Combine(FAppDir, ExePath))
  else
    ExePath := TPath.GetFullPath(ExePath);

  if not TFile.Exists(ExePath) then
    raise EPortappixTraceError.CreateFmt('Executable not found: "%s".', [ExePath]);
  Result := ExePath;
end;

function TPortappixTraceRunner.CreateReportDirectory(const AAppId: string): string;
var
  Base: string;
  Index: Integer;
begin
  Base := TPath.Combine(TPath.Combine(FRootPath, 'Trace'),
    Format('%s_%s', [AAppId, FormatDateTime('yyyymmdd_hhnnss', Now)]));
  Result := Base;
  Index := 2;
  while TDirectory.Exists(Result) do
  begin
    Result := Format('%s_%d', [Base, Index]);
    Inc(Index);
  end;
  ForceDirectories(Result);
end;

function TPortappixTraceRunner.LaunchUnvirtualized(const AExePath: string): Cardinal;
var
  StartupInfo: TStartupInfo;
  ProcessInfo: TProcessInformation;
  CommandLine: string;
  CurrentDirectory: string;
  CurrentDirectoryPointer: PChar;
  ProcessExitCode: DWORD;
  LastError: DWORD;
  Job: TPortappixJob;
begin
  FillChar(StartupInfo, SizeOf(StartupInfo), 0);
  StartupInfo.cb := SizeOf(StartupInfo);

  CommandLine := QuoteArgument(AExePath);
  if FManifest.Args.Trim <> '' then
    CommandLine := CommandLine + ' ' + FManifest.Args;

  CurrentDirectory := TPath.GetDirectoryName(AExePath);
  CurrentDirectoryPointer := nil;
  if CurrentDirectory <> '' then
    CurrentDirectoryPointer := PChar(CurrentDirectory);

  Log(Format('Launching "%s" without virtualization (trace mode).', [AExePath]));

  Job := TPortappixJob.Create;
  try
    // The environment is inherited from the launcher on purpose: trace mode
    // must show where the app writes with the machine's real configuration.
    UniqueString(CommandLine);
    if not CreateProcess(nil, PChar(CommandLine), nil, nil, False,
      CREATE_SUSPENDED or CREATE_UNICODE_ENVIRONMENT, nil, CurrentDirectoryPointer,
      StartupInfo, ProcessInfo) then
    begin
      LastError := GetLastError;
      if LastError = ERROR_ELEVATION_REQUIRED then
        raise EPortappixTraceElevationRequired.CreateFmt(
          '"%s" requires administrator elevation and cannot be traced; run the trace ' +
          'in a VM from a launcher that is allowed to elevate. (Error %u)',
          [AExePath, LastError]);
      raise EPortappixTraceError.CreateFmt('Unable to start "%s": %s',
        [AExePath, SysErrorMessage(Integer(LastError))]);
    end;

    try
      if not Job.IsValid then
        Log('Job objects are not available; waiting for the main process only.')
      else if not Job.AssignProcess(ProcessInfo.hProcess) then
        Log('Unable to assign the process to a job object; waiting for the main process only.');

      if ResumeThread(ProcessInfo.hThread) = Cardinal(-1) then
        raise EPortappixTraceError.CreateFmt('Unable to resume "%s": %s',
          [AExePath, SysErrorMessage(Integer(GetLastError))]);

      if Job.IsValid then
      begin
        if not Job.WaitForEmpty(INFINITE) then
          raise EPortappixTraceError.CreateFmt(
            'Unable to wait for the process tree of "%s" to exit.', [AExePath]);
      end
      else if WaitForSingleObject(ProcessInfo.hProcess, INFINITE) <> WAIT_OBJECT_0 then
      begin
        LastError := GetLastError;
        raise EPortappixTraceError.CreateFmt('Failed while waiting for "%s": %s',
          [AExePath, SysErrorMessage(Integer(LastError))]);
      end;

      if not GetExitCodeProcess(ProcessInfo.hProcess, ProcessExitCode) then
      begin
        LastError := GetLastError;
        raise EPortappixTraceError.CreateFmt('Unable to read the exit code for "%s": %s',
          [AExePath, SysErrorMessage(Integer(LastError))]);
      end;

      Result := ProcessExitCode;
    finally
      CloseHandle(ProcessInfo.hThread);
      CloseHandle(ProcessInfo.hProcess);
    end;
  finally
    Job.Free;
  end;
end;

function TPortappixTraceRunner.Execute: TPortappixTraceResult;
var
  ExePath: string;
  Before: TPortappixSnapshot;
  After: TPortappixSnapshot;
  Suggestions: TArray<TPortappixSuggestion>;
  Policy: TPolicyResult;
begin
  // A trace still refuses manifests Portappix would never run.
  Policy := TPortappixPolicy.ValidateManifest(FManifest);
  try
    if not Policy.Allowed then
      raise EPortappixTracePolicyError.CreateFmt(
        'Manifest "%s" failed policy validation.' + sLineBreak + '%s',
        [FManifestPath, Policy.Summary]);
  finally
    Policy.Free;
  end;

  ExePath := ResolveExePath;

  var ReportDirectory := CreateReportDirectory(FManifest.Id);
  Log(Format('Trace report directory: "%s".', [ReportDirectory]));

  Log('Taking the "before" snapshot of well-known host locations...');
  Before := TPortappixTrace.TakeSnapshot(FOptions, FFileProbe, FRegistryProbe, FNoise);
  Log(Format('Before snapshot: %d file(s), %d key(s) in %d ms%s.',
    [Before.FileCount, Before.KeyCount, Before.ElapsedMs,
     IfThen(Before.Truncated, ' (truncated)', '')]));

  Result.AppExitCode := LaunchUnvirtualized(ExePath);
  Log(Format('Application exited with code %u.', [Result.AppExitCode]));

  Log('Taking the "after" snapshot...');
  After := TPortappixTrace.TakeSnapshot(FOptions, FFileProbe, FRegistryProbe, FNoise);
  Log(Format('After snapshot: %d file(s), %d key(s) in %d ms%s.',
    [After.FileCount, After.KeyCount, After.ElapsedMs,
     IfThen(After.Truncated, ' (truncated)', '')]));

  Result := WriteReports(ReportDirectory, Before, After, Result.AppExitCode,
    Suggestions);
end;

function TPortappixTraceRunner.WriteReports(const AReportDirectory: string;
  const ABefore, AAfter: TPortappixSnapshot; AAppExitCode: Cardinal;
  out ASuggestions: TArray<TPortappixSuggestion>): TPortappixTraceResult;
var
  Diff: TPortappixDiff;
  Folders: TPortappixKnownFolders;
begin
  Diff := TPortappixTrace.DiffSnapshots(ABefore, AAfter);
  Folders := KnownFoldersFromEnvironment;
  ASuggestions := TPortappixTrace.SuggestFromDiff(Diff, Folders, FDataDir,
    FAppDir, FRootPath);

  ForceDirectories(AReportDirectory);

  Result := Default(TPortappixTraceResult);
  Result.ReportDirectory := AReportDirectory;
  Result.AppExitCode := AAppExitCode;
  Result.Truncated := ABefore.Truncated or AAfter.Truncated;

  for var FileDiff in Diff.Files do
    case FileDiff.Kind of
      dkAdded: Inc(Result.FilesAdded);
      dkModified: Inc(Result.FilesModified);
      dkDeleted: Inc(Result.FilesDeleted);
    end;

  for var KeyDiff in Diff.Keys do
    case KeyDiff.Kind of
      dkAdded: Inc(Result.KeysAdded);
      dkModified: Inc(Result.KeysModified);
      dkDeleted: Inc(Result.KeysDeleted);
    end;

  for var Suggestion in ASuggestions do
    case Suggestion.Kind of
      skEnvironment, skJunction, skRegistry: Inc(Result.SuggestionCount);
      skWarning: Inc(Result.WarningCount);
      skManualReview: Inc(Result.ManualReviewCount);
    end;

  Result.ReportJsonFile := TPath.Combine(AReportDirectory, 'report.json');
  Result.ReportMarkdownFile := TPath.Combine(AReportDirectory, 'report.md');
  Result.SuggestedManifestFile := TPath.Combine(AReportDirectory, 'suggested_app.json');

  WriteJsonReport(Result, Diff, ASuggestions, ABefore, AAfter);
  WriteMarkdownReport(Result, Diff, ASuggestions, ABefore, AAfter);
  WriteSuggestedManifest(Result, ASuggestions);

  Log(Format('Trace finished: %d file(s) and %d registry key(s) changed; ' +
    '%d suggestion(s), %d warning(s), %d item(s) need manual review.',
    [Result.FilesAdded + Result.FilesModified + Result.FilesDeleted,
     Result.KeysAdded + Result.KeysModified + Result.KeysDeleted,
     Result.SuggestionCount, Result.WarningCount, Result.ManualReviewCount]));
  if Result.Truncated then
    Log('The snapshot was truncated (file/key cap or time budget); results are incomplete.');
  Log(Format('Report directory: "%s".', [AReportDirectory]));
end;

procedure TPortappixTraceRunner.WriteJsonReport(const AResult: TPortappixTraceResult;
  const ADiff: TPortappixDiff; const ASuggestions: TArray<TPortappixSuggestion>;
  const ABefore, AAfter: TPortappixSnapshot);

  procedure AddFileDiffSection(AParent: TJSONObject; const AName: string;
    AKind: TPortappixDiffKind; ANotes: TStringList);
  var
    Items: TJSONArray;
    Total: Integer;
  begin
    Items := TJSONArray.Create;
    Total := 0;
    for var Diff in ADiff.Files do
    begin
      if Diff.Kind <> AKind then
        Continue;
      Inc(Total);
      if Total > MaxReportEntriesPerSection then
        Continue;

      var Entry := TJSONObject.Create;
      Entry.AddPair('path', Diff.Path);
      if AKind = dkAdded then
        Entry.AddPair('size', TJSONNumber.Create(Diff.SizeAfter))
      else if AKind = dkModified then
      begin
        Entry.AddPair('sizeBefore', TJSONNumber.Create(Diff.SizeBefore));
        Entry.AddPair('sizeAfter', TJSONNumber.Create(Diff.SizeAfter));
        if Diff.MetadataOnly then
          Entry.AddPair('metadataOnly', TJSONBool.Create(True));
      end;
      Items.Add(Entry);
    end;

    AParent.AddPair(AName, Items);
    AParent.AddPair(AName + 'Count', TJSONNumber.Create(Total));
    if Total > MaxReportEntriesPerSection then
      ANotes.Add(Format('The "%s" file list is capped at %d entries; %d were skipped in the report.',
        [AName, MaxReportEntriesPerSection, Total - MaxReportEntriesPerSection]));
  end;

  procedure AddKeyDiffSection(AParent: TJSONObject; const AName: string;
    AKind: TPortappixDiffKind; ANotes: TStringList);
  var
    Items: TJSONArray;
    Total: Integer;
  begin
    Items := TJSONArray.Create;
    Total := 0;
    for var Diff in ADiff.Keys do
    begin
      if Diff.Kind <> AKind then
        Continue;
      Inc(Total);
      if Total <= MaxReportEntriesPerSection then
        Items.Add(Diff.Path);
    end;

    AParent.AddPair(AName, Items);
    AParent.AddPair(AName + 'Count', TJSONNumber.Create(Total));
    if Total > MaxReportEntriesPerSection then
      ANotes.Add(Format('The "%s" registry list is capped at %d entries; %d were skipped in the report.',
        [AName, MaxReportEntriesPerSection, Total - MaxReportEntriesPerSection]));
  end;

var
  Root: TJSONObject;
  FilesObject: TJSONObject;
  RegistryObject: TJSONObject;
  SnapshotObject: TJSONObject;
  Notes: TStringList;
begin
  Notes := TStringList.Create;
  Root := TJSONObject.Create;
  try
    Root.AddPair('schema', TJSONNumber.Create(1));
    Root.AddPair('appId', FManifest.Id);
    Root.AddPair('appName', FManifest.Name);
    Root.AddPair('exe', FManifest.Exe);
    Root.AddPair('finishedAt', DateToISO8601(Now));
    Root.AddPair('appExitCode', TJSONNumber.Create(Integer(AResult.AppExitCode)));

    SnapshotObject := TJSONObject.Create;
    SnapshotObject.AddPair('before', SnapshotStats(ABefore));
    SnapshotObject.AddPair('after', SnapshotStats(AAfter));
    Root.AddPair('snapshot', SnapshotObject);

    FilesObject := TJSONObject.Create;
    AddFileDiffSection(FilesObject, 'added', dkAdded, Notes);
    AddFileDiffSection(FilesObject, 'modified', dkModified, Notes);
    AddFileDiffSection(FilesObject, 'deleted', dkDeleted, Notes);
    Root.AddPair('files', FilesObject);

    RegistryObject := TJSONObject.Create;
    AddKeyDiffSection(RegistryObject, 'added', dkAdded, Notes);
    AddKeyDiffSection(RegistryObject, 'modified', dkModified, Notes);
    AddKeyDiffSection(RegistryObject, 'deleted', dkDeleted, Notes);
    Root.AddPair('registry', RegistryObject);

    Root.AddPair('suggestions', SuggestionsToJson(ASuggestions));

    Notes.Insert(0, 'Registry reads are not captured; only keys that appeared or whose values changed are listed.');
    Root.AddPair('notes', StringsToJsonArray(Notes));

    WriteTextFileAtomic(AResult.ReportJsonFile, Root.Format(2));
  finally
    Root.Free;
    Notes.Free;
  end;
end;

procedure TPortappixTraceRunner.WriteMarkdownReport(
  const AResult: TPortappixTraceResult; const ADiff: TPortappixDiff;
  const ASuggestions: TArray<TPortappixSuggestion>;
  const ABefore, AAfter: TPortappixSnapshot);
var
  Builder: TStringBuilder;

  procedure AddFileSection(const ATitle: string; AKind: TPortappixDiffKind);
  var
    Count: Integer;
  begin
    Builder.AppendLine('## ' + ATitle);
    Count := 0;
    for var Diff in ADiff.Files do
    begin
      if Diff.Kind <> AKind then
        Continue;
      Inc(Count);
      if Count > MaxReportEntriesPerSection then
        Continue;

      case AKind of
        dkAdded:
          Builder.AppendLine(Format('- `%s` (%d bytes)', [Diff.Path, Diff.SizeAfter]));
        dkModified:
          if Diff.MetadataOnly then
            Builder.AppendLine(Format('- `%s` (metadata changed: %d -> %d bytes)',
              [Diff.Path, Diff.SizeBefore, Diff.SizeAfter]))
          else
            Builder.AppendLine(Format('- `%s` (content changed: %d -> %d bytes)',
              [Diff.Path, Diff.SizeBefore, Diff.SizeAfter]));
      else
        Builder.AppendLine('- `' + Diff.Path + '`');
      end;
    end;

    if Count = 0 then
      Builder.AppendLine('(none)');
    if Count > MaxReportEntriesPerSection then
      Builder.AppendLine(Format('- ...%d more entries not listed',
        [Count - MaxReportEntriesPerSection]));
    Builder.AppendLine('');
  end;

  procedure AddKeySection(const ATitle: string; AKind: TPortappixDiffKind);
  var
    Count: Integer;
  begin
    Builder.AppendLine('## ' + ATitle);
    Count := 0;
    for var Diff in ADiff.Keys do
    begin
      if Diff.Kind <> AKind then
        Continue;
      Inc(Count);
      if Count > MaxReportEntriesPerSection then
        Continue;
      Builder.AppendLine('- `' + Diff.Path + '`');
    end;

    if Count = 0 then
      Builder.AppendLine('(none)');
    if Count > MaxReportEntriesPerSection then
      Builder.AppendLine(Format('- ...%d more entries not listed',
        [Count - MaxReportEntriesPerSection]));
    Builder.AppendLine('');
  end;

  procedure AddSuggestionSection(const ATitle: string;
    AKind: TPortappixSuggestionKind);
  var
    Count: Integer;
  begin
    Builder.AppendLine('### ' + ATitle);
    Count := 0;
    for var Suggestion in ASuggestions do
    begin
      if Suggestion.Kind <> AKind then
        Continue;
      Inc(Count);
      case AKind of
        skEnvironment:
          Builder.AppendLine(Format('- `%s` = `%s` — %s',
            [Suggestion.Key, Suggestion.Value, Suggestion.Message]));
        skJunction:
          Builder.AppendLine(Format('- `%s` -> `%s` — %s',
            [Suggestion.Key, Suggestion.Value, Suggestion.Message]));
        skRegistry:
          Builder.AppendLine(Format('- `%s` — %s',
            [Suggestion.Key, Suggestion.Message]));
      else
        Builder.AppendLine('- ' + Suggestion.Message);
      end;
    end;

    if Count = 0 then
      Builder.AppendLine('(none)');
    Builder.AppendLine('');
  end;

begin
  Builder := TStringBuilder.Create;
  try
    Builder.AppendLine(Format('# Portappix trace report — %s (%s)',
      [FManifest.Name, FManifest.Id]));
    Builder.AppendLine('');
    Builder.AppendLine(Format('- App exe: %s', [FManifest.Exe]));
    Builder.AppendLine(Format('- Finished: %s', [DateToISO8601(Now)]));
    Builder.AppendLine(Format('- App exit code: %d', [AResult.AppExitCode]));
    Builder.AppendLine(Format('- Before snapshot: %d file(s), %d key(s), truncated: %s',
      [ABefore.FileCount, ABefore.KeyCount, IfThen(ABefore.Truncated, 'yes', 'no')]));
    Builder.AppendLine(Format('- After snapshot: %d file(s), %d key(s), truncated: %s',
      [AAfter.FileCount, AAfter.KeyCount, IfThen(AAfter.Truncated, 'yes', 'no')]));
    Builder.AppendLine('');

    AddFileSection('Files added', dkAdded);
    AddFileSection('Files modified', dkModified);
    AddFileSection('Files deleted', dkDeleted);
    AddKeySection('Registry keys added', dkAdded);
    AddKeySection('Registry keys modified', dkModified);
    AddKeySection('Registry keys deleted', dkDeleted);

    Builder.AppendLine('## Suggestions');
    Builder.AppendLine('');
    AddSuggestionSection('Environment overrides', skEnvironment);
    AddSuggestionSection('Junctions', skJunction);
    AddSuggestionSection('Registry keys', skRegistry);
    AddSuggestionSection('Warnings', skWarning);
    AddSuggestionSection('Needs manual review', skManualReview);

    Builder.AppendLine('## Notes');
    Builder.AppendLine('- Registry reads are not captured; only keys that appeared or whose values changed are listed.');
    if AResult.Truncated then
      Builder.AppendLine('- The snapshot was truncated (file/key cap or time budget); results are incomplete.');
    Builder.AppendLine('- Trace mode runs the app without virtualization; use a VM or Windows Sandbox for untrusted apps.');
    Builder.AppendLine('');

    WriteTextFileAtomic(AResult.ReportMarkdownFile, Builder.ToString);
  finally
    Builder.Free;
  end;
end;

procedure TPortappixTraceRunner.WriteSuggestedManifest(
  const AResult: TPortappixTraceResult;
  const ASuggestions: TArray<TPortappixSuggestion>);
var
  Root: TJSONObject;
  Env: TJSONObject;
  Junctions: TJSONObject;
  RegistryKeys: TJSONArray;
  Warnings: TJSONArray;
  Review: TJSONArray;
begin
  Root := TJSONObject.Create;
  Env := TJSONObject.Create;
  Junctions := TJSONObject.Create;
  RegistryKeys := TJSONArray.Create;
  Warnings := TJSONArray.Create;
  Review := TJSONArray.Create;
  try
    for var Suggestion in ASuggestions do
      case Suggestion.Kind of
        skEnvironment: Env.AddPair(Suggestion.Key, Suggestion.Value);
        skJunction: Junctions.AddPair(Suggestion.Key, Suggestion.Value);
        skRegistry: RegistryKeys.Add(Suggestion.Key);
        skWarning: Warnings.Add(Suggestion.Message);
        skManualReview: Review.Add(Suggestion.Message);
      end;

    Root.AddPair('schema', TJSONNumber.Create(PortappixManifestSchema));
    Root.AddPair('id', FManifest.Id);
    Root.AddPair('name', FManifest.Name);
    Root.AddPair('exe', FManifest.Exe);
    if FManifest.Args.Trim <> '' then
      Root.AddPair('args', FManifest.Args);
    if FManifest.Version.Trim <> '' then
      Root.AddPair('version', FManifest.Version);

    if Env.Count > 0 then
      Root.AddPair('env', Env)
    else
      Env.Free;
    if Junctions.Count > 0 then
      Root.AddPair('junctions', Junctions)
    else
      Junctions.Free;
    if RegistryKeys.Count > 0 then
      Root.AddPair('registry', RegistryKeys)
    else
      RegistryKeys.Free;
    if Warnings.Count > 0 then
      Root.AddPair('_warnings', Warnings)
    else
      Warnings.Free;
    if Review.Count > 0 then
      Root.AddPair('_manualReview', Review)
    else
      Review.Free;

    WriteTextFileAtomic(AResult.SuggestedManifestFile, Root.Format(2));
  finally
    Root.Free;
  end;
end;

end.
