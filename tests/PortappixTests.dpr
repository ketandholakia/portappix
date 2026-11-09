program PortappixTests;

{$APPTYPE CONSOLE}

uses
  Winapi.Windows,
  System.SysUtils,
  System.StrUtils,
  System.Classes,
  System.IOUtils,
  System.Zip,
  System.JSON,
  System.Generics.Collections,
  Portappix.Common,
  Portappix.Manifest,
  Portappix.Policy,
  Portappix.Catalog,
  Portappix.PackageManager,
  Portappix.Registry,
  Portappix.Runner,
  Portappix.Settings,
  Portappix.State,
  Portappix.Trace,
  Portappix.Update,
  Portappix.Version;

type
  TFakeRegistryOps = class(TInterfacedObject, IPortappixRegistryOps)
  protected
    function _AddRef: Integer; stdcall;
    function _Release: Integer; stdcall;
  private
    FCalls: TStringList;
    FExportSucceeds: Boolean;
  public
    constructor Create(const AExportSucceeds: Boolean);
    destructor Destroy; override;
    function KeyExists(const AKey: string): Boolean;
    function ExportKey(const AKey, AFileName: string): Boolean;
    function ImportFile(const AFileName: string): Boolean;
    function DeleteKey(const AKey: string): Boolean;
    function CallOrder: string;
  end;

  TFakeFileProbe = class(TInterfacedObject, IPortappixFileProbe)
  private
    FPaths: TList<string>;
    FSizes: TList<Int64>;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Add(const APath: string; ASize: Int64);
    procedure EnumerateFiles(const ARootPath: string; AMaxDepth: Integer;
      const AOnFile: TPortappixFileVisit);
  end;

  TFakeRegistryProbe = class(TInterfacedObject, IPortappixRegistryProbe)
  private
    FKeys: TStringList;
    FValues: TList<TList<TPortappixRegistryValue>>;
  public
    constructor Create;
    destructor Destroy; override;
    procedure AddValue(const AKeyPath, AValueName: string; AKind: Integer;
      const AData: string);
    procedure EnumerateKeys(const AKeyPath: string; AMaxDepth: Integer;
      AMaxValueBytes, AMaxValuesPerKey: Integer;
      const AOnKey: TPortappixKeyVisit);
  end;

var
  Passed: Integer = 0;
  Failed: Integer = 0;

procedure Check(const ACondition: Boolean; const AName: string);
begin
  if ACondition then
  begin
    Inc(Passed);
    Writeln('PASS: ', AName);
  end
  else
  begin
    Inc(Failed);
    Writeln('FAIL: ', AName);
  end;
end;

procedure ExpectException(const AProc: TProc; const AName: string);
begin
  try
    AProc();
    Check(False, AName + ' (no exception raised)');
  except
    on E: Exception do
      Check(True, AName);
  end;
end;

function MakeTempRoot: string;
begin
  Result := TPath.Combine(TPath.GetTempPath, 'portappix-tests-' +
    FormatDateTime('yyyymmddhhnnsszzz', Now) + '-' + IntToStr(GetCurrentProcessId));
  ForceDirectories(Result);
end;

function WriteTextFile(const APath, AContent: string): string;
begin
  ForceDirectories(TPath.GetDirectoryName(APath));
  TFile.WriteAllText(APath, AContent, TEncoding.UTF8);
  Result := APath;
end;

procedure TestTokenExpansion;
var
  Value: string;
begin
  Value := ExpandManifestTokens('{root}|{app}|{data}|{id}', 'C:\Root', 'C:\Root\Apps\demo',
    'C:\Root\Data\demo', 'demo');
  Check(Value = 'C:\Root|C:\Root\Apps\demo|C:\Root\Data\demo|demo',
    'Token expansion replaces all manifest tokens');
end;

procedure TestManifestParsing(const ARoot: string);
var
  AppDir: string;
  ManifestPath: string;
  Manifest: TPortappixManifest;
begin
  AppDir := TPath.Combine(ARoot, 'demo');
  ManifestPath := WriteTextFile(TPath.Combine(AppDir, 'app.json'),
    '{"name":"Demo","exe":"demo.exe","args":"--portable","version":"1.2.3",' +
    '"category":"Utilities","env":{"APPDATA":"{data}\\AppData"},"registry":[]}');

  Manifest := TPortappixManifest.LoadFromFile(ManifestPath);
  try
    Check(Manifest.Id = 'demo', 'Manifest id defaults to the folder name');
    Check(Manifest.Args = '--portable', 'Manifest parses args');
    Check(Manifest.Version = '1.2.3', 'Manifest parses version');
    Check(Manifest.Category = 'Utilities', 'Manifest parses category');
    Check(Manifest.Schema = PortappixManifestSchema, 'Manifest schema defaults to current');
    Check(ManifestIdMatchesFolder(ManifestPath), 'Manifest id matches Apps folder');
  finally
    Manifest.Free;
  end;

  ExpectException(
    procedure
    begin
      WriteTextFile(TPath.Combine(TPath.Combine(ARoot, 'bad'), 'app.json'),
        '{"id":"other","name":"Bad","exe":"bad.exe"}');
      ManifestIdMatchesFolder(TPath.Combine(TPath.Combine(ARoot, 'bad'), 'app.json'));
      raise Exception.Create('id mismatch should raise');
    end,
    'Manifest id mismatch is detected');
end;

procedure TestPolicy;
var
  Result: TPolicyResult;
  Env: TDictionary<string, string>;
begin
  Result := TPolicyResult.Create;
  try
    Check(TPortappixPolicy.ValidateRegistryPath('HKCU\Software\Vendor\Demo', Result),
      'Policy allows HKCU\Software\<vendor>\<app>');
  finally
    Result.Free;
  end;

  Result := TPolicyResult.Create;
  try
    Check(not TPortappixPolicy.ValidateRegistryPath('HKLM\Software\Vendor\Demo', Result),
      'Policy denies HKLM');
  finally
    Result.Free;
  end;

  Result := TPolicyResult.Create;
  try
    Check(not TPortappixPolicy.ValidateRegistryPath('HKCU\Software', Result),
      'Policy denies HKCU\Software root');
  finally
    Result.Free;
  end;

  Result := TPolicyResult.Create;
  try
    Check(not TPortappixPolicy.ValidateRegistryPath('HKCU\Software\Microsoft\Demo', Result),
      'Policy denies HKCU\Software\Microsoft');
  finally
    Result.Free;
  end;

  Result := TPolicyResult.Create;
  try
    Check(TPortappixPolicy.ValidateJunctionHost('%APPDATA%\PortappixTests', Result),
      'Policy allows %APPDATA% junction hosts');
  finally
    Result.Free;
  end;

  Result := TPolicyResult.Create;
  try
    Check(not TPortappixPolicy.ValidateJunctionHost('C:\Windows\Temp\Portappix', Result),
      'Policy denies junctions in system folders');
  finally
    Result.Free;
  end;

  Result := TPolicyResult.Create;
  try
    Check(not TPortappixPolicy.ValidateJunctionHost('%USERPROFILE%\Documents\Portappix', Result),
      'Policy denies junctions in Documents');
  finally
    Result.Free;
  end;

  Env := TDictionary<string, string>.Create;
  Result := TPolicyResult.Create;
  try
    Env.Add('PATH', '{app}\bin;%PATH%');
    Check(TPortappixPolicy.ValidateEnvironment(Env, Result), 'Policy allows {app} PATH overrides');
  finally
    Result.Free;
    Env.Free;
  end;

  Env := TDictionary<string, string>.Create;
  Result := TPolicyResult.Create;
  try
    Env.Add('PATH', 'C:\Windows');
    Check(not TPortappixPolicy.ValidateEnvironment(Env, Result),
      'Policy denies PATH overrides without {app}/{data}');
  finally
    Result.Free;
    Env.Free;
  end;

  Env := TDictionary<string, string>.Create;
  Result := TPolicyResult.Create;
  try
    Env.Add('WINDIR', 'C:\Elsewhere');
    Check(not TPortappixPolicy.ValidateEnvironment(Env, Result),
      'Policy denies non-allow-listed environment variables');
  finally
    Result.Free;
    Env.Free;
  end;
end;

procedure TestCatalog(const ARoot: string);
var
  Catalog: TPortappixCatalog;
  GoodJson: string;
  Sha: string;
begin
  Sha := StringOfChar('a', 64);
  GoodJson := '{"apps":[{"id":"demo","name":"Demo","version":"1.0","category":"Utilities",' +
    '"url":"https://example.com/demo.zip","sha256":"' + Sha + '","size":123}]}';

  Catalog := TPortappixCatalog.Create;
  try
    Catalog.LoadFromJson(GoodJson);
    Check(Catalog.Apps.Count = 1, 'Catalog parses a valid app list');
    Check(Catalog.FindById('demo') <> nil, 'Catalog FindById works');

    ExpectException(
      procedure
      begin
        Catalog.LoadFromJson('{"apps":[{"id":"broken"}]}');
      end,
      'Catalog rejects malformed entries');

    Check(Catalog.Apps.Count = 1,
      'Catalog keeps the previous list when a reload fails (atomic swap)');

    ExpectException(
      procedure
      begin
        Catalog.LoadFromJson('{"apps":[{"id":"demo","name":"Demo","version":"1.0",' +
          '"url":"http://example.com/demo.zip","sha256":"' + Sha + '","size":1}]}');
      end,
      'Catalog rejects non-https package URLs');

    ExpectException(
      procedure
      begin
        Catalog.LoadFromJson('{"apps":[]}');
        Catalog.LoadFromFile(TPath.Combine(ARoot, 'missing.json'));
      end,
      'Catalog rejects missing files');
  finally
    Catalog.Free;
  end;
end;

procedure TestZipExtraction(const ARoot: string);
var
  SourceFile: string;
  ZipPath: string;
  Zip: TZipFile;
  Manager: TPortappixPackageManager;
  Destination: string;
  SlipZip: string;
begin
  SourceFile := WriteTextFile(TPath.Combine(ARoot, 'payload.txt'), 'hello');
  ZipPath := TPath.Combine(ARoot, 'subfolders.zip');
  Zip := TZipFile.Create;
  try
    Zip.Open(ZipPath, TZipMode.zmWrite);
    Zip.Add(SourceFile, 'sub/dir/file.txt');
    Zip.Close;
  finally
    Zip.Free;
  end;

  Manager := TPortappixPackageManager.Create(ARoot);
  try
    Destination := TPath.Combine(ARoot, 'extracted');
    Manager.ExtractArchive(ZipPath, Destination);
    Check(TFile.Exists(TPath.Combine(Destination, 'sub\dir\file.txt')),
      'Zip extraction preserves subfolders');
  finally
    Manager.Free;
  end;

  SlipZip := TPath.Combine(ARoot, 'slip.zip');
  Zip := TZipFile.Create;
  try
    Zip.Open(SlipZip, TZipMode.zmWrite);
    Zip.Add(SourceFile, '..\escape.txt');
    Zip.Close;
  finally
    Zip.Free;
  end;

  Manager := TPortappixPackageManager.Create(ARoot);
  try
    ExpectException(
      procedure
      begin
        Manager.ExtractArchive(SlipZip, TPath.Combine(ARoot, 'slip-extract'));
      end,
      'Zip extraction rejects zip-slip entries');
  finally
    Manager.Free;
  end;
end;

procedure TestHashing;
begin
  Check(Sha256Text('abc') =
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    'SHA-256 of "abc" matches the reference value');
end;

procedure TestJournal(const ARoot: string);
var
  Journal: TPortappixJournal;
  StateFile: string;
begin
  Journal := TPortappixJournal.Create(ARoot);
  try
    StateFile := Journal.StateFile;
    Journal.AddActiveApp('demo', ['HKCU\Software\Vendor\Demo'], nil);
    Check(TFile.Exists(StateFile), 'Journal writes run_state.json');
    Check(ContainsStr(TFile.ReadAllText(StateFile), 'demo'),
      'Journal records the active app');

    Journal.RemoveActiveApp('demo');
    Check(not ContainsStr(TFile.ReadAllText(StateFile), '"demo"'),
      'Journal removes the active app');

    Journal.AddActiveApp('demo', nil, nil);
    Journal.RecoverPendingCleanups;
    Check(not ContainsStr(TFile.ReadAllText(StateFile), '"demo"'),
      'RecoverPendingCleanups clears entries with no remaining backups');

    TFile.WriteAllText(StateFile, '{ this is not json', TEncoding.UTF8);
    Journal.AddActiveApp('demo', ['HKCU\Software\Vendor\Demo'], nil);
    Check(TFile.Exists(StateFile + '.bad'),
      'Corrupt run_state.json is preserved as run_state.json.bad');
    Journal.RemoveActiveApp('demo');
  finally
    Journal.Free;
  end;
end;

procedure TestRegistryOrdering(const ARoot: string);
var
  FakeOps: TFakeRegistryOps;
  Fake: IPortappixRegistryOps;
  FailingFakeOps: TFakeRegistryOps;
  FailingFake: IPortappixRegistryOps;
  DataDir: string;
  Keys: TArray<string>;
  Order: string;
begin
  SetLength(Keys, 1);
  Keys[0] := 'HKCU\Software\Vendor\Demo';
  DataDir := TPath.Combine(ARoot, 'Data\demo');
  ForceDirectories(DataDir);

  FakeOps := TFakeRegistryOps.Create(True);
  Fake := FakeOps;
  TPortableAppRunner.PerformCleanup('demo', Keys, nil, DataDir, nil, Fake);
  Order := FakeOps.CallOrder;
  Check((Pos('export', Order) > 0) and (Pos('delete', Order) > 0) and
    (Pos('export', Order) < Pos('delete', Order)),
    'PerformCleanup exports registry keys before deleting them');

  FailingFakeOps := TFakeRegistryOps.Create(False);
  FailingFake := FailingFakeOps;
  TPortableAppRunner.PerformCleanup('demo', Keys, nil, DataDir, nil, FailingFake);
  Check(Pos('delete', FailingFakeOps.CallOrder) = 0,
    'PerformCleanup never deletes keys when the export fails');
end;

constructor TFakeRegistryOps.Create(const AExportSucceeds: Boolean);
begin
  inherited Create;
  FExportSucceeds := AExportSucceeds;
  FCalls := TStringList.Create;
end;

function TFakeRegistryOps._AddRef: Integer;
begin
  Result := -1;
end;

function TFakeRegistryOps._Release: Integer;
begin
  Result := -1;
end;

destructor TFakeRegistryOps.Destroy;
begin
  FCalls.Free;
  inherited;
end;

function TFakeRegistryOps.KeyExists(const AKey: string): Boolean;
begin
  FCalls.Add('exists');
  Result := True;
end;

function TFakeRegistryOps.ExportKey(const AKey, AFileName: string): Boolean;
begin
  FCalls.Add('export');
  if not FExportSucceeds then
    Exit(False);
  TFile.WriteAllText(AFileName,
    'Windows Registry Editor Version 5.00' + sLineBreak + sLineBreak +
    '[HKEY_CURRENT_USER\Software\Vendor\Demo]' + sLineBreak + '"Value"="1"' + sLineBreak,
    TEncoding.Unicode);
  Result := True;
end;

function TFakeRegistryOps.ImportFile(const AFileName: string): Boolean;
begin
  FCalls.Add('import');
  Result := True;
end;

function TFakeRegistryOps.DeleteKey(const AKey: string): Boolean;
begin
  FCalls.Add('delete');
  Result := True;
end;

function TFakeRegistryOps.CallOrder: string;
begin
  Result := FCalls.Text;
end;

{ Fake trace probes }

constructor TFakeFileProbe.Create;
begin
  inherited Create;
  FPaths := TList<string>.Create;
  FSizes := TList<Int64>.Create;
end;

destructor TFakeFileProbe.Destroy;
begin
  FPaths.Free;
  FSizes.Free;
  inherited;
end;

procedure TFakeFileProbe.Add(const APath: string; ASize: Int64);
begin
  FPaths.Add(APath);
  FSizes.Add(ASize);
end;

procedure TFakeFileProbe.EnumerateFiles(const ARootPath: string;
  AMaxDepth: Integer; const AOnFile: TPortappixFileVisit);
var
  Stop: Boolean;
begin
  Stop := False;
  for var Index := 0 to FPaths.Count - 1 do
  begin
    AOnFile(FPaths[Index], FSizes[Index], 45000.0, Stop);
    if Stop then
      Exit;
  end;
end;

constructor TFakeRegistryProbe.Create;
begin
  inherited Create;
  FKeys := TStringList.Create;
  FValues := TList<TList<TPortappixRegistryValue>>.Create;
end;

destructor TFakeRegistryProbe.Destroy;
begin
  for var Index := 0 to FValues.Count - 1 do
    FValues[Index].Free;
  FValues.Free;
  FKeys.Free;
  inherited;
end;

procedure TFakeRegistryProbe.AddValue(const AKeyPath, AValueName: string;
  AKind: Integer; const AData: string);
var
  KeyIndex: Integer;
  Value: TPortappixRegistryValue;
begin
  KeyIndex := FKeys.IndexOf(AKeyPath);
  if KeyIndex < 0 then
  begin
    FKeys.Add(AKeyPath);
    KeyIndex := FKeys.IndexOf(AKeyPath);
    FValues.Add(TList<TPortappixRegistryValue>.Create);
  end;

  Value.Name := AValueName;
  Value.Kind := AKind;
  Value.Data := TEncoding.UTF8.GetBytes(AData);
  Value.Truncated := False;
  FValues[KeyIndex].Add(Value);
end;

procedure TFakeRegistryProbe.EnumerateKeys(const AKeyPath: string;
  AMaxDepth: Integer; AMaxValueBytes, AMaxValuesPerKey: Integer;
  const AOnKey: TPortappixKeyVisit);
var
  Stop: Boolean;
begin
  Stop := False;
  for var Index := 0 to FKeys.Count - 1 do
  begin
    AOnKey(FKeys[Index], FValues[Index].ToArray, Stop);
    if Stop then
      Exit;
  end;
end;

{ Trace tests }

function CountFileDiffs(const ADiff: TPortappixDiff;
  AKind: TPortappixDiffKind): Integer;
begin
  Result := 0;
  for var Diff in ADiff.Files do
    if Diff.Kind = AKind then
      Inc(Result);
end;

function CountKeyDiffs(const ADiff: TPortappixDiff;
  AKind: TPortappixDiffKind): Integer;
begin
  Result := 0;
  for var Diff in ADiff.Keys do
    if Diff.Kind = AKind then
      Inc(Result);
end;

function FindSuggestion(const ASuggestions: TArray<TPortappixSuggestion>;
  AKind: TPortappixSuggestionKind; const AKey: string): Integer;
begin
  Result := -1;
  for var Index := 0 to High(ASuggestions) do
    if (ASuggestions[Index].Kind = AKind) and
       SameText(ASuggestions[Index].Key, AKey) then
      Exit(Index);
end;

function OneAddedFileDiff(const APath: string): TPortappixDiff;
begin
  Result := Default(TPortappixDiff);
  SetLength(Result.Files, 1);
  Result.Files[0].Kind := dkAdded;
  Result.Files[0].Path := APath;
end;

procedure TestTraceNoiseFilter;
var
  Filter: TPortappixTraceNoiseFilter;
begin
  Filter := TPortappixTraceNoiseFilter.Create('C:\Root');
  try
    Check(Filter.IsNoiseFile('C:\Windows\Prefetch\APP.EXE-AB12CD.pf'),
      'Noise filter treats Prefetch as noise');
    Check(Filter.IsNoiseFile(
      'C:\Users\demo\AppData\Local\Microsoft\Windows\Explorer\thumbcache_1000.db'),
      'Noise filter treats thumbnail caches as noise');
    Check(Filter.IsNoiseFile('C:\Users\demo\ntuser.dat'),
      'Noise filter treats user registry hive files as noise');
    Check(Filter.IsNoiseFile('C:\Root\Cache\catalog.json'),
      'Noise filter excludes the launcher root');
    Check(Filter.IsNoiseFile(
      'C:\Users\demo\AppData\Roaming\Microsoft\Windows\Recent\a.lnk'),
      'Noise filter treats Explorer Recent items as noise');
    Check(not Filter.IsNoiseFile('C:\Users\demo\AppData\Roaming\Vendor\App\settings.ini'),
      'Noise filter keeps normal app files');
    Check(Filter.IsNoiseFile('C:\tools\myappleftovers\junk.txt') = False,
      'Noise filter ignores unrelated fragments before they are added');
    Filter.AddFileFragment('myappleftovers');
    Check(Filter.IsNoiseFile('C:\tools\myappleftovers\junk.txt'),
      'Custom file fragments are honoured');

    Check(Filter.IsNoiseKey(
      'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\file.txt'),
      'Noise filter treats Explorer RecentDocs as noise');
    Check(Filter.IsNoiseKey(
      'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count'),
      'Noise filter treats UserAssist as noise');
    Check(not Filter.IsNoiseKey('HKCU\Software\Vendor\App\Settings'),
      'Noise filter keeps normal app keys');
    Check(not Filter.IsNoiseKey(
      'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\DocumentSanitizer'),
      'Registry noise prefixes match on component boundaries');
  finally
    Filter.Free;
  end;
end;

procedure TestTraceSnapshotAndDiff(const ARoot: string);
var
  Options: TPortappixTraceOptions;
  Noise: TPortappixTraceNoiseFilter;
  BeforeProbe: TFakeFileProbe;
  AfterProbe: TFakeFileProbe;
  BeforeRegProbe: TFakeRegistryProbe;
  AfterRegProbe: TFakeRegistryProbe;
  BeforeFiles: IPortappixFileProbe;
  AfterFiles: IPortappixFileProbe;
  BeforeKeys: IPortappixRegistryProbe;
  AfterKeys: IPortappixRegistryProbe;
  Before: TPortappixSnapshot;
  After: TPortappixSnapshot;
  Diff: TPortappixDiff;
  SettingsFile: string;
  CacheFile: string;
  MissingFile: string;
begin
  SettingsFile := WriteTextFile(
    TPath.Combine(ARoot, 'appdata\Vendor\App\settings.ini'), 'v1');
  CacheFile := WriteTextFile(TPath.Combine(ARoot, 'appdata\Vendor\App\cache.dat'), 'c');
  MissingFile := TPath.Combine(ARoot, 'appdata\Vendor\App\gone.dat');

  Options := DefaultTraceOptions;
  Options.FileRoots := [TPortappixFileRoot.Create(ARoot, 6)];
  Options.RegistryRoots := ['HKCU\Software'];
  Options.TimeBudgetMs := 60000;
  Noise := TPortappixTraceNoiseFilter.Create('');

  BeforeProbe := TFakeFileProbe.Create;
  BeforeProbe.Add(SettingsFile, 2);
  BeforeProbe.Add(MissingFile, 7);
  BeforeFiles := BeforeProbe;

  BeforeRegProbe := TFakeRegistryProbe.Create;
  BeforeRegProbe.AddValue('HKCU\Software\Vendor\App', 'Settings', 1, '1');
  BeforeKeys := BeforeRegProbe;

  Before := TPortappixTrace.TakeSnapshot(Options, BeforeFiles, BeforeKeys, Noise);
  Check(Before.FileCount = 2, 'Snapshot records files reported by the probe');
  Check(Before.KeyCount = 1, 'Snapshot records keys reported by the probe');
  if Before.FileCount = 2 then
  begin
    var SettingsEntry: TPortappixSnapshotFile;
    var MissingEntry: TPortappixSnapshotFile;
    for var SnapshotFile in Before.Files do
      if SameText(SnapshotFile.Path, SettingsFile) then
        SettingsEntry := SnapshotFile
      else
        MissingEntry := SnapshotFile;
    Check(SettingsEntry.Hash <> '', 'Snapshot hashes file contents');
    Check(MissingEntry.Hash = '',
      'Missing files are tolerated with an empty hash');
  end;
  if Before.KeyCount > 0 then
    Check(Before.Keys[0].ValuesHash <> '', 'Snapshot hashes registry values');

  TFile.WriteAllText(SettingsFile, 'v2 with new content', TEncoding.UTF8);

  AfterProbe := TFakeFileProbe.Create;
  AfterProbe.Add(SettingsFile, 20);
  AfterProbe.Add(CacheFile, 1);
  AfterFiles := AfterProbe;

  AfterRegProbe := TFakeRegistryProbe.Create;
  AfterRegProbe.AddValue('HKCU\Software\Vendor\App', 'Settings', 1, '2');
  AfterRegProbe.AddValue('HKCU\Software\Vendor\App\Sub', 'New', 1, 'x');
  AfterKeys := AfterRegProbe;

  After := TPortappixTrace.TakeSnapshot(Options, AfterFiles, AfterKeys, Noise);
  Diff := TPortappixTrace.DiffSnapshots(Before, After);

  Check(CountFileDiffs(Diff, dkModified) = 1, 'Diff detects modified file content');
  Check(CountFileDiffs(Diff, dkAdded) = 1, 'Diff detects added files');
  Check(CountFileDiffs(Diff, dkDeleted) = 1, 'Diff detects deleted files');
  Check(CountKeyDiffs(Diff, dkModified) = 1, 'Diff detects modified registry values');
  Check(CountKeyDiffs(Diff, dkAdded) = 1, 'Diff detects added registry keys');
  Check(not Diff.IsEmpty, 'Diff is not empty when the host changed');

  for var FileDiff in Diff.Files do
    if (FileDiff.Kind = dkModified) and SameText(FileDiff.Path, SettingsFile) then
      Check(not FileDiff.MetadataOnly,
        'Modified detection uses content hashes when available');

  Check(TPortappixTrace.DiffSnapshots(Before, Before).IsEmpty,
    'Diffing a snapshot with itself is empty');
end;

procedure TestTraceSnapshotCaps(const ARoot: string);
var
  Options: TPortappixTraceOptions;
  Noise: TPortappixTraceNoiseFilter;
  Probe: TFakeFileProbe;
  Files: IPortappixFileProbe;
  Keys: IPortappixRegistryProbe;
  Snapshot: TPortappixSnapshot;
  FilePath: string;
begin
  Options := DefaultTraceOptions;
  Options.FileRoots := [TPortappixFileRoot.Create(ARoot, 6)];
  Options.RegistryRoots := ['HKCU\Software'];
  Options.TimeBudgetMs := 60000;
  Noise := TPortappixTraceNoiseFilter.Create('');

  Probe := TFakeFileProbe.Create;
  for var Index := 1 to 30 do
  begin
    FilePath := WriteTextFile(TPath.Combine(ARoot, Format('many\f%d.bin', [Index])), 'x');
    Probe.Add(FilePath, 1);
  end;
  Probe.Add('C:\Windows\Prefetch\NOISE.EXE-AAAA.pf', 123);
  Files := Probe;
  Keys := TFakeRegistryProbe.Create;

  Snapshot := TPortappixTrace.TakeSnapshot(Options, Files, Keys, Noise);
  Check(Snapshot.FileCount = 30, 'Noise files are excluded from snapshots');
  Check(not Snapshot.Truncated, 'Snapshot is not truncated below the caps');

  Probe := TFakeFileProbe.Create;
  for var Index := 1 to 30 do
    Probe.Add(TPath.Combine(ARoot, Format('many\f%d.bin', [Index])), 1);
  Files := Probe;

  Options.MaxFiles := 10;
  Snapshot := TPortappixTrace.TakeSnapshot(Options, Files, Keys, Noise);
  Check(Snapshot.FileCount = 10, 'MaxFiles caps the snapshot');
  Check(Snapshot.Truncated, 'Hitting MaxFiles marks the snapshot truncated');

  Probe := TFakeFileProbe.Create;
  FilePath := TPath.Combine(ARoot, 'many\f1.bin');
  Probe.Add(FilePath, 1);
  Probe.Add(FilePath, 1);
  Files := Probe;
  Options.MaxFiles := 1000;
  Snapshot := TPortappixTrace.TakeSnapshot(Options, Files, Keys, Noise);
  Check(Snapshot.FileCount = 1, 'Duplicate file reports collapse into one entry');
end;

procedure TestTraceSuggestions(const ARoot: string);
var
  Folders: TPortappixKnownFolders;
  DataDir: string;
  AppDir: string;
  Diff: TPortappixDiff;
  Suggestions: TArray<TPortappixSuggestion>;
begin
  DataDir := TPath.Combine(ARoot, 'Data\demo');
  AppDir := TPath.Combine(ARoot, 'Apps\demo');

  Folders := Default(TPortappixKnownFolders);
  Folders.AppData := TPath.Combine(ARoot, 'AppData');
  Folders.LocalAppData := TPath.Combine(ARoot, 'LocalAppData');
  Folders.Temp := TPath.Combine(Folders.LocalAppData, 'Temp');
  Folders.ProgramData := TPath.Combine(ARoot, 'ProgramData');
  Folders.Profile := TPath.Combine(ARoot, 'Users\demo');
  Folders.Documents := TPath.Combine(Folders.Profile, 'Documents');
  Folders.Desktop := TPath.Combine(Folders.Profile, 'Desktop');
  Folders.PublicFolder := TPath.Combine(ARoot, 'Public');

  // Full diff: AppData write, ProgramData write, Documents write, a portable
  // Data write (must be ignored) and registry keys.
  Diff := Default(TPortappixDiff);
  SetLength(Diff.Files, 4);
  Diff.Files[0].Kind := dkAdded;
  Diff.Files[0].Path := TPath.Combine(Folders.AppData, 'Vendor\App\settings.ini');
  Diff.Files[1].Kind := dkAdded;
  Diff.Files[1].Path := TPath.Combine(Folders.ProgramData, 'Vendor\cache.dat');
  Diff.Files[2].Kind := dkAdded;
  Diff.Files[2].Path := TPath.Combine(Folders.Documents, 'notes.txt');
  Diff.Files[3].Kind := dkAdded;
  Diff.Files[3].Path := TPath.Combine(DataDir, 'already_portable.txt');
  SetLength(Diff.Keys, 3);
  Diff.Keys[0].Kind := dkAdded;
  Diff.Keys[0].Path := 'HKCU\Software\Vendor\App\Settings';
  Diff.Keys[1].Kind := dkModified;
  Diff.Keys[1].Path := 'HKCU\Software\Vendor\App\MRU';
  Diff.Keys[2].Kind := dkAdded;
  Diff.Keys[2].Path := 'HKLM\Software\Vendor\App';

  Suggestions := TPortappixTrace.SuggestFromDiff(Diff, Folders, DataDir,
    AppDir, TPath.Combine(ARoot, 'LauncherRoot'));

  Check(FindSuggestion(Suggestions, skEnvironment, 'APPDATA') >= 0,
    'Suggestions propose an APPDATA override for %APPDATA% writes');
  Check(FindSuggestion(Suggestions, skEnvironment, 'LOCALAPPDATA') < 0,
    'Suggestions skip the LOCALAPPDATA override when it was not touched');
  Check(FindSuggestion(Suggestions, skJunction, '%PROGRAMDATA%\Vendor') >= 0,
    'Suggestions propose a junction for %PROGRAMDATA% writes');
  Check(FindSuggestion(Suggestions, skRegistry, 'HKCU\Software\Vendor\App') >= 0,
    'Suggestions collapse registry keys to the common vendor\app prefix');
  Check(FindSuggestion(Suggestions, skManualReview, 'HKLM\Software\Vendor\App') >= 0,
    'Suggestions flag keys outside HKCU\Software for manual review');
  Check(Length(Suggestions) > 0, 'Suggestions were produced');

  var HasWarning := False;
  for var Suggestion in Suggestions do
    if Suggestion.Kind = skWarning then
      HasWarning := True;
  Check(HasWarning, 'Suggestions warn about protected user folders');

  for var Suggestion in Suggestions do
    Check(not ContainsStr(Suggestion.Message, 'already_portable'),
      'Suggestions ignore writes inside the portable data folder');

  // Registry keys too shallow for policy get a manual review entry.
  Diff := Default(TPortappixDiff);
  SetLength(Diff.Keys, 1);
  Diff.Keys[0].Kind := dkAdded;
  Diff.Keys[0].Path := 'HKCU\Software\Vendor';
  Suggestions := TPortappixTrace.SuggestFromDiff(Diff, Folders, DataDir,
    AppDir, '');
  Check(FindSuggestion(Suggestions, skManualReview, 'HKCU\Software\Vendor') >= 0,
    'Registry prefixes shallower than vendor\app need manual review');

  // Temp writes propose TEMP and TMP overrides.
  Suggestions := TPortappixTrace.SuggestFromDiff(
    OneAddedFileDiff(TPath.Combine(Folders.Temp, 'scratch.tmp')),
    Folders, DataDir, AppDir, '');
  Check(FindSuggestion(Suggestions, skEnvironment, 'TEMP') >= 0,
    'Suggestions propose a TEMP override for temp writes');
  Check(FindSuggestion(Suggestions, skEnvironment, 'TMP') >= 0,
    'Suggestions propose a TMP override for temp writes');
end;

procedure TestTraceReports(const ARoot: string);
var
  ManifestPath: string;
  Runner: TPortappixTraceRunner;
  Before: TPortappixSnapshot;
  After: TPortappixSnapshot;
  Suggestions: TArray<TPortappixSuggestion>;
  TraceResult: TPortappixTraceResult;
  Json: TJSONValue;
  ReportText: string;
  SuggestedText: string;
begin
  ManifestPath := WriteTextFile(
    TPath.Combine(TPath.Combine(ARoot, 'Apps\demo'), 'app.json'),
    '{"name":"Demo","exe":"demo.exe"}');

  Runner := TPortappixTraceRunner.Create(ARoot, ManifestPath);
  try
    Before := Default(TPortappixSnapshot);
    After := Default(TPortappixSnapshot);

    SetLength(After.Files, 2);
    // Outside every folder Portappix can redirect (never created on disk;
    // the suggestion engine only compares paths): a redirect warning.
    After.Files[0].Path := TPath.Combine(
      TPath.GetPathRoot(ARoot), 'portappix-trace-tests', 'created.txt');
    After.Files[0].Size := 5;
    // Documents: protected folder warning.
    After.Files[1].Path := TPath.Combine(
      GetEnvironmentVariable('USERPROFILE'), 'Documents', 'trace-tests\notes.txt');
    After.Files[1].Size := 9;

    SetLength(After.Keys, 1);
    After.Keys[0].Path := 'HKCU\Software\Vendor\App';

    TraceResult := Runner.WriteReports(TPath.Combine(ARoot, 'Trace\out'),
      Before, After, 3, Suggestions);

    Check(TFile.Exists(TraceResult.ReportJsonFile), 'Trace writes report.json');
    Check(TFile.Exists(TraceResult.ReportMarkdownFile), 'Trace writes report.md');
    Check(TFile.Exists(TraceResult.SuggestedManifestFile),
      'Trace writes suggested_app.json');
    Check(TraceResult.FilesAdded = 2, 'Trace result counts added files');
    Check(TraceResult.KeysAdded = 1, 'Trace result counts added keys');
    Check(TraceResult.AppExitCode = 3, 'Trace result records the app exit code');
    Check(TraceResult.SuggestionCount = 1,
      'Trace result counts the registry suggestion');
    Check(TraceResult.WarningCount = 2, 'Trace result counts the warnings');

    Json := TJSONObject.ParseJSONValue(
      TFile.ReadAllText(TraceResult.ReportJsonFile, TEncoding.UTF8));
    try
      Check(Json is TJSONObject, 'report.json parses as JSON');
      Check(TJSONObject(Json).GetValue('files') <> nil,
        'report.json has a files section');
      Check(TJSONObject(Json).GetValue('registry') <> nil,
        'report.json has a registry section');
      Check(TJSONObject(Json).GetValue('suggestions') <> nil,
        'report.json has a suggestions section');
      Check(TJSONObject(Json).GetValue('snapshot') <> nil,
        'report.json has a snapshot section');
    finally
      Json.Free;
    end;

    ReportText := TFile.ReadAllText(TraceResult.ReportMarkdownFile, TEncoding.UTF8);
    Check(ContainsStr(ReportText, '## Files added'), 'report.md lists added files');
    Check(ContainsStr(ReportText, '## Suggestions'), 'report.md lists suggestions');

    SuggestedText := TFile.ReadAllText(TraceResult.SuggestedManifestFile, TEncoding.UTF8);
    Check(ContainsStr(SuggestedText, '"id": "demo"'),
      'suggested_app.json keeps the app id');
    Check(ContainsStr(SuggestedText, 'HKCU\\Software\\Vendor\\App'),
      'suggested_app.json contains the registry suggestion');
    Check(ContainsStr(SuggestedText, '"_warnings"'),
      'suggested_app.json carries warnings for manual review');
  finally
    Runner.Free;
  end;
end;

{ Update tests }

procedure TestSemVer;
begin
  Check(TPortappixSemVer.CompareText('1.0.0', '1.0.0') = 0, 'SemVer equal versions compare as equal');
  Check(TPortappixSemVer.CompareText('1.0.0', '1.0.1') < 0, 'SemVer patch increments sort upward');
  Check(TPortappixSemVer.CompareText('1.9.0', '1.10.0') < 0, 'SemVer minor numbers compare numerically');
  Check(TPortappixSemVer.CompareText('1.0.0', '2.0.0') < 0, 'SemVer major numbers sort upward');
  Check(TPortappixSemVer.CompareText('1.0', '1.0.0') = 0, 'SemVer missing numbers default to zero');
  Check(TPortappixSemVer.CompareText('1.0.0-alpha', '1.0.0') < 0,
    'SemVer pre-releases sort before the stable release');
  Check(TPortappixSemVer.CompareText('1.0.0-alpha', '1.0.0-beta') < 0,
    'SemVer alphanumeric pre-release identifiers sort lexically');
  Check(TPortappixSemVer.CompareText('1.0.0-alpha', '1.0.0-alpha.1') < 0,
    'SemVer longer pre-release lists sort after their prefixes');
  Check(TPortappixSemVer.CompareText('1.0.0-2', '1.0.0-10') < 0,
    'SemVer numeric pre-release identifiers compare numerically');
  Check(TPortappixSemVer.CompareText('1.0.0+build5', '1.0.0') = 0,
    'SemVer build metadata is ignored for ordering');

  var Parsed := TPortappixSemVer.Parse('1.2.3-beta.4');
  Check((Parsed.Major = 1) and (Parsed.Minor = 2) and (Parsed.Patch = 3) and
    (Parsed.PreRelease = 'beta.4'), 'SemVer parses core numbers and pre-release');

  var Broken: TPortappixSemVer;
  Check(not TPortappixSemVer.TryParse('not-a-version', Broken),
    'SemVer rejects non-numeric versions');
  Check(not TPortappixSemVer.TryParse('v1.9.0', Broken),
    'SemVer rejects a leading v prefix');
  Check(not TPortappixSemVer.TryParse('1.2.3.4', Broken),
    'SemVer rejects more than three core numbers');
end;

procedure TestDataVersion(const ARoot: string);
var
  DataDir: string;
begin
  DataDir := TPath.Combine(ARoot, 'Data\demo');
  Check(TPortappixManifest.ReadDataVersion(DataDir) = 0,
    'Data version defaults to 0 when no marker exists');

  TPortappixManifest.WriteDataVersion(DataDir, 'demo', 3);
  Check(TPortappixManifest.ReadDataVersion(DataDir) = 3,
    'Data version round-trips through data_version.json');

  TPortappixManifest.WriteDataVersion(DataDir, 'demo', 0);
  Check(TPortappixManifest.ReadDataVersion(DataDir) = 3,
    'A dataVersion of 0 writes nothing and keeps the previous marker');

  var ManifestPath := WriteTextFile(TPath.Combine(ARoot, 'm1\app.json'),
    '{"exe":"x.exe","dataVersion":7}');
  var Manifest := TPortappixManifest.LoadFromFile(ManifestPath);
  try
    Check(Manifest.DataVersion = 7, 'Manifest parses dataVersion');
  finally
    Manifest.Free;
  end;

  ManifestPath := WriteTextFile(TPath.Combine(ARoot, 'm2\app.json'), '{"exe":"x.exe"}');
  Manifest := TPortappixManifest.LoadFromFile(ManifestPath);
  try
    Check(Manifest.DataVersion = 0, 'Manifest dataVersion defaults to 0');
  finally
    Manifest.Free;
  end;

  WriteTextFile(TPath.Combine(ARoot, 'm3\app.json'), '{"exe":"x.exe","dataVersion":-1}');
  ExpectException(
    procedure
    begin
      TPortappixManifest.LoadFromFile(TPath.Combine(ARoot, 'm3\app.json'));
    end,
    'Manifest rejects negative dataVersion');
end;

procedure TestPendingUpdatesAndRollback(const ARoot: string);
var
  Manager: TPortappixPackageManager;
  App: TCatalogApp;
begin
  Manager := TPortappixPackageManager.Create(ARoot);
  try
    Check(Length(Manager.PendingUpdateIds) = 0, 'Pending updates start empty');

    App := TCatalogApp.Create;
    try
      App.Id := 'demo';
      App.Version := '2.0';
      App.Url := 'https://example.com/demo.zip';
      App.Sha256 := StringOfChar('a', 64);
      App.Size := 10;
      Manager.QueueUpdate(App);
      App.Version := '2.1';
      Manager.QueueUpdate(App);   // same id: refreshed, not duplicated
      Check(Length(Manager.PendingUpdateIds) = 1,
        'Queueing the same app twice refreshes one entry');
      Check(Manager.HasPendingUpdate('demo'), 'HasPendingUpdate finds queued entries');
      Check(not Manager.HasPendingUpdate('other'), 'HasPendingUpdate ignores other apps');

      var Second := TCatalogApp.Create;
      try
        Second.Id := 'other';
        Second.Version := '1.0';
        Second.Url := 'https://example.com/other.zip';
        Second.Sha256 := StringOfChar('b', 64);
        Second.Size := 5;
        Manager.QueueUpdate(Second);
        Check(Length(Manager.PendingUpdateIds) = 2, 'Two apps can be queued');
      finally
        Second.Free;
      end;
    finally
      App.Free;
    end;

    // Entries survive a new manager instance (disk persistence).
    var Reopened := TPortappixPackageManager.Create(ARoot);
    try
      Check(Length(Reopened.PendingUpdateIds) = 2,
        'Pending updates persist on disk');
      Reopened.RemovePendingUpdate('demo');
      Check((not Reopened.HasPendingUpdate('demo')) and Reopened.HasPendingUpdate('other'),
        'RemovePendingUpdate deletes only the target entry');
    finally
      Reopened.Free;
    end;

    // A corrupt queue file behaves like an empty queue.
    ForceDirectories(TPath.Combine(ARoot, 'Cache'));
    TFile.WriteAllText(TPath.Combine(TPath.Combine(ARoot, 'Cache'), 'pending_updates.json'),
      '{ not json', TEncoding.UTF8);
    Check(Length(Manager.PendingUpdateIds) = 0,
      'A corrupt pending_updates.json is treated as an empty queue');
  finally
    Manager.Free;
  end;
end;

procedure TestRollback(const ARoot: string);
var
  Manager: TPortappixPackageManager;
begin
  Manager := TPortappixPackageManager.Create(ARoot);
  try
    WriteTextFile(TPath.Combine(ARoot, 'Apps\demo\app.json'), '{"exe":"new.exe","version":"2.0"}');
    WriteTextFile(TPath.Combine(ARoot, 'Apps\demo.prev\app.json'), '{"exe":"old.exe","version":"1.0"}');
    Manager.RollbackApp('demo');
    Check(ContainsStr(TFile.ReadAllText(TPath.Combine(ARoot, 'Apps\demo\app.json')), 'old.exe'),
      'Rollback restores Apps\<id>.prev into place');
    Check(not TDirectory.Exists(TPath.Combine(ARoot, 'Apps\demo.prev')),
      'Rollback consumes the .prev folder');
    Check(not TDirectory.Exists(TPath.Combine(ARoot, 'Apps\demo.stale')),
      'Rollback removes the stale folder');

    ExpectException(
      procedure
      begin
        Manager.RollbackApp('demo');
      end,
      'Rollback without a .prev folder is refused');

    // Downgrade protection: newer installed version refuses an older package.
    WriteTextFile(TPath.Combine(ARoot, 'Apps\demo\app.json'),
      '{"exe":"new.exe","version":"2.0.0"}');
    var IncomingPath := WriteTextFile(TPath.Combine(ARoot, 'incoming\app.json'),
      '{"id":"demo","exe":"old.exe","version":"1.9.0"}');
    var Incoming := TPortappixManifest.LoadFromFile(IncomingPath);
    try
      ExpectException(
        procedure
        begin
          Manager.ValidateUpdateAllowed(Incoming);
        end,
        'Updates refuse version downgrades');
    finally
      Incoming.Free;
    end;

    IncomingPath := WriteTextFile(TPath.Combine(ARoot, 'incoming2\app.json'),
      '{"id":"demo","exe":"newer.exe","version":"2.0.1"}');
    Incoming := TPortappixManifest.LoadFromFile(IncomingPath);
    try
      Manager.ValidateUpdateAllowed(Incoming);
      Check(True, 'Updates allow version upgrades');
    finally
      Incoming.Free;
    end;

    // Data downgrade protection.
    WriteTextFile(TPath.Combine(ARoot, 'Data\demo\data_version.json'),
      '{"dataVersion":3}');
    IncomingPath := WriteTextFile(TPath.Combine(ARoot, 'incoming3\app.json'),
      '{"id":"demo","exe":"newer.exe","version":"2.1.0","dataVersion":2}');
    Incoming := TPortappixManifest.LoadFromFile(IncomingPath);
    try
      ExpectException(
        procedure
        begin
          Manager.ValidateUpdateAllowed(Incoming);
        end,
        'Updates refuse data-version downgrades');
    finally
      Incoming.Free;
    end;

    IncomingPath := WriteTextFile(TPath.Combine(ARoot, 'incoming4\app.json'),
      '{"id":"demo","exe":"newer.exe","version":"2.1.0","dataVersion":4}');
    Incoming := TPortappixManifest.LoadFromFile(IncomingPath);
    try
      Manager.ValidateUpdateAllowed(Incoming);
      Check(True, 'Updates allow data-version upgrades');
    finally
      Incoming.Free;
    end;
  finally
    Manager.Free;
  end;
end;

procedure TestSettings(const ARoot: string);
var
  Settings: TPortappixSettings;
begin
  Settings := TPortappixSettings.Create(ARoot);
  try
    Settings.Load;
    Check(Settings.UpdateUrl = '', 'Settings default to no update URL');
    Check(not Settings.AutoCheckUpdates, 'Settings default to no automatic update checks');
    Check(Settings.AutoApplyPendingUpdates, 'Settings default to applying pending updates');

    Settings.UpdateUrl := 'https://example.com/releases.json';
    Settings.AutoCheckUpdates := True;
    Settings.AutoApplyPendingUpdates := False;
    Settings.Save;

    var Reopened := TPortappixSettings.Create(ARoot);
    try
      Reopened.Load;
      Check(Reopened.UpdateUrl = 'https://example.com/releases.json',
        'Settings round-trip the update URL');
      Check(Reopened.AutoCheckUpdates, 'Settings round-trip autoCheckUpdates');
      Check(not Reopened.AutoApplyPendingUpdates, 'Settings round-trip autoApplyPendingUpdates');
    finally
      Reopened.Free;
    end;

    TFile.WriteAllText(TPath.Combine(TPath.Combine(ARoot, 'Cache'), 'settings.json'),
      '{ corrupt', TEncoding.UTF8);
    Settings.Load;
    Check((Settings.UpdateUrl = '') and Settings.AutoApplyPendingUpdates,
      'A corrupt settings file behaves like defaults');
  finally
    Settings.Free;
  end;
end;

function ReleasesJsonFor(const AVersion, ASha256: string; ASize: Int64): string;
begin
  Result := Format('{"schema":1,"channel":"stable","version":"%s",' +
    '"url":"https://example.com/portappix.zip","sha256":"%s","size":%d}',
    [AVersion, ASha256, ASize]);
end;

procedure BuildLauncherZip(const AZipPath, ANewExeContent: string);
var
  TempFile: string;
  Zip: TZipFile;
begin
  TempFile := AZipPath + '.payload';
  TFile.WriteAllText(TempFile, ANewExeContent, TEncoding.UTF8);
  Zip := TZipFile.Create;
  try
    Zip.Open(AZipPath, TZipMode.zmWrite);
    Zip.Add(TempFile, 'Launcher.exe');
    Zip.Add(TempFile, 'readme.txt');
    Zip.Close;
  finally
    Zip.Free;
  end;
  TFile.Delete(TempFile);
end;

procedure TestUpdateManager(const ARoot: string);
var
  Manager: TPortappixUpdateManager;
  ZipPath: string;
  Release: TPortappixRelease;
  FailedFiles: TArray<string>;
begin
  // releases.json parsing.
  Release := ParseReleasesJson(ReleasesJsonFor('1.1.0', StringOfChar('a', 64), 5));
  try
    Check((Release.Version = '1.1.0') and (Release.Channel = 'stable') and
      (Release.Size = 5), 'releases.json parses into a release record');
  finally
    Release.Free;
  end;

  ExpectException(
    procedure
    begin
      ParseReleasesJson(ReleasesJsonFor('not-a-version', StringOfChar('a', 64), 5));
    end,
    'releases.json rejects non-semantic versions');

  ExpectException(
    procedure
    begin
      ParseReleasesJson('{"schema":9,"channel":"stable","version":"1.0",' +
        '"url":"https://example.com/x.zip","sha256":"' + StringOfChar('a', 64) + '"}');
    end,
    'releases.json rejects unknown schema versions');

  ExpectException(
    procedure
    begin
      ParseReleasesJson(ReleasesJsonFor('1.0', 'zz', 5));
    end,
    'releases.json rejects invalid sha256 values');

  // Full swap/confirm/rollback flow against a local zip (no network, no spawn).
  WriteTextFile(TPath.Combine(ARoot, 'Launcher.exe'), 'old-launcher');
  Manager := TPortappixUpdateManager.Create(ARoot);
  try
    Check(Manager.InstalledVersion = '0.0.0',
      'Installed version defaults to 0.0.0');
    Check(not Manager.NeedsRollbackOffer,
      'No rollback offer before any update');

    ZipPath := TPath.Combine(TPath.Combine(ARoot, 'Cache'), 'update.zip');
    BuildLauncherZip(ZipPath, 'new-launcher');
    Release := ParseReleasesJson(ReleasesJsonFor('1.1.0',
      Sha256File(ZipPath), TFile.GetSize(ZipPath)));
    try
      Check(Manager.IsUpdateAvailable(Release), 'A newer release is an update');

      // A wrong hash is refused and the package is deleted.
      var BadRelease := ParseReleasesJson(
        ReleasesJsonFor('1.2.0', StringOfChar('c', 64), 0));
      try
        ExpectException(
          procedure
          begin
            Manager.PrepareUpdate(ZipPath, BadRelease, False);
          end,
          'PrepareUpdate refuses a package with a wrong sha256');
        Check(not TFile.Exists(ZipPath),
          'PrepareUpdate deletes the rejected package');
      finally
        BadRelease.Free;
      end;

      BuildLauncherZip(ZipPath, 'new-launcher');
      Manager.PrepareUpdate(ZipPath, Release, False);
      Check(TFile.ReadAllText(TPath.Combine(ARoot, 'Launcher.exe')) = 'new-launcher',
        'PrepareUpdate puts the new launcher in place');
      Check(TFile.ReadAllText(TPath.Combine(ARoot, 'Launcher.exe.old')) = 'old-launcher',
        'PrepareUpdate keeps the old launcher as Launcher.exe.old');
      Check(TFile.ReadAllText(TPath.Combine(ARoot, 'readme.txt')) = 'new-launcher',
        'PrepareUpdate copies extra release files into the root');
      Check(TFile.Exists(TPath.Combine(TPath.Combine(ARoot, 'Cache'), 'update_pending.json')),
        'PrepareUpdate writes update_pending.json');
      Check(Manager.NeedsRollbackOffer,
        'NeedsRollbackOffer is true for an unconfirmed update');
      Check(Manager.PendingUpdateVersion = '1.1.0',
        'PendingUpdateVersion reads the pending update');

      Manager.ConfirmUpdate;
      Check(TFile.Exists(TPath.Combine(TPath.Combine(ARoot, 'Cache'), 'update_ok')),
        'ConfirmUpdate writes the update_ok marker');
      Check(Manager.InstalledVersion = '1.1.0',
        'ConfirmUpdate records the new installed version');
      Check(not Manager.NeedsRollbackOffer,
        'NeedsRollbackOffer is false once the update is confirmed');

      Check(Manager.RollbackToOldLauncher(False),
        'RollbackToOldLauncher reports success');
      Check(TFile.ReadAllText(TPath.Combine(ARoot, 'Launcher.exe')) = 'old-launcher',
        'Rollback restores the previous launcher');
      Check(not TFile.Exists(TPath.Combine(ARoot, 'Launcher.exe.old')),
        'Rollback consumes Launcher.exe.old');
      FailedFiles := TDirectory.GetFiles(ARoot, 'Launcher.exe.failed_*');
      Check(Length(FailedFiles) = 1,
        'Rollback keeps the failed build next to the launcher');
    finally
      Release.Free;
    end;

    ExpectException(
      procedure
      begin
        Manager.RollbackToOldLauncher(False);
      end,
      'Rollback without Launcher.exe.old is refused');
  finally
    Manager.Free;
  end;
end;

var
  Root: string;
begin
  Writeln('Portappix engine tests');
  Writeln('----------------------');
  Root := MakeTempRoot;
  try
    TestTokenExpansion;
    TestManifestParsing(Root);
    TestPolicy;
    TestCatalog(Root);
    TestZipExtraction(Root);
    TestHashing;
    TestJournal(Root);
    TestRegistryOrdering(Root);
    TestTraceNoiseFilter;
    TestTraceSnapshotAndDiff(Root);
    TestTraceSnapshotCaps(Root);
    TestTraceSuggestions(Root);
    TestTraceReports(Root);
    TestSemVer;
    TestDataVersion(Root);
    TestPendingUpdatesAndRollback(Root);
    TestRollback(Root);
    TestSettings(Root);
    TestUpdateManager(Root);
  finally
    try
      TDirectory.Delete(Root, True);
    except
    end;
  end;

  Writeln;
  Writeln(Format('Result: %d passed, %d failed', [Passed, Failed]));
  if Failed > 0 then
    ExitCode := 1
  else
    ExitCode := 0;
end.
