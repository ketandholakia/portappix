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
  Portappix.State;

type
  TFakeRegistryOps = class(TInterfacedObject, IPortappixRegistryOps)
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
    Check(ContainsStr('demo', TFile.ReadAllText(StateFile)),
      'Journal records the active app');

    Journal.RemoveActiveApp('demo');
    Check(not ContainsStr('"demo"', TFile.ReadAllText(StateFile)),
      'Journal removes the active app');

    Journal.AddActiveApp('demo', nil, nil);
    Journal.RecoverPendingCleanups;
    Check(not ContainsStr('"demo"', TFile.ReadAllText(StateFile)),
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
  Fake: TFakeRegistryOps;
  FailingFake: TFakeRegistryOps;
  DataDir: string;
  Keys: TArray<string>;
  Order: string;
begin
  SetLength(Keys, 1);
  Keys[0] := 'HKCU\Software\Vendor\Demo';
  DataDir := TPath.Combine(ARoot, 'Data\demo');
  ForceDirectories(DataDir);

  Fake := TFakeRegistryOps.Create(True);
  try
    TPortableAppRunner.PerformCleanup('demo', Keys, nil, DataDir, nil, Fake);
    Order := Fake.CallOrder;
    Check((Pos('export', Order) > 0) and (Pos('delete', Order) > 0) and
      (Pos('export', Order) < Pos('delete', Order)),
      'PerformCleanup exports registry keys before deleting them');
  finally
    Fake.Free;
  end;

  FailingFake := TFakeRegistryOps.Create(False);
  try
    TPortableAppRunner.PerformCleanup('demo', Keys, nil, DataDir, nil, FailingFake);
    Check(Pos('delete', FailingFake.CallOrder) = 0,
      'PerformCleanup never deletes keys when the export fails');
  finally
    FailingFake.Free;
  end;
end;

constructor TFakeRegistryOps.Create(const AExportSucceeds: Boolean);
begin
  inherited Create;
  FExportSucceeds := AExportSucceeds;
  FCalls := TStringList.Create;
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
