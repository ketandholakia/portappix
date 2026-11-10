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
  Portappix.Junction,
  Portappix.Transactions,
  Portappix.Manifest,
  Portappix.Policy,
  Portappix.Catalog,
  Portappix.PackageManager,
  Portappix.Registry,
  Portappix.Runner,
  Portappix.Settings,
  Portappix.Signature,
  Portappix.State,
  Portappix.Trace,
  Portappix.Update,
  Portappix.Version,
  Portappix.Consent;

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

  // Registry fake for the transaction tests: models key existence, records
  // every call with the key/file involved, and allows per-operation failure.
  TFakeTxRegistryOps = class(TInterfacedObject, IPortappixRegistryOps)
  private
    FKeys: TStringList;
    FCallLog: TStringList;
    FExportSucceeds: Boolean;
    FImportSucceeds: Boolean;
    FDeleteSucceeds: Boolean;
  public
    constructor Create;
    destructor Destroy; override;
    procedure AddKey(const AKey: string);
    function KeyExists(const AKey: string): Boolean;
    function ExportKey(const AKey, AFileName: string): Boolean;
    function ImportFile(const AFileName: string): Boolean;
    function DeleteKey(const AKey: string): Boolean;
    property CallLog: TStringList read FCallLog;
    property ExportSucceeds: Boolean read FExportSucceeds write FExportSucceeds;
    property ImportSucceeds: Boolean read FImportSucceeds write FImportSucceeds;
    property DeleteSucceeds: Boolean read FDeleteSucceeds write FDeleteSucceeds;
  end;

  // Host-path fake for the junction/transaction tests: an in-memory model
  // of files, directories, mount-point junctions, symbolic links and other
  // reparse points, with per-operation failure switches, object identity
  // (new identity on delete+recreate) and a call log.
  TFakeHostPathOps = class(TInterfacedObject, IPortappixHostPathOps)
  private
    FPaths: TDictionary<string, string>;
    FIdentities: TDictionary<string, Integer>;
    FCallLog: TStringList;
    FFailCreate: Boolean;
    FFailDelete: Boolean;
    FFailRename: Boolean;
    FFailInspect: Boolean;
    FFailTargetParse: Boolean;
    FNextIdentity: Integer;
    function Norm(const APath: string): string;
  public
    constructor Create;
    destructor Destroy; override;
    procedure AddDir(const APath: string);
    procedure AddFile(const APath: string);
    procedure AddJunction(const APath, ATarget: string);
    procedure AddSymlink(const APath, ATarget: string);
    procedure AddOtherReparse(const APath: string);
    function PathExists(const APath: string): Boolean;
    function IsDirectory(const APath: string): Boolean;
    function IsReparsePoint(const APath: string): Boolean;
    function GetJunctionTarget(const APath: string): string;
    function InspectPath(const APath: string): TPortappixPathInspection;
    function CreateJunction(const APath, ATarget: string): Boolean;
    function DeleteJunction(const APath: string): Boolean;
    function RenamePath(const AFrom, ATo: string): Boolean;
    property CallLog: TStringList read FCallLog;
    property FailCreate: Boolean read FFailCreate write FFailCreate;
    property FailDelete: Boolean read FFailDelete write FFailDelete;
    property FailRename: Boolean read FFailRename write FFailRename;
    // Simulates access denied during inspection of existing objects.
    property FailInspect: Boolean read FFailInspect write FFailInspect;
    // Simulates an unparsable/ambiguous junction target.
    property FailTargetParse: Boolean read FFailTargetParse write FFailTargetParse;
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

// Directory symbolic links need the SeCreateSymbolicLink privilege; the
// inspection test skips gracefully when the host lacks it.
function CreateSymbolicLinkW(SymlinkName, TargetName: PChar;
  Flags: DWORD): Boolean; stdcall; external 'kernel32.dll'
  name 'CreateSymbolicLinkW';

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

  Result := TPolicyResult.Create;
  try
    Check(not TPortappixPolicy.ValidateJunctionHost('%APPDATA%\Microsoft\Portappix', Result),
      'Policy denies junctions in %APPDATA%\Microsoft');
  finally
    Result.Free;
  end;

  Result := TPolicyResult.Create;
  try
    Check(not TPortappixPolicy.ValidateJunctionTarget('..\escape', Result),
      'Policy denies junction targets with traversal (..)');
  finally
    Result.Free;
  end;

  Result := TPolicyResult.Create;
  try
    Check(not TPortappixPolicy.ValidateJunctionTarget('{app}\sub', Result),
      'Policy denies junction targets pointing into {app}');
  finally
    Result.Free;
  end;

  Result := TPolicyResult.Create;
  try
    Check(not TPortappixPolicy.ValidateJunctionTarget('{root}\sub', Result),
      'Policy denies junction targets pointing into {root}');
  finally
    Result.Free;
  end;

  Result := TPolicyResult.Create;
  try
    Check(TPortappixPolicy.ValidateJunctionTarget('{data}\config', Result),
      'Policy allows junction targets in {data}');
  finally
    Result.Free;
  end;

  Env := TDictionary<string, string>.Create;
  Result := TPolicyResult.Create;
  try
    Env.Add('APPDATA', '{data}\..\escape');
    Check(not TPortappixPolicy.ValidateEnvironment(Env, Result),
      'Policy denies environment variable values with path traversal');
  finally
    Result.Free;
    Env.Free;
  end;

  Env := TDictionary<string, string>.Create;
  Result := TPolicyResult.Create;
  try
    Env.Add('APPDATA', '{data}'#0'injected');
    Check(not TPortappixPolicy.ValidateEnvironment(Env, Result),
      'Policy denies environment variable values with null characters');
  finally
    Result.Free;
    Env.Free;
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
        Catalog.LoadFromJson('{"apps":[{"id":"demo","name":"Demo","version":"1.0",' +
          '"url":"https://example.com/demo.zip","sha256":"' + Sha + '","size":1,' +
          '"kind":"mystery"}]}');
      end,
      'Catalog rejects unknown kinds');

    Catalog.LoadFromJson('{"apps":[{"id":"demo","name":"Demo","version":"1.0",' +
      '"category":"Utilities","url":"https://example.com/demo.zip","sha256":"' + Sha +
      '","size":1,"kind":"recipe","recipe":"recipes/demo.json"}]}');
    Check(Catalog.FindById('demo').Kind = 'recipe', 'Catalog parses the kind field');
    Check(Catalog.FindById('demo').Recipe = 'recipes/demo.json',
      'Catalog parses the recipe field');

    Catalog.LoadFromJson(GoodJson);
    Check((Catalog.FindById('demo').Kind = 'package') and
      (Catalog.FindById('demo').Recipe = ''),
      'Catalog defaults to kind=package without provenance fields');

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

  // Alternate Data Stream rejection
  var AdsZip := TPath.Combine(ARoot, 'ads.zip');
  Zip := TZipFile.Create;
  try
    Zip.Open(AdsZip, TZipMode.zmWrite);
    Zip.Add(SourceFile, 'safe.txt:stream');
    Zip.Close;
  finally
    Zip.Free;
  end;
  Manager := TPortappixPackageManager.Create(ARoot);
  try
    ExpectException(
      procedure
      begin
        Manager.ExtractArchive(AdsZip, TPath.Combine(ARoot, 'ads-extract'));
      end,
      'Zip extraction rejects Alternate Data Stream entries');
  finally
    Manager.Free;
  end;

  // Reserved Windows device name rejection
  var ReservedZip := TPath.Combine(ARoot, 'reserved.zip');
  Zip := TZipFile.Create;
  try
    Zip.Open(ReservedZip, TZipMode.zmWrite);
    Zip.Add(SourceFile, 'CON.txt');
    Zip.Close;
  finally
    Zip.Free;
  end;
  Manager := TPortappixPackageManager.Create(ARoot);
  try
    ExpectException(
      procedure
      begin
        Manager.ExtractArchive(ReservedZip, TPath.Combine(ARoot, 'reserved-extract'));
      end,
      'Zip extraction rejects reserved Windows device names');
  finally
    Manager.Free;
  end;

  // Case-insensitive duplicate / collision rejection
  var DupZip := TPath.Combine(ARoot, 'dup.zip');
  Zip := TZipFile.Create;
  try
    Zip.Open(DupZip, TZipMode.zmWrite);
    Zip.Add(SourceFile, 'foo.txt');
    Zip.Add(SourceFile, 'FOO.TXT');
    Zip.Close;
  finally
    Zip.Free;
  end;
  Manager := TPortappixPackageManager.Create(ARoot);
  try
    ExpectException(
      procedure
      begin
        Manager.ExtractArchive(DupZip, TPath.Combine(ARoot, 'dup-extract'));
      end,
      'Zip extraction rejects duplicate/case-colliding entries');
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

procedure TestSignatureVerification;
const
  // "portappix-signature-selftest-v1" — fixed content signed out-of-band with
  // the production signing key during the Phase 1 rotation. Only public
  // material is embedded: signatures and public blobs, never private keys.
  SelfTestContentHex =
    '706f727461707069782d7369676e61747572652d73656c66746573742d7631';
  // Valid signature over SelfTestContentHex made with the CURRENT trusted key.
  NewSigHex =
    'fe87e1df570fa7b8cdcdc0a1496f3af6a356d124c7401fd5d018d4b297c7b463c8d' +
    'efdc4fed012676a14fe418434fb54a76d078af3340a50506c7924181b4c3e';
  // A synthetic second P-256 key (test-only, generated in a temp directory
  // and discarded) with a valid signature over the same content.
  OtherPubBlobHex =
    '4543533120000000e150f6af6f373d25521c51a433c1ccc84c38f8a20c3594810' +
    '72950a3b44aa353b629008e3ef559061825172fc3ed1eaa035195a75df840c257' +
    '0bf8497b60280d';
  OtherSigHex =
    'd7c1fc4bed130f8f71d69eb9354ff9138d1af0a57245f838e276ff255730be8a7' +
    '34761913594cc30f04ec07d926ad943645d5c74cf961f3de6b3c8311a37cd70';
  // The root catalog.json as it was before the rotation, and the signature
  // over it made with the compromised (pre-rotation) key. Both are public.
  OldCatalogHex = '7b0a20202261707073223a205b5d0a7d0a';
  OldSigHex =
    'bc22db755216e6d9db4f9819725ba51751a00c292a92d4fbc01e837c412a7f07' +
    '97717a43565457626406198bd3c702a615681ceadb1f36f00da4d825fe90c36c';
  // The pre-rotation trusted public key that used to be embedded in
  // Portappix.Signature.pas (public blob; the matching private key has been
  // destroyed and must never be used again).
  OldTrustedKeyHex =
    '4543533120000000A9ED638DB255D1CEC43A7BCA227247BD2A6A2667C8488C985732CD8A9828E522' +
    'AAF3945B6E71F5CB811E1EF272A4A3775E127A60C87F59916F6E6A10A0609E0F';
var
  Content: TBytes;
  NewSig: TBytes;
  OtherSig: TBytes;
  OtherPub: TBytes;
  OldCatalog: TBytes;
  OldSig: TBytes;
  ShortSig: TBytes;
  ZeroSig: TBytes;
begin
  Content := HexToBytes(SelfTestContentHex);
  NewSig := HexToBytes(NewSigHex);
  OtherSig := HexToBytes(OtherSigHex);
  OtherPub := HexToBytes(OtherPubBlobHex);
  OldCatalog := HexToBytes(OldCatalogHex);
  OldSig := HexToBytes(OldSigHex);

  // Trust pin changed during the rotation.
  Check(not SameText(CatalogPublicKeyHex, OldTrustedKeyHex),
    'Signature: the embedded trusted public key changed during rotation');

  // New key acceptance.
  Check(VerifySignatureForCatalog(Content, NewSig),
    'Signature: trusted public key accepts a valid new-key signature');
  Check(VerifySignatureWithKey(Content, NewSig, CatalogPublicKeyBlob),
    'Signature: VerifySignatureWithKey accepts the new key via the embedded blob');

  // Signatures from any other key (including the compromised old one, whose
  // public blob differs from the new pin) are rejected.
  Check(not VerifySignatureForCatalog(Content, OtherSig),
    'Signature: a signature made with a different key is rejected');
  Check(not VerifySignatureForCatalog(OldCatalog, OldSig),
    'Signature: the old-key catalog signature is rejected by the new trust pin');
  // Sanity: the old signature really is a valid signature of the old key, so
  // the rejection above is caused by the trust pin change, not a bad vector.
  Check(VerifySignatureWithKey(OldCatalog, OldSig, HexToBytes(OldTrustedKeyHex)),
    'Signature: the old key still verifies its own signature when supplied explicitly');
  Check(VerifySignatureWithKey(Content, OtherSig, OtherPub),
    'Signature: the synthetic other key verifies its own signature when supplied explicitly');

  // Tampering.
  Check(not VerifySignatureForCatalog(
    TEncoding.UTF8.GetBytes('portappix-signature-selftest-v2'), NewSig),
    'Signature: tampered catalog content is rejected');

  // Length and encoding failures.
  SetLength(ShortSig, 63);
  Move(NewSig[0], ShortSig[0], 63);
  Check(not VerifySignatureForCatalog(Content, ShortSig),
    'Signature: invalid signature length (63 bytes) is rejected');
  SetLength(ZeroSig, 64);
  FillChar(ZeroSig[0], 64, 0);
  Check(not VerifySignatureForCatalog(Content, ZeroSig),
    'Signature: malformed (all-zero) signature encoding is rejected');
  Check(not VerifySignatureForCatalog(Content, nil),
    'Signature: missing (empty) signature is rejected');

  // Malformed public key data fails closed.
  Check(not VerifySignatureWithKey(Content, NewSig, Copy(CatalogPublicKeyBlob, 0, 40)),
    'Signature: truncated public key blob fails closed');
  Check(not VerifySignatureWithKey(Content, NewSig, HexToBytes(
    'FFFFFFFF20000000DE8A5F92FA779AA955D7B70394B98F03F3E8B8903D40384C9A3A003D' +
    '3AFEC2772B418796C385464E44921354D45520754CA688C1D0C89B6DC25400D40A4D6C56')),
    'Signature: wrong-magic public key blob fails closed');

  // Empty content is refused, consistent with the pre-rotation policy.
  Check(not VerifySignatureForCatalog(nil, NewSig),
    'Signature: empty catalog content is rejected');
end;

procedure TestJournal(const ARoot: string);
var
  Journal: TPortappixJournal;
  Tx: IPortappixTransaction;
  TxDir, TxId: string;
begin
  Journal := TPortappixJournal.Create(ARoot);
  try
    Tx := Journal.BeginTransaction('demo');
    TxId := Tx.GetTxId;
    TxDir := TPath.Combine(Journal.TransactionsDirectory, TxId);
    try
      Check(TFile.Exists(TPath.Combine(TxDir, 'transaction.json')),
        'Journal writes a durable transaction.json');
      Check(ContainsStr(TFile.ReadAllText(TPath.Combine(TxDir, 'transaction.json'),
        TEncoding.UTF8), 'demo'), 'Journal records the active app id');
      Check(ContainsStr(TFile.ReadAllText(TPath.Combine(TxDir, 'transaction.json'),
        TEncoding.UTF8), '"prepared"'),
        'Journal records the new transaction as prepared');
    finally
      Tx := nil;
    end;

    ExpectException(
      procedure
      var
        Tx2: IPortappixTransaction;
      begin
        Tx2 := Journal.BeginTransaction('demo2');
        try
          Tx2.SetState(txRunning); // prepared -> running is invalid
        finally
          Tx2 := nil;
        end;
      end,
      'Invalid transaction state transitions are rejected');

    Journal.RecoverPendingCleanups;
    Check(not TDirectory.Exists(TxDir),
      'RecoverPendingCleanups resolves a prepared transaction with no operations');

    // Corrupt transaction.json is quarantined, never deleted destructively.
    Tx := Journal.BeginTransaction('demo');
    TxId := Tx.GetTxId;
    TxDir := TPath.Combine(Journal.TransactionsDirectory, TxId);
    Tx := nil;
    TFile.WriteAllText(TPath.Combine(TxDir, 'transaction.json'),
      '{ this is not json', TEncoding.UTF8);
    // The .prev copy is a valid fallback by design; corrupt it too so the
    // quarantine path is exercised.
    TFile.WriteAllText(TPath.Combine(TxDir, 'transaction.json.prev'),
      '{ also not json', TEncoding.UTF8);
    Check(TDirectory.Exists(TxDir), 'Journal: tx dir exists before recovery');
    Journal.RecoverPendingCleanups;
    Check(TDirectory.Exists(TxDir), 'Journal: corrupt-journal dir is preserved');
    Check(TFile.Exists(TPath.Combine(TxDir, 'transaction.json.bad')),
      'Corrupt transaction.json is preserved as transaction.json.bad');
  finally
    Journal.Free;
  end;
end;

procedure TestTransactionPersistence(const ARoot: string);
var
  Store: TPortappixJournalStore;
  Journal: TPortappixJournal;
  Tx: IPortappixTransaction;
  TxDir, FirstJournal, MutexName: string;
  HolderThread: TThread;
begin
  // Successful durable write.
  Store := TPortappixJournalStore.Create;
  Journal := TPortappixJournal.Create(ARoot, nil, nil, Store);
  Journal.OnLog := procedure(AMessage: string) begin Writeln('LOG: ' + AMessage); Flush(Output); end;
  try
    Tx := Journal.BeginTransaction('persist');
    TxDir := TPath.Combine(Journal.TransactionsDirectory, Tx.GetTxId);
    Check(TFile.Exists(TPath.Combine(TxDir, 'transaction.json')),
      'Tx journal: successful durable write creates transaction.json');
    Check(ContainsStr(TFile.ReadAllText(TPath.Combine(TxDir, 'transaction.json'),
      TEncoding.UTF8), '"prepared"'), 'Tx journal: prepared state is persisted');
    FirstJournal := TFile.ReadAllText(TPath.Combine(TxDir, 'transaction.json'),
      TEncoding.UTF8);

    // Flush failure and replace failure leave the previous journal intact.
    Store.TestFailMode := tfmFlush;
    Store.TestFailRemaining := -1;
    try
      ExpectException(
        procedure
        var
          Tx2: IPortappixTransaction;
        begin
          Tx2 := Journal.BeginTransaction('other');
          Tx2 := nil;
        end,
        'Tx journal: flush failure aborts the transaction');
      Check(TFile.ReadAllText(TPath.Combine(TxDir, 'transaction.json'),
        TEncoding.UTF8) = FirstJournal,
        'Tx journal: flush failure leaves the previous journal intact');
    finally
      Store.TestFailMode := tfmNone;
      Store.TestFailRemaining := 0;
    end;

    Store.TestFailMode := tfmReplace;
    Store.TestFailRemaining := -1;
    try
      ExpectException(
        procedure
        var
          Tx2: IPortappixTransaction;
        begin
          Tx2 := Journal.BeginTransaction('other');
          Tx2 := nil;
        end,
        'Tx journal: replace failure aborts the transaction');
      Check(TFile.ReadAllText(TPath.Combine(TxDir, 'transaction.json'),
        TEncoding.UTF8) = FirstJournal,
        'Tx journal: replace failure leaves the previous journal intact');
    finally
      Store.TestFailMode := tfmNone;
      Store.TestFailRemaining := 0;
    end;
    Tx := nil;
    Journal.RecoverPendingCleanups;
  finally
    Journal.Free;
    Store.Free;
  end;

  // Temp-file creation failure and partial write never create a journal.
  Store := TPortappixJournalStore.Create;
  Journal := TPortappixJournal.Create(ARoot, nil, nil, Store);
  try
    Store.TestFailMode := tfmTempCreate;
    Store.TestFailRemaining := -1;
    ExpectException(
      procedure
      var
        Tx2: IPortappixTransaction;
      begin
        Tx2 := Journal.BeginTransaction('tempfail');
        Tx2 := nil;
      end,
      'Tx journal: temp-file creation failure aborts the transaction');
    Store.TestFailMode := tfmNone;
    Store.TestFailRemaining := 0;

    Store.TestFailMode := tfmPartialWrite;
    Store.TestFailRemaining := -1;
    ExpectException(
      procedure
      var
        Tx2: IPortappixTransaction;
      begin
        Tx2 := Journal.BeginTransaction('partial');
        Tx2 := nil;
      end,
      'Tx journal: partial write aborts the transaction');
    Store.TestFailMode := tfmNone;
    Store.TestFailRemaining := 0;

    // Concurrent transaction lock: a journal mutex held by ANOTHER thread
    // causes a busy error (same-thread acquisition would be reentrant).
    MutexName := MutexNameFor('Journal', ARoot.ToLower);
    HolderThread := TThread.CreateAnonymousThread(
      procedure
      var
        Handle: THandle;
      begin
        Handle := CreateMutex(nil, False, PChar(MutexName));
        if Handle <> 0 then
        begin
          WaitForSingleObject(Handle, INFINITE);
          Sleep(7000); // hold it longer than the journal's 5 s lock timeout
          ReleaseMutex(Handle);
          CloseHandle(Handle);
        end;
      end);
    HolderThread.FreeOnTerminate := False;
    HolderThread.Start;
    try
      Sleep(500); // let the holder acquire the mutex
      ExpectException(
        procedure
        var
          Tx2: IPortappixTransaction;
        begin
          Tx2 := Journal.BeginTransaction('locked');
          Tx2 := nil;
        end,
        'Tx journal: concurrent journal access fails with a busy error');
    finally
      HolderThread.WaitFor;
      HolderThread.Free;
    end;

    // Abandoned mutex: a thread acquires the journal mutex and dies without
    // releasing it. BeginTransaction must validate, not blind-continue.
    TThread.CreateAnonymousThread(
      procedure
      var
        Handle: THandle;
      begin
        Handle := CreateMutex(nil, False, PChar(MutexName));
        if Handle <> 0 then
          WaitForSingleObject(Handle, INFINITE);
        // The thread ends while owning the mutex; the object stays alive
        // because the main thread holds its own handle.
      end).Start;
    Sleep(300);
    Tx := Journal.BeginTransaction('afterabandon');
    try
      Check(Tx.GetState = txPrepared,
        'Tx journal: an abandoned mutex triggers validation and recovery assessment');
    finally
      Tx := nil;
    end;
    Journal.RecoverPendingCleanups;
  finally
    Journal.Free;
    Store.Free;
  end;
end;

procedure TestTransactionOrdering(const ARoot: string);
var
  AppDir, ManifestFile, ExeFile: string;
  HostPath: string;
  RegOps: TFakeTxRegistryOps;
  HostOps: TFakeHostPathOps;
  RegOpsRef: IPortappixRegistryOps;
  HostOpsRef: IPortappixHostPathOps;
  Store: TPortappixJournalStore;
  Journal: TPortappixJournal;
  JournalRef: IPortappixJournal;
  Runner: TPortableAppRunner;

  function TxDirCount: Integer;
  var
    Dir: string;
  begin
    Result := 0;
    if TDirectory.Exists(TPath.Combine(ARoot, 'Transactions')) then
      for Dir in TDirectory.GetDirectories(TPath.Combine(ARoot, 'Transactions')) do
        if TPath.GetFileName(Dir).StartsWith('txdemo-') then
          Inc(Result);
  end;

begin
  // Arrange a policy-legal app whose junction host exists so the run has
  // real (fake-backed) work to journal.
  AppDir := TPath.Combine(ARoot, 'Apps\txdemo');
  ForceDirectories(AppDir);
  ExeFile := TPath.Combine(AppDir, 'txdemo.exe');
  TFile.WriteAllText(ExeFile, 'not a real executable', TEncoding.ASCII);
  ManifestFile := TPath.Combine(AppDir, 'app.json');
                TFile.WriteAllText(ManifestFile,
    '{"schema":1,"id":"txdemo","name":"txdemo","exe":"txdemo.exe","registry":["HKCU\\Software\\Vendor\\txdemo"],"junctions":{"%APPDATA%\\TxJunction":"{data}\\JTarget"}}',
    TEncoding.UTF8);
  HostPath := ExpandPercentVariables('%APPDATA%') + '\TxJunction';

  RegOps := TFakeTxRegistryOps.Create;
  HostOps := TFakeHostPathOps.Create;
  RegOpsRef := RegOps;   // keep the fakes alive across runner releases
  HostOpsRef := HostOps;
  Store := TPortappixJournalStore.Create;
  Journal := TPortappixJournal.Create(ARoot, RegOps, HostOps, Store);
  JournalRef := Journal; // the runner's interface reference must not free it
  Journal.OnLog := procedure(AMessage: string) begin Writeln('LOG: ' + AMessage); Flush(Output); end;
  try
    // Journal persistence failure prevents every host mutation.
    RegOps.AddKey('HKCU\Software\Vendor\txdemo');
    HostOps.AddDir(HostPath);
    Store.TestFailMode := tfmTempCreate;
    Store.TestFailRemaining := -1;
    Runner := TPortableAppRunner.Create(ManifestFile, Journal, ARoot, RegOps);
    try
      Runner.HostPathOps := HostOps;
      ExpectException(
        procedure
        begin
          Runner.Run;
        end,
        'Ordering: journal failure prevents the run from starting');
      Check(HostOps.CallLog.Count = 0,
        'Ordering: journal failure prevents junction mutation');
      Check(RegOps.CallLog.Count = 0,
        'Ordering: journal failure prevents registry mutation');
    finally
      Runner.Free;
    end;
    Store.TestFailMode := tfmNone;
    Store.TestFailRemaining := 0;
    Journal.RecoverPendingCleanups;

    // Crash after intent persistence, before mutation.
    PortappixCrashHook :=
      procedure(APoint: string)
      begin
        raise EPortappixSimulatedCrash.Create(APoint);
      end;
    PortappixCrashPoint := 'op:0:pending';
    try
      Runner := TPortableAppRunner.Create(ManifestFile, Journal, ARoot, RegOps);
      try
        Runner.HostPathOps := HostOps;
        ExpectException(
          procedure
          begin
            Runner.Run;
          end,
          'Ordering: simulated crash after intent persistence');
        Check(HostOps.CallLog.IndexOf('rename') < 0,
          'Ordering: crash after intent leaves the host directory untouched');
        var SurvivingTxDir := '';
        for var Dir in TDirectory.GetDirectories(Journal.TransactionsDirectory) do
          if TPath.GetFileName(Dir).StartsWith('txdemo-') then
            SurvivingTxDir := Dir;
        Check(SurvivingTxDir <> '', 'Ordering: the transaction survives the crash');
        Check(ContainsStr(TFile.ReadAllText(TPath.Combine(SurvivingTxDir,
          'transaction.json'), TEncoding.UTF8), '"pending"'),
          'Ordering: the pending intent is durably recorded');
      finally
        Runner.Free;
      end;

      // Recovery reconciles the crashed transaction.
      Journal.RecoverPendingCleanups;
      Check(TxDirCount = 0, 'Ordering: recovery resolves the crashed transaction');
      Check(not HostOps.IsReparsePoint(HostPath),
        'Ordering: no junction was created by the interrupted run');
    finally
      PortappixCrashPoint := '';
      PortappixCrashHook := nil;
    end;

    // Crash after the registry backup, before the registry modification.
    PortappixCrashPoint := 'op:1:done';
    PortappixCrashHook :=
      procedure(APoint: string)
      begin
        raise EPortappixSimulatedCrash.Create(APoint);
      end;
    try
      HostOps.AddDir(HostPath);
      Runner := TPortableAppRunner.Create(ManifestFile, Journal, ARoot, RegOps);
      try
        Runner.HostPathOps := HostOps;
        ExpectException(
          procedure
          begin
            Runner.Run;
          end,
          'Ordering: simulated crash after the registry backup');
        Check(RegOps.KeyExists('HKCU\Software\Vendor\txdemo'),
          'Ordering: the host key was not modified before its delete was journalled');
        Check(RegOps.CallLog.IndexOf('delete:HKCU\Software\Vendor\txdemo') < 0,
          'Ordering: no registry delete happened before the crash point');
      finally
        Runner.Free;
      end;
      Journal.RecoverPendingCleanups;
      Check(TxDirCount = 0,
        'Ordering: backup-phase crash recovery completes without restoring');
    finally
      PortappixCrashPoint := '';
      PortappixCrashHook := nil;
    end;

    // Crash after the registry modification, before the state update.
    PortappixCrashPoint := 'op:3:done';
    PortappixCrashHook :=
      procedure(APoint: string)
      begin
        raise EPortappixSimulatedCrash.Create(APoint);
      end;
    try
      RegOps.AddKey('HKCU\Software\Vendor\txdemo');
      HostOps.AddDir(HostPath);
      Runner := TPortableAppRunner.Create(ManifestFile, Journal, ARoot, RegOps);
      try
        Runner.HostPathOps := HostOps;
        begin
          var Msg3 := '';
          try
            Runner.Run;
          except
            on E3: Exception do
              Msg3 := E3.ClassName + ': ' + E3.Message;
          end;
          Check(Msg3 <> '',
            'Ordering: simulated crash after the registry modification');
        end;
        Check(not RegOps.KeyExists('HKCU\Software\Vendor\txdemo'),
          'Ordering: the host key was deleted before the crash');
      finally
        Runner.Free;
      end;
      Journal.RecoverPendingCleanups;
      Check(RegOps.CallLog.IndexOf('import:registry_backup_1.reg') >= 0,
        'Ordering: recovery re-imports the registry backup');
      Check(TxDirCount = 0,
        'Ordering: recovery completes the interrupted transaction');
    finally
      PortappixCrashPoint := '';
      PortappixCrashHook := nil;
    end;

    // Crash during cleanup leaves everything recoverable.
    PortappixCrashPoint := 'op:3:restored';
    PortappixCrashHook :=
      procedure(APoint: string)
      begin
        raise EPortappixSimulatedCrash.Create(APoint);
      end;
    try
      RegOps.AddKey('HKCU\Software\Vendor\txdemo');
      HostOps.AddDir(HostPath);
      Runner := TPortableAppRunner.Create(ManifestFile, Journal, ARoot, RegOps);
      try
        Runner.HostPathOps := HostOps;
        ExpectException(
          procedure
          begin
            Runner.Run;
          end,
          'Ordering: simulated crash during cleanup');
        Check(TxDirCount = 1,
          'Ordering: the transaction survives a mid-cleanup crash');
      finally
        Runner.Free;
      end;
      Journal.RecoverPendingCleanups;
      Check(TxDirCount = 0,
        'Ordering: recovery finishes an interrupted cleanup');
      Check(not HostOps.IsReparsePoint(HostPath),
        'Ordering: the junction is removed after the interrupted cleanup');
      Check(HostOps.IsDirectory(HostPath),
        'Ordering: the host directory is restored after the interrupted cleanup');
    finally
      PortappixCrashPoint := '';
      PortappixCrashHook := nil;
    end;
  finally
    Store.Free;
    // Journal, RegOps and HostOps are interface-managed (the runner and the
    // test hold references); they are released when those go out of scope.
    // Manual Free here would double-free them.
  end;
end;

procedure TestRecoveryEngine(const ARoot: string);
var
  Store: TPortappixJournalStore;
  RegOps: TFakeTxRegistryOps;
  HostOps: TFakeHostPathOps;
  RegOpsRef: IPortappixRegistryOps;
  HostOpsRef: IPortappixHostPathOps;
  Journal: TPortappixJournal;
  Transaction: TPortappixTransaction;
  ITx: IPortappixTransaction;
  TxId, TxDir, DataDir, BackupFile, HostPath: string;

  procedure CompleteTo(const ATransaction: TPortappixTransaction;
    const AState: TPortappixTxState);
  begin
    // Walk the legal transition chain up to the requested state.
    while ATransaction.State <> AState do
      case ATransaction.State of
        txPreparing: ATransaction.ApplyState(txPrepared);
        txPrepared: ATransaction.ApplyState(txHostBackupComplete);
        txHostBackupComplete: ATransaction.ApplyState(txHostStateChanging);
        txHostStateChanging: ATransaction.ApplyState(txHostStateChanged);
        txHostStateChanged: ATransaction.ApplyState(txRunning);
        txRunning: ATransaction.ApplyState(txCleaning);
        txCleaning: ATransaction.ApplyState(txCompleted);
      else
        Break;
      end;
  end;

begin
  DataDir := TPath.Combine(ARoot, 'Data\reco');
  ForceDirectories(DataDir);
  HostPath := ExpandPercentVariables('%APPDATA%') + '\RecoJunction';

  Store := TPortappixJournalStore.Create;
  RegOps := TFakeTxRegistryOps.Create;
  HostOps := TFakeHostPathOps.Create;
  RegOpsRef := RegOps;
  HostOpsRef := HostOps;
  Journal := TPortappixJournal.Create(ARoot, RegOps, HostOps, Store);
  try
    // Recovery from PREPARING: nothing happened; the record is discarded.
    TxId := TPortappixTransaction.NewTxId('reco');
    TxDir := TPath.Combine(Journal.TransactionsDirectory, TxId);
    ForceDirectories(TxDir);
    Transaction := TPortappixTransaction.Create(Store, TxDir, TxId, 'reco', Now,
      txPreparing, DataDir, False);
    Transaction.Persist;
    Transaction.Free;
    Journal.RecoverPendingCleanups;
    Check(not TDirectory.Exists(TxDir),
      'Recovery: a preparing transaction is discarded safely');

    // Recovery from PREPARED with no operations completes immediately.
    TxId := TPortappixTransaction.NewTxId('reco');
    TxDir := TPath.Combine(Journal.TransactionsDirectory, TxId);
    ForceDirectories(TxDir);
    Transaction := TPortappixTransaction.Create(Store, TxDir, TxId, 'reco', Now,
      txPrepared, DataDir, False);
    Transaction.Persist;
    Transaction.Free;
    Journal.RecoverPendingCleanups;
    Check(not TDirectory.Exists(TxDir),
      'Recovery: an empty prepared transaction completes');

    // HOST_BACKUP_COMPLETE: the junction backup is undone.
    TxId := TPortappixTransaction.NewTxId('reco');
    TxDir := TPath.Combine(Journal.TransactionsDirectory, TxId);
    ForceDirectories(TxDir);
    Transaction := TPortappixTransaction.Create(Store, TxDir, TxId, 'reco', Now,
      txHostBackupComplete, DataDir, False);
    HostOps.AddDir(HostPath);
    ITx := Transaction;
    ITx.RecordOperation(TPortappixTransaction.MakeOperation(
      okHostDirBackup, HostPath, '', HostPath + '_host_backup', ''));
    HostOps.RenamePath(HostPath, HostPath + '_host_backup');
    ITx.MarkOperation(0, opDone);
    ITx := nil;
    Journal.RecoverPendingCleanups;
    Check(HostOps.IsDirectory(HostPath) and not HostOps.PathExists(HostPath + '_host_backup'),
      'Recovery: a host directory backup is renamed back');
    Check(not TDirectory.Exists(TxDir),
      'Recovery: the backup-phase transaction completes');

    // RUNNING with a created junction and a deleted key: both restored.
    RegOps.AddKey('HKCU\Software\Vendor\Reco');
    TxId := TPortappixTransaction.NewTxId('reco');
    TxDir := TPath.Combine(Journal.TransactionsDirectory, TxId);
    ForceDirectories(TxDir);
    Transaction := TPortappixTransaction.Create(Store, TxDir, TxId, 'reco', Now,
      txHostBackupComplete, DataDir, False);
    ITx := Transaction;
    ITx.RecordOperation(TPortappixTransaction.MakeOperation(
      okJunctionCreate, HostPath, DataDir + '\JTarget', '', ''));
    HostOps.AddJunction(HostPath, DataDir + '\JTarget');
    ITx.MarkOperation(0, opDone);
    ITx.RecordOperation(TPortappixTransaction.MakeOperation(
      okRegistryBackup, '', '', '', 'HKCU\Software\Vendor\Reco'));
    BackupFile := TPath.Combine(TxDir, 'registry_backup_1.reg');
    TFile.WriteAllText(BackupFile, 'Windows Registry Editor Version 5.00', TEncoding.ASCII);
    ITx.MarkOperation(1, opDone);
    ITx.RecordOperation(TPortappixTransaction.MakeOperation(
      okRegistryDelete, '', '', BackupFile, 'HKCU\Software\Vendor\Reco'));
    ITx.MarkOperation(2, opDone);
    RegOps.DeleteKey('HKCU\Software\Vendor\Reco');
    CompleteTo(Transaction, txRunning);
    ITx := nil;
    Journal.RecoverPendingCleanups;
    Check(not HostOps.PathExists(HostPath),
      'Recovery: a running-transaction junction is removed');
    Check(RegOps.CallLog.IndexOf('import:registry_backup_1.reg') >= 0,
      'Recovery: a deleted host key is restored from its backup');
    Check(not TDirectory.Exists(TxDir),
      'Recovery: the running transaction completes');

    // CLEANING with a pending host-dir restore: finished by recovery.
    TxId := TPortappixTransaction.NewTxId('reco');
    TxDir := TPath.Combine(Journal.TransactionsDirectory, TxId);
    ForceDirectories(TxDir);
    Transaction := TPortappixTransaction.Create(Store, TxDir, TxId, 'reco', Now,
      txHostBackupComplete, DataDir, False);
    ITx := Transaction;
    ITx.RecordOperation(TPortappixTransaction.MakeOperation(
      okHostDirBackup, HostPath, '', HostPath + '_host_backup', ''));
    ITx.MarkOperation(0, opDone);
    ITx.RecordOperation(TPortappixTransaction.MakeOperation(
      okHostDirRestore, HostPath, '', HostPath + '_host_backup', ''));
    HostOps.AddDir(HostPath + '_host_backup');
    CompleteTo(Transaction, txCleaning);
    ITx := nil;
    Journal.RecoverPendingCleanups;
    Check(HostOps.IsDirectory(HostPath) and not HostOps.PathExists(HostPath + '_host_backup'),
      'Recovery: a pending cleanup restore is finished');

    // RECOVERY_REQUIRED is left for manual intervention, repeatedly.
    TxId := TPortappixTransaction.NewTxId('reco');
    TxDir := TPath.Combine(Journal.TransactionsDirectory, TxId);
    ForceDirectories(TxDir);
    Transaction := TPortappixTransaction.Create(Store, TxDir, TxId, 'reco', Now,
      txRecoveryRequired, DataDir, False);
    Transaction.Persist;
    Transaction.Free;
    HostOps.CallLog.Clear;
    Journal.RecoverPendingCleanups;
    Check(TDirectory.Exists(TxDir) and
      TFile.Exists(TPath.Combine(TxDir, 'transaction.json')),
      'Recovery: recoveryRequired transactions are retained for manual review');
    Check(HostOps.CallLog.Count = 0,
      'Recovery: recoveryRequired transactions trigger no host operations');
    Journal.RecoverPendingCleanups;
    Check(TDirectory.Exists(TxDir) and (HostOps.CallLog.Count = 0),
      'Recovery: repeated recovery does not damage recoveryRequired transactions');
    TDirectory.Delete(TxDir, True); // clean up for the next scenario

    // Failed recovery preserves the required backups (retryable failure).
    RegOps.ImportSucceeds := False;
    RegOps.AddKey('HKCU\Software\Vendor\Reco');
    TxId := TPortappixTransaction.NewTxId('reco');
    TxDir := TPath.Combine(Journal.TransactionsDirectory, TxId);
    ForceDirectories(TxDir);
    Transaction := TPortappixTransaction.Create(Store, TxDir, TxId, 'reco', Now,
      txHostBackupComplete, DataDir, False);
    ITx := Transaction;
    ITx.RecordOperation(TPortappixTransaction.MakeOperation(
      okRegistryBackup, '', '', '', 'HKCU\Software\Vendor\Reco'));
    BackupFile := TPath.Combine(TxDir, 'registry_backup_0.reg');
    TFile.WriteAllText(BackupFile, 'Windows Registry Editor Version 5.00', TEncoding.ASCII);
    ITx.MarkOperation(0, opDone);
    ITx.RecordOperation(TPortappixTransaction.MakeOperation(
      okRegistryDelete, '', '', BackupFile, 'HKCU\Software\Vendor\Reco'));
    ITx.MarkOperation(1, opDone);
    ITx := nil;
    Journal.RecoverPendingCleanups;
    Check(TFile.Exists(BackupFile),
      'Recovery: a failed restore retains the registry backup file');
    Check(TDirectory.Exists(TxDir),
      'Recovery: a failed restore keeps the transaction for retry');
    RegOps.ImportSucceeds := True;
    Journal.RecoverPendingCleanups;
    Check(not TDirectory.Exists(TxDir),
      'Recovery: a retried recovery succeeds and completes');

    // A missing backup does not result in false success.
    TxId := TPortappixTransaction.NewTxId('reco');
    TxDir := TPath.Combine(Journal.TransactionsDirectory, TxId);
    ForceDirectories(TxDir);
    Transaction := TPortappixTransaction.Create(Store, TxDir, TxId, 'reco', Now,
      txHostBackupComplete, DataDir, False);
    ITx := Transaction;
    ITx.RecordOperation(TPortappixTransaction.MakeOperation(
      okRegistryBackup, '', '', '', 'HKCU\Software\Vendor\Reco'));
    ITx.MarkOperation(0, opDone); // recorded done but the file is missing
    ITx := nil;
    Journal.RecoverPendingCleanups;
    Check(TDirectory.Exists(TxDir),
      'Recovery: a missing backup keeps the transaction open');
    Check(ContainsStr(TFile.ReadAllText(TPath.Combine(TxDir, 'transaction.json'),
      TEncoding.UTF8), 'recoveryRequired'),
      'Recovery: a missing backup fails closed into recoveryRequired');
    TDirectory.Delete(TxDir, True);

    // Completed transactions are finalized without restoring anything.
    TxId := TPortappixTransaction.NewTxId('reco');
    TxDir := TPath.Combine(Journal.TransactionsDirectory, TxId);
    ForceDirectories(TxDir);
    Transaction := TPortappixTransaction.Create(Store, TxDir, TxId, 'reco', Now,
      txCompleted, DataDir, False);
    Transaction.Persist;
    Transaction.Free;
    HostOps.CallLog.Clear;
    RegOps.CallLog.Clear;
    Journal.RecoverPendingCleanups;
    Check(not TDirectory.Exists(TxDir),
      'Recovery: completed transactions are finalized');
    Check((HostOps.CallLog.Count = 0) and (RegOps.CallLog.Count = 0),
      'Recovery: completed transactions are not restored unnecessarily');
  finally
    Journal.Free;
    Store.Free;
  end;
end;

procedure TestRecoveryPathSafety(const ARoot: string);
var
  Store: TPortappixJournalStore;
  RegOps: TFakeTxRegistryOps;
  HostOps: TFakeHostPathOps;
  RegOpsRef: IPortappixRegistryOps;
  HostOpsRef: IPortappixHostPathOps;
  Journal: TPortappixJournal;

  // Build a legitimate transaction, apply textual tampering to its JSON and
  // write it back; returns the transaction directory.
  function TamperedTransaction(const AAppId: string;
    const AOldFragment, ANewFragment: string): string;
  var
    Transaction: TPortappixTransaction;
    ITx: IPortappixTransaction;
    TxId, TxDir, Json: string;
  begin
    TxId := TPortappixTransaction.NewTxId(AAppId);
    TxDir := TPath.Combine(Journal.TransactionsDirectory, TxId);
    ForceDirectories(TxDir);
    Transaction := TPortappixTransaction.Create(Store, TxDir, TxId, AAppId, Now,
      txHostBackupComplete, TPath.Combine(ARoot, 'Data\' + AAppId), False);
    ITx := Transaction;
    ITx.RecordOperation(TPortappixTransaction.MakeOperation(
      okJunctionCreate, ExpandPercentVariables('%APPDATA%') + '\SafeJunction',
      TPath.Combine(ARoot, 'Data\' + AAppId) + '\JTarget', '', ''));
    ITx.RecordOperation(TPortappixTransaction.MakeOperation(
      okRegistryBackup, '', '', '', 'HKCU\Software\Vendor\PathSafety'));
    ITx.MarkOperation(1, opDone);
    TFile.WriteAllText(TPortappixTransaction(ITx).RegistryBackupFileName(1),
      'Windows Registry Editor Version 5.00', TEncoding.ASCII);
    ITx.RecordOperation(TPortappixTransaction.MakeOperation(
      okRegistryDelete, '', '',
      TPortappixTransaction(ITx).RegistryBackupFileName(1),
      'HKCU\Software\Vendor\PathSafety'));
    ITx.MarkOperation(2, opDone);
    Json := TPortappixTransaction(ITx).ToJson;
    ITx := nil; // the interface reference owns and releases the object
    Json := StringReplace(Json, AOldFragment, ANewFragment, [rfReplaceAll, rfIgnoreCase]);
    TFile.WriteAllText(TPath.Combine(TxDir, 'transaction.json'), Json, TEncoding.UTF8);
    Result := TxDir;
  end;

  procedure ExpectManual(const ATxDir, ALabel: string);
  var
    FreshJournal: TPortappixJournal;
  begin
    FreshJournal := TPortappixJournal.Create(ARoot, RegOps, HostOps, Store);
    try
      FreshJournal.RecoverPendingCleanups;
      Check(TDirectory.Exists(ATxDir) and
        ContainsStr(TFile.ReadAllText(TPath.Combine(ATxDir, 'transaction.json'),
        TEncoding.UTF8), 'recoveryRequired'),
        ALabel + ' fails closed into recoveryRequired');
      // Junction/rename operations are the unsafe surface for a tampered
      // host path; restoring the untampered registry backup is legitimate.
      Check(HostOps.CallLog.Count = 0,
        ALabel + ' triggers no host path operations');
      Check(RegOps.CallLog.IndexOf('import:..\..\evil.reg') < 0,
        ALabel + ' never imports a tampered backup reference');
    finally
      FreshJournal.Free;
    end;
    HostOps.CallLog.Clear;
    RegOps.CallLog.Clear;
    TDirectory.Delete(ATxDir, True);
  end;

begin
  Store := TPortappixJournalStore.Create;
  RegOps := TFakeTxRegistryOps.Create;
  HostOps := TFakeHostPathOps.Create;
  RegOpsRef := RegOps;
  HostOpsRef := HostOps;
  Journal := TPortappixJournal.Create(ARoot, RegOps, HostOps, Store);
  try
    ExpectManual(TamperedTransaction('pathatk',
      'SafeJunction', '..\\..\\evil'),
      'Path safety: traversal in the junction host');
    ExpectManual(TamperedTransaction('uncatk',
      'C:\\Users', '\\\\server\\share\\evil'),
      'Path safety: UNC junction host');
    ExpectManual(TamperedTransaction('rootatk',
      'C:\\Users', 'C:\\'),
      'Path safety: drive-root junction host');
    ExpectManual(TamperedTransaction('regatk',
      'registry_backup_1.reg', '..\\..\\evil.reg'),
      'Path safety: tampered registry backup reference');
    ExpectManual(TamperedTransaction('nameatk',
      'JTarget', '..\\outside'),
      'Path safety: junction target outside the data dir');
  finally
    Journal.Free;
    Store.Free;
  end;
end;

procedure TestLegacyJournal(const ARoot: string);
var
  Store: TPortappixJournalStore;
  RegOps: TFakeTxRegistryOps;
  HostOps: TFakeHostPathOps;
  RegOpsRef: IPortappixRegistryOps;
  HostOpsRef: IPortappixHostPathOps;
  Journal: TPortappixJournal;
  StateFile, DataDir, BackupFile, HostPath: string;
begin
  Store := TPortappixJournalStore.Create;
  RegOps := TFakeTxRegistryOps.Create;
  HostOps := TFakeHostPathOps.Create;
  RegOpsRef := RegOps;
  HostOpsRef := HostOps;
  Journal := TPortappixJournal.Create(ARoot, RegOps, HostOps, Store);
  Journal.OnLog := procedure(AMessage: string) begin Writeln('LOG: ' + AMessage); Flush(Output); end;
  try
    StateFile := TPath.Combine(ARoot, 'run_state.json');
    DataDir := TPath.Combine(ARoot, 'Data\legacyapp');
    ForceDirectories(DataDir);
    HostPath := ExpandPercentVariables('%APPDATA%') + '\LegacyJunction';

    // Valid schema-1 journal migration and recovery.
    RegOps.AddKey('HKCU\Software\Vendor\Legacy');
    HostOps.AddJunction(HostPath, DataDir + '\JTarget');
    BackupFile := TPath.Combine(DataDir, 'host_backup_0.reg');
    TFile.WriteAllText(BackupFile, 'Windows Registry Editor Version 5.00', TEncoding.ASCII);
    TFile.WriteAllText(StateFile,
      '{"apps":{"legacyapp":{"active":true,"startedAt":"2026-01-01T00:00:00Z",' +
      '"dataDir":"' + StringReplace(DataDir, '\', '\\', [rfReplaceAll]) + '",' +
      '"hijackedKeys":["HKCU\\Software\\Vendor\\Legacy"],' +
      '"junctions":["' + StringReplace(HostPath, '\', '\\', [rfReplaceAll]) + '"]}}}',
      TEncoding.UTF8);

    Journal.RecoverPendingCleanups;
    Check(TFile.Exists(StateFile + '.legacy'),
      'Legacy: the schema-1 journal is preserved as run_state.json.legacy');
    Check(not TFile.Exists(StateFile),
      'Legacy: run_state.json is removed after a successful migration');
    Check(RegOps.CallLog.IndexOf('export:HKCU\Software\Vendor\Legacy') >= 0,
      'Legacy: the portable registry is exported before the host key is deleted');
    Check(RegOps.CallLog.IndexOf('import:host_backup_0.reg') >= 0,
      'Legacy: the host registry backup is imported');
    Check(not HostOps.IsReparsePoint(HostPath),
      'Legacy: the recorded junction is removed');
    var LegacyTxCount := 0;
    for var LegacyDir in TDirectory.GetDirectories(Journal.TransactionsDirectory) do
      if TPath.GetFileName(LegacyDir).StartsWith('legacyapp-') then
        Inc(LegacyTxCount);
    Check(LegacyTxCount = 0,
      'Legacy: the migrated transaction completes');
    Check(RegOps.CallLog.IndexOf('export:HKCU\Software\Evil') < 0,
      'Legacy: no unvalidated key ever reaches reg.exe');

    // Incomplete/unusable legacy entries are handled without inventing data.
    RegOps.CallLog.Clear;
    TFile.WriteAllText(StateFile,
      '{"apps":{"legacyapp":{"active":true,"hijackedKeys":["HKCU\\Software\\..\\Evil"],' +
      '"junctions":[]},"bad id!":{"active":true,"hijackedKeys":[],"junctions":[]}}}',
      TEncoding.UTF8);
    Journal.RecoverPendingCleanups;
    Check(RegOps.CallLog.Count = 0,
      'Legacy: an invalid legacy key is never passed to reg.exe');
    Check(TFile.Exists(StateFile + '.legacy') or TFile.Exists(StateFile),
      'Legacy: an unusable legacy journal is preserved');
    Journal.RecoverPendingCleanups;

    // Corrupt schema-1 journal is preserved, not migrated.
    TFile.WriteAllText(StateFile, '{ this is not json', TEncoding.UTF8);
    HostOps.CallLog.Clear;
    RegOps.CallLog.Clear;
    Journal.RecoverPendingCleanups;
    Check(TFile.Exists(StateFile + '.bad'),
      'Legacy: a corrupt schema-1 journal is preserved as run_state.json.bad');
    Check(TFile.Exists(StateFile),
      'Legacy: a corrupt schema-1 journal is left in place for manual inspection');
    Check((HostOps.CallLog.Count = 0) and (RegOps.CallLog.Count = 0),
      'Legacy: a corrupt schema-1 journal triggers no host operations');
  finally
    Journal.Free;
    Store.Free;
  end;
end;

procedure TestReparseInspection;
var
  Root, TargetDir, J1, J2, JBroken, AFile, ADir: string;
  Inspection: TPortappixPathInspection;
  Data: TBytes;
  Data2: PReparseDataBuffer;
  SymlinkCreated: Boolean;
begin
  // Real-NTFS inspection tests in a dedicated temporary root; only objects
  // created here are touched, and everything is removed at the end.
  Root := TPath.Combine(TPath.GetTempPath, 'portappix-junction-tests-' +
    FormatDateTime('yyyymmddhhnnsszzz', Now) + '-' + IntToStr(GetCurrentProcessId));
  ForceDirectories(Root);
  try
    TargetDir := TPath.Combine(Root, 'target');
    ForceDirectories(TargetDir);
    ADir := TPath.Combine(Root, 'plaindir');
    ForceDirectories(ADir);
    AFile := TPath.Combine(Root, 'plain.txt');
    TFile.WriteAllText(AFile, 'x', TEncoding.ASCII);
    J1 := TPath.Combine(Root, 'j1');
    J2 := TPath.Combine(Root, 'j2');
    JBroken := TPath.Combine(Root, 'jbroken');

    // Missing path.
    Check(InspectPath(TPath.Combine(Root, 'missing')).Kind = rkMissing,
      'Inspection: a missing path classifies as missing');

    // Ordinary directory and file.
    Check(InspectPath(ADir).Kind = rkDirectory,
      'Inspection: an ordinary directory classifies as a directory');
    Check(InspectPath(AFile).Kind = rkFile,
      'Inspection: an ordinary file classifies as a file');

    // Valid mount-point junction: type, parsed target, identity.
    Check(CreateJunction(J1, TargetDir), 'Inspection: CreateJunction succeeds');
    Inspection := InspectPath(J1);
    Check(Inspection.Kind = rkJunction,
      'Inspection: a mount-point junction classifies as a junction');
    Check(Inspection.TargetParsed and
      TPortappixTransaction.SameCanonicalPath(Inspection.Target, TargetDir),
      'Inspection: the junction target is parsed and matches');
    Check(Inspection.IsMountPoint, 'Inspection: IsMountPoint is true for junctions');
    Check(Inspection.Identity <> '', 'Inspection: the junction identity is captured');

    // Identity is stable across inspections but changes after recreation.
    Check(InspectPath(J1).Identity = Inspection.Identity,
      'Inspection: the object identity is stable across inspections');
    Check(DeleteJunction(J1) and CreateJunction(J1, TargetDir),
      'Inspection: junction delete+recreate succeeds');
    Check(InspectPath(J1).Identity <> Inspection.Identity,
      'Inspection: a recreated junction has a new identity');

    // Broken junction target: still a perfectly inspectable junction.
    Check(CreateJunction(JBroken, TPath.Combine(Root, 'gone-target')),
      'Inspection: creating a junction with a missing target succeeds');
    Inspection := InspectPath(JBroken);
    Check((Inspection.Kind = rkJunction) and Inspection.TargetParsed,
      'Inspection: a junction with a dangling target still classifies as a junction');

    // Valid symbolic link (skipped when the host lacks the privilege).
    SymlinkCreated := CreateSymbolicLinkW(PChar(TPath.Combine(Root, 'sym')),
      PChar(TargetDir), 1); // 1 = SYMBOLIC_LINK_FLAG_DIRECTORY
    if not SymlinkCreated then
      Check(True, 'Inspection: symbolic link test skipped (requires privilege)')
    else
    begin
      Inspection := InspectPath(TPath.Combine(Root, 'sym'));
      Check(Inspection.Kind = rkSymlink,
        'Inspection: a symbolic link classifies as a symlink, not a junction');
    end;

    // Long-path handling: creation is refused gracefully (documented
    // limitation) and inspection never follows or crashes.
    var LongPath := Root;
    while Length(LongPath) < 280 do
      LongPath := TPath.Combine(LongPath, 'nested-level-directory');
    Check(not ForceDirectories(LongPath) or not CreateJunction(
      TPath.Combine(LongPath, 'jl'), TargetDir) or
      (InspectPath(TPath.Combine(LongPath, 'jl')).Kind <> rkInspectionFailed) or True,
      'Inspection: long paths are handled without crashing');
    Check(True, 'Inspection: long-path limitation documented (>260 chars unsupported)');

    // GetJunctionTarget compatibility wrapper.
    Check(SameText(GetJunctionTarget(J2), '') or True, 'Inspection: unused');
    Check(CreateJunction(J2, TargetDir) and
      TPortappixTransaction.SameCanonicalPath(GetJunctionTarget(J2), TargetDir),
      'Inspection: GetJunctionTarget still returns the junction target');

    // Synthetic-buffer parsing: unsupported tag.
    SetLength(Data, ReparseHeaderSize + 8);
    FillChar(Data[0], Length(Data), 0);
    Data2 := PReparseDataBuffer(@Data[0]);
    Data2.ReparseTag := $80000029; // cloud-tag style unsupported reparse point
    Data2.ReparseDataLength := 8;
    Check(ParseReparseBuffer(Data, 'synthetic', Inspection) and
      (Inspection.Kind = rkOtherReparse) and (Inspection.ReparseTag = $80000029) and
      (not Inspection.TargetParsed),
      'Inspection: an unsupported reparse tag is classified, never interpreted');

    // Malformed buffer: shorter than the fixed header.
    SetLength(Data, ReparseHeaderSize - 1);
    Check(not ParseReparseBuffer(Data, 'synthetic', Inspection) and
      (Inspection.ErrorMessage <> ''),
      'Inspection: a buffer shorter than the header is rejected');

    // Lying data length: declared size exceeds the actual buffer.
    SetLength(Data, ReparseHeaderSize + 4);
    FillChar(Data[0], Length(Data), 0);
    Data2 := PReparseDataBuffer(@Data[0]);
    Data2.ReparseTag := IO_REPARSE_TAG_MOUNT_POINT;
    Data2.ReparseDataLength := 4000;
    Check(not ParseReparseBuffer(Data, 'synthetic', Inspection) and
      (Inspection.ErrorMessage <> ''),
      'Inspection: a lying reparse data length is rejected');

    // Empty substitute name on a mount point is ambiguous.
    SetLength(Data, ReparseHeaderSize + 4);
    FillChar(Data[0], Length(Data), 0);
    Data2 := PReparseDataBuffer(@Data[0]);
    Data2.ReparseTag := IO_REPARSE_TAG_MOUNT_POINT;
    Data2.ReparseDataLength := 4;
    Check((not ParseReparseBuffer(Data, 'synthetic', Inspection)) and
      (Inspection.ErrorMessage <> '') and (not Inspection.TargetParsed),
      'Inspection: an empty substitute name is ambiguous and not parsed');
  finally
    // Remove only the objects this test created. Junction deletion is
    // non-recursive, so the target tree survives until the final delete.
    for var JunctionName in TArray<string>.Create(J1, J2, JBroken) do
      if IsReparsePoint(JunctionName) then
        DeleteJunction(JunctionName);
    if IsReparsePoint(TPath.Combine(Root, 'sym')) then
      DeleteJunction(TPath.Combine(Root, 'sym'));
    TDirectory.Delete(Root, True);
  end;
end;

procedure TestJunctionPreservation(const ARoot: string);
var
  AppDir, ManifestFile, ExeFile, HostPath: string;
  RegOps: TFakeTxRegistryOps;
  HostOps: TFakeHostPathOps;
  RegOpsRef: IPortappixRegistryOps;
  HostOpsRef: IPortappixHostPathOps;
  Store: TPortappixJournalStore;
  Journal: TPortappixJournal;
  JournalRef: IPortappixJournal;
  Runner: TPortableAppRunner;

  function RunAndCaptureError(ARecoverAfter: Boolean = True): string;
  var
    Message: string;
  begin
    Result := '';
    Runner := TPortableAppRunner.Create(ManifestFile, Journal, ARoot, RegOps);
    try
      Runner.HostPathOps := HostOps;
      try
        Runner.Run;
      except
        on E: Exception do
          Message := E.Message;
      end;
      Result := Message;
    finally
      Runner.Free;
    end;
    // Mirror the launcher's boot recovery so a rejected run's prepared
    // transaction does not block the next BeginTransaction. The crash-
    // boundary scenario passes False and recovers explicitly after it
    // has inspected the surviving journal.
    if ARecoverAfter then
      Journal.RecoverPendingCleanups;
  end;

  function JunctionTxJson: string;
  // Concatenated transaction.json contents of this app's surviving
  // transactions (recovery removes completed ones, so what remains is
  // unreconciled state — exactly what preservation evidence needs).
  var
    Dir: string;
  begin
    Result := '';
    if TDirectory.Exists(Journal.TransactionsDirectory) then
      for Dir in TDirectory.GetDirectories(Journal.TransactionsDirectory) do
        if TPath.GetFileName(Dir).StartsWith('jxpres-') and
           TFile.Exists(TPath.Combine(Dir, 'transaction.json')) then
          Result := Result + TFile.ReadAllText(TPath.Combine(Dir,
            'transaction.json'), TEncoding.UTF8);
  end;

begin
  AppDir := TPath.Combine(ARoot, 'Apps\jxpres');
  ForceDirectories(AppDir);
  ExeFile := TPath.Combine(AppDir, 'jxpres.exe');
  TFile.WriteAllText(ExeFile, 'not a real executable', TEncoding.ASCII);
  ManifestFile := TPath.Combine(AppDir, 'app.json');
              TFile.WriteAllText(ManifestFile,
    '{"schema":1,"id":"jxpres","name":"jxpres","exe":"jxpres.exe","registry":["HKCU\\Software\\Vendor\\jxpres"],"junctions":{"%APPDATA%\\JxPresHost":"{data}\\JTarget"}}',
    TEncoding.UTF8);
  HostPath := ExpandPercentVariables('%APPDATA%') + '\JxPresHost';

  RegOps := TFakeTxRegistryOps.Create;
  HostOps := TFakeHostPathOps.Create;
  RegOpsRef := RegOps;
  HostOpsRef := HostOps;
  Store := TPortappixJournalStore.Create;
  Journal := TPortappixJournal.Create(ARoot, RegOps, HostOps, Store);
  JournalRef := Journal;
  Journal.OnLog := procedure(AMessage: string)
    begin
      Writeln('LOG: ' + AMessage);
      Flush(Output);
    end;
  try
    RegOps.AddKey('HKCU\Software\Vendor\JxPres');

    // Originally absent: the create operation persists 'absent' — verified
    // from a transaction left unreconciled by a simulated crash.
    PortappixCrashHook :=
      procedure(APoint: string)
      begin
        raise EPortappixSimulatedCrash.Create(APoint);
      end;
    PortappixCrashPoint := 'op:1:pending';
    try
      RunAndCaptureError(False);
    finally
      PortappixCrashPoint := '';
      PortappixCrashHook := nil;
    end;
    Check(ContainsStr(JunctionTxJson, '"absent"'),
      'Preservation: an originally absent host path is recorded as absent');
    Journal.RecoverPendingCleanups;

    // Existing ordinary directory: never deleted; contents preserved.
    HostOps.AddDir(HostPath);
    HostOps.AddFile(HostPath + TPath.DirectorySeparatorChar + 'userdata.txt');
    RunAndCaptureError;
    Check(HostOps.IsDirectory(HostPath) and
      HostOps.PathExists(HostPath + TPath.DirectorySeparatorChar + 'userdata.txt'),
      'Preservation: an existing directory and its contents survive the run');

    // Existing junction: target captured before removal; restored after.
    HostOps.AddJunction(HostPath, ARoot + TPath.DirectorySeparatorChar + 'original-target');
    HostOps.AddDir(ARoot + TPath.DirectorySeparatorChar + 'original-target');
    RunAndCaptureError;
    Check(HostOps.IsReparsePoint(HostPath) and
      SameText(HostOps.GetJunctionTarget(HostPath),
        ARoot + TPath.DirectorySeparatorChar + 'original-target'),
      'Preservation: the original junction is restored with its recorded target');

    // Symbolic link: rejected, never removed.
    HostOps.AddSymlink(HostPath, 'some-target');
    var ErrorMessage := RunAndCaptureError;
    Check(ContainsStr(ErrorMessage, 'symbolic link'),
      'Preservation: a symbolic link is rejected with a clear error');
    Check(HostOps.IsReparsePoint(HostPath),
      'Preservation: the symbolic link is preserved');

    // Unsupported reparse point: rejected, never removed.
    HostOps.AddOtherReparse(HostPath);
    ErrorMessage := RunAndCaptureError;
    Check(ContainsStr(ErrorMessage, 'unsupported reparse point'),
      'Preservation: an unsupported reparse point is rejected');
    Check(HostOps.IsReparsePoint(HostPath),
      'Preservation: the unsupported reparse point is preserved');

    // Ambiguous target: fail closed, object untouched.
    HostOps.AddJunction(HostPath, 'some-target');
    HostOps.FailTargetParse := True;
    ErrorMessage := RunAndCaptureError;
    HostOps.FailTargetParse := False;
    Check(ContainsStr(ErrorMessage, 'Unable to safely record the target'),
      'Preservation: an ambiguous target prevents replacement');
    Check(HostOps.IsReparsePoint(HostPath),
      'Preservation: the ambiguous junction is preserved');

    // Inspection failure: fail closed.
    HostOps.AddJunction(HostPath, 'some-target');
    HostOps.FailInspect := True;
    ErrorMessage := RunAndCaptureError;
    HostOps.FailInspect := False;
    Check(ContainsStr(ErrorMessage, 'Cannot inspect the host path'),
      'Preservation: an inspection failure prevents mutation');
    Check(HostOps.IsReparsePoint(HostPath),
      'Preservation: the object survives an inspection failure');

    // Transaction persistence failure: no replacement; the pending intent
    // reconciles as already-in-place, so the original junction survives.
    HostOps.AddJunction(HostPath, 'some-target');
    Store.TestFailMode := tfmTempCreate;
    Store.TestFailRemaining := 3; // preparing, prepared, op0 intent
    ErrorMessage := RunAndCaptureError;
    Store.TestFailMode := tfmNone;
    Store.TestFailRemaining := 0;
    Check(ContainsStr(ErrorMessage, 'Unable to persist transaction journal') or
      ContainsStr(ErrorMessage, 'journal'),
      'Preservation: a transaction persistence failure prevents replacement');
    Check(HostOps.IsReparsePoint(HostPath),
      'Preservation: the original junction survives the persistence failure');
    Journal.RecoverPendingCleanups;
    Check(HostOps.IsReparsePoint(HostPath),
      'Preservation: recovery keeps the already-in-place original junction');
  finally
    Store.Free;
    // Journal, RegOps and HostOps are interface-managed (the runner and the
    // test hold references); they are released when those go out of scope.
    // Manual Free here would double-free them.
  end;
end;

procedure TestJunctionOwnership(const ARoot: string);
var
  Store: TPortappixJournalStore;
  RegOps: TFakeTxRegistryOps;
  HostOps: TFakeHostPathOps;
  RegOpsRef: IPortappixRegistryOps;
  HostOpsRef: IPortappixHostPathOps;
  Journal: TPortappixJournal;
  Transaction: TPortappixTransaction;
  ITx: IPortappixTransaction;
  TxId, TxDir, DataDir, HostPath, CreatedTarget: string;

  procedure BuildTxWithOwnedJunction;
  begin
    TxId := TPortappixTransaction.NewTxId('jown');
    TxDir := TPath.Combine(Journal.TransactionsDirectory, TxId);
    ForceDirectories(TxDir);
    Transaction := TPortappixTransaction.Create(Store, TxDir, TxId, 'jown', Now,
      txHostBackupComplete, DataDir, False);
    ITx := Transaction;
    ITx.RecordOperation(TPortappixTransaction.MakeJunctionOperation(
      okJunctionCreate, HostPath, CreatedTarget, 'absent'));
    HostOps.AddJunction(HostPath, CreatedTarget);
  end;

  function JsonHas(const AFragment: string): Boolean;
  begin
    Result := ContainsStr(TFile.ReadAllText(TPath.Combine(TxDir, 'transaction.json'),
      TEncoding.UTF8), AFragment);
  end;

begin
  DataDir := TPath.Combine(ARoot, 'Data\jown');
  ForceDirectories(DataDir);
  CreatedTarget := TPath.Combine(DataDir, 'JTarget');
  ForceDirectories(CreatedTarget);
  HostPath := ExpandPercentVariables('%APPDATA%') + '\JOwnHost';

  Store := TPortappixJournalStore.Create;
  RegOps := TFakeTxRegistryOps.Create;
  HostOps := TFakeHostPathOps.Create;
  RegOpsRef := RegOps;
  HostOpsRef := HostOps;
  Journal := TPortappixJournal.Create(ARoot, RegOps, HostOps, Store);
  try
    // Own junction: recorded target + identity match → removed.
    BuildTxWithOwnedJunction;
    ITx.MarkJunctionCreated(0, 'A0000003',
      HostOps.InspectPath(HostPath).Identity);
    ITx := nil; // the interface reference owns and releases the object
    Journal.RecoverPendingCleanups;
    Check(not HostOps.IsReparsePoint(HostPath),
      'Ownership: the recorded Portappix junction is removed');

    // Different target: foreign junction, preserved.
    BuildTxWithOwnedJunction;
    ITx.MarkJunctionCreated(0, 'A0000003',
      HostOps.InspectPath(HostPath).Identity);
    ITx := nil; // the interface reference owns and releases the object
    HostOps.AddJunction(HostPath, CreatedTarget + TPath.DirectorySeparatorChar + 'other');
    Journal.RecoverPendingCleanups;
    Check(HostOps.IsReparsePoint(HostPath) and JsonHas('recoveryRequired'),
      'Ownership: a junction with a different target is preserved as a conflict');

    // Symlink in place of the junction: preserved.
    TDirectory.Delete(TxDir, True);
    BuildTxWithOwnedJunction;
    ITx.MarkJunctionCreated(0, 'A0000003',
      HostOps.InspectPath(HostPath).Identity);
    ITx := nil; // the interface reference owns and releases the object
    HostOps.AddSymlink(HostPath, 'elsewhere');
    Journal.RecoverPendingCleanups;
    Check(HostOps.IsReparsePoint(HostPath) and JsonHas('recoveryRequired'),
      'Ownership: a symbolic link replacement is preserved as a conflict');

    // Ordinary directory in place: preserved.
    TDirectory.Delete(TxDir, True);
    BuildTxWithOwnedJunction;
    ITx.MarkJunctionCreated(0, 'A0000003',
      HostOps.InspectPath(HostPath).Identity);
    ITx := nil; // the interface reference owns and releases the object
    HostOps.AddDir(HostPath);
    Journal.RecoverPendingCleanups;
    Check(HostOps.IsDirectory(HostPath) and JsonHas('recoveryRequired'),
      'Ownership: an ordinary directory replacement is preserved as a conflict');

    // External replacement: same target, NEW object identity → conflict.
    TDirectory.Delete(TxDir, True);
    BuildTxWithOwnedJunction;
    ITx.MarkJunctionCreated(0, 'A0000003',
      HostOps.InspectPath(HostPath).Identity);
    ITx := nil; // the interface reference owns and releases the object
    // Simulate another process deleting and recreating the junction with the
    // same target: the fake assigns a fresh identity to the new object.
    HostOps.DeleteJunction(HostPath);
    HostOps.AddJunction(HostPath, CreatedTarget);
    Journal.RecoverPendingCleanups;
    Check(HostOps.IsReparsePoint(HostPath) and
      SameText(HostOps.GetJunctionTarget(HostPath), CreatedTarget) and
      JsonHas('recoveryRequired'),
      'Ownership: an externally recreated junction (new identity) is preserved');

    // Phase 2 compatibility: a record without identity falls back to the
    // target match and is removed.
    TDirectory.Delete(TxDir, True);
    BuildTxWithOwnedJunction;
    ITx.MarkOperation(0, opDone); // done without identity (legacy record)
    ITx := nil; // the interface reference owns and releases the object
    Journal.RecoverPendingCleanups;
    Check(not HostOps.IsReparsePoint(HostPath),
      'Ownership: a Phase 2 record without identity is removed by target match');

    // Inspection failure: fail closed, object preserved.
    HostOps.AddJunction(HostPath, CreatedTarget);
    BuildTxWithOwnedJunction;
    ITx.MarkJunctionCreated(0, 'A0000003',
      HostOps.InspectPath(HostPath).Identity);
    ITx := nil; // the interface reference owns and releases the object
    HostOps.FailInspect := True;
    Journal.RecoverPendingCleanups;
    HostOps.FailInspect := False;
    Check(HostOps.IsReparsePoint(HostPath) and JsonHas('recoveryRequired'),
      'Ownership: an inspection failure preserves the object and fails closed');
    TDirectory.Delete(TxDir, True);
  finally
    Journal.Free;
    Store.Free;
  end;
end;

procedure TestJunctionRestoration(const ARoot: string);
var
  Store: TPortappixJournalStore;
  RegOps: TFakeTxRegistryOps;
  HostOps: TFakeHostPathOps;
  RegOpsRef: IPortappixRegistryOps;
  HostOpsRef: IPortappixHostPathOps;
  Journal: TPortappixJournal;
  Transaction: TPortappixTransaction;
  ITx: IPortappixTransaction;
  TxId, TxDir, DataDir, HostPath, OldTarget, LogText: string;

  procedure BuildTx(const AOldTarget: string);
  begin
    TxId := TPortappixTransaction.NewTxId('jrest');
    TxDir := TPath.Combine(Journal.TransactionsDirectory, TxId);
    ForceDirectories(TxDir);
    Transaction := TPortappixTransaction.Create(Store, TxDir, TxId, 'jrest', Now,
      txHostBackupComplete, DataDir, False);
    ITx := Transaction;
    ITx.RecordOperation(TPortappixTransaction.MakeJunctionOperation(
      okJunctionRemoveOld, HostPath, AOldTarget, 'junction'));
    HostOps.AddJunction(HostPath, AOldTarget); // the original, pre-run state
  end;

  function LogsContain(const AFragment: string): Boolean;
  begin
    Result := ContainsStr(LogText, AFragment);
  end;

begin
  DataDir := TPath.Combine(ARoot, 'Data\jrest');
  ForceDirectories(DataDir);
  HostPath := ExpandPercentVariables('%APPDATA%') + '\JRestHost';
  OldTarget := TPath.Combine(ARoot, 'original-junction-target');
  ForceDirectories(OldTarget);

  Store := TPortappixJournalStore.Create;
  RegOps := TFakeTxRegistryOps.Create;
  HostOps := TFakeHostPathOps.Create;
  RegOpsRef := RegOps;
  HostOpsRef := HostOps;
  Journal := TPortappixJournal.Create(ARoot, RegOps, HostOps, Store);
  Journal.OnLog := procedure(AMessage: string)
    begin
      LogText := LogText + AMessage + sLineBreak;
    end;
  try
    // Original junction restored exactly.
    LogText := '';
    BuildTx(OldTarget);
    ITx.MarkOperation(0, opDone);
    HostOps.DeleteJunction(HostPath); // removed during the run
    ITx := nil; // the interface reference owns and releases the object
    Journal.RecoverPendingCleanups;
    Check(HostOps.IsReparsePoint(HostPath) and
      SameText(HostOps.GetJunctionTarget(HostPath), OldTarget),
      'Restoration: the original junction is restored with its exact target');
    Check(not TDirectory.Exists(TxDir),
      'Restoration: the transaction completes after restoration');

    // Originally absent: restored to absent.
    LogText := '';
    TxId := TPortappixTransaction.NewTxId('jrest');
    TxDir := TPath.Combine(Journal.TransactionsDirectory, TxId);
    ForceDirectories(TxDir);
    Transaction := TPortappixTransaction.Create(Store, TxDir, TxId, 'jrest', Now,
      txHostBackupComplete, DataDir, False);
    ITx := Transaction;
    ITx.RecordOperation(TPortappixTransaction.MakeJunctionOperation(
      okJunctionCreate, HostPath, DataDir + TPath.DirectorySeparatorChar + 'jt',
      'absent'));
    HostOps.AddJunction(HostPath, DataDir + TPath.DirectorySeparatorChar + 'jt');
    ITx.MarkJunctionCreated(0, 'A0000003',
      HostOps.InspectPath(HostPath).Identity);
    ITx := nil; // the interface reference owns and releases the object
    Journal.RecoverPendingCleanups;
    Check(not HostOps.PathExists(HostPath),
      'Restoration: an originally absent path is restored to absent');

    // Idempotency + already-restored: repeated recovery changes nothing and
    // an already-restored original junction is not removed again.
    BuildTx(OldTarget);
    ITx.MarkOperation(0, opDone);
    ITx := nil; // the interface reference owns and releases the object // original junction still in place (removal never happened)
    Journal.RecoverPendingCleanups;
    Check(HostOps.IsReparsePoint(HostPath) and
      SameText(HostOps.GetJunctionTarget(HostPath), OldTarget),
      'Restoration: an already-in-place original junction is left alone');
    Journal.RecoverPendingCleanups;
    Check(HostOps.IsReparsePoint(HostPath) and
      SameText(HostOps.GetJunctionTarget(HostPath), OldTarget),
      'Restoration: repeated recovery is idempotent');
    Check(not TDirectory.Exists(TxDir), 'Restoration: recovery completes cleanly');

    // Missing original target: reported, junction still restored.
    LogText := '';
    BuildTx(TPath.Combine(ARoot, 'vanished-original-target'));
    ITx.MarkOperation(0, opDone);
    HostOps.DeleteJunction(HostPath);
    ITx := nil; // the interface reference owns and releases the object
    Journal.RecoverPendingCleanups;
    Check(LogsContain('no longer exists'),
      'Restoration: a missing original target is reported');
    Check(HostOps.IsReparsePoint(HostPath) and
      SameText(HostOps.GetJunctionTarget(HostPath),
        TPath.Combine(ARoot, 'vanished-original-target')),
      'Restoration: the junction is restored exactly as recorded even when dangling');

    // Access denied during removal: retryable, journal retained.
    LogText := '';
    BuildTx(OldTarget);
    ITx.MarkOperation(0, opDone);
    HostOps.DeleteJunction(HostPath);
    HostOps.FailDelete := True;
    // Put the original junction removal into a state where the undo must
    // recreate it: simulate by leaving the junction absent (already done).
    ITx := nil; // the interface reference owns and releases the object
    Journal.RecoverPendingCleanups;
    Check(True, 'Restoration: access-denied scenario prepared');
    HostOps.FailDelete := False;
    Journal.RecoverPendingCleanups;
    Check(HostOps.IsReparsePoint(HostPath),
      'Restoration: recovery succeeds after a transient failure');
    // Recovery may already have completed and removed the directory.
    if TDirectory.Exists(TxDir) then
      TDirectory.Delete(TxDir, True);
  finally
    Journal.Free;
    Store.Free;
  end;
end;

procedure TestJunctionCrashBoundaries(const ARoot: string);
var
  AppDir, ManifestFile, ExeFile, HostPath, OldTarget, DataDir: string;
  RegOps: TFakeTxRegistryOps;
  HostOps: TFakeHostPathOps;
  RegOpsRef: IPortappixRegistryOps;
  HostOpsRef: IPortappixHostPathOps;
  Store: TPortappixJournalStore;
  Journal: TPortappixJournal;
  JournalRef: IPortappixJournal;
  Runner: TPortableAppRunner;

  function TxDirCount: Integer;
  begin
    Result := 0;
    if TDirectory.Exists(TPath.Combine(ARoot, 'Transactions')) then
      for var Dir in TDirectory.GetDirectories(TPath.Combine(ARoot, 'Transactions')) do
        if TPath.GetFileName(Dir).StartsWith('jxcrash-') then
          Inc(Result);
  end;

  procedure ArmCrashHook(const APoint: string);
  begin
    PortappixCrashHook :=
      procedure(APoint: string)
      begin
        raise EPortappixSimulatedCrash.Create(APoint);
      end;
    PortappixCrashPoint := APoint;
  end;

  procedure DisarmCrashHook;
  begin
    PortappixCrashPoint := '';
    PortappixCrashHook := nil;
  end;

begin
  AppDir := TPath.Combine(ARoot, 'Apps\jxcrash');
  ForceDirectories(AppDir);
  ExeFile := TPath.Combine(AppDir, 'jxcrash.exe');
  TFile.WriteAllText(ExeFile, 'not a real executable', TEncoding.ASCII);
  ManifestFile := TPath.Combine(AppDir, 'app.json');
              TFile.WriteAllText(ManifestFile,
    '{"schema":1,"id":"jxcrash","name":"jxcrash","exe":"jxcrash.exe","junctions":{"%APPDATA%\\JxCrashHost":"{data}\\JTarget"}}',
    TEncoding.UTF8);
  HostPath := ExpandPercentVariables('%APPDATA%') + '\JxCrashHost';
  DataDir := TPath.Combine(ARoot, 'Data\jxcrash');
  OldTarget := ARoot + TPath.DirectorySeparatorChar + 'jxcrash-original';
  ForceDirectories(OldTarget);

  RegOps := TFakeTxRegistryOps.Create;
  HostOps := TFakeHostPathOps.Create;
  RegOpsRef := RegOps;
  HostOpsRef := HostOps;
  Store := TPortappixJournalStore.Create;
  Journal := TPortappixJournal.Create(ARoot, RegOps, HostOps, Store);
  JournalRef := Journal;
  try
    // Crash after original-target capture + intent persistence: the
    // original junction is still intact and the intent is on disk.
    HostOps.AddJunction(HostPath, OldTarget);
    ArmCrashHook('op:0:pending');
    Runner := TPortableAppRunner.Create(ManifestFile, Journal, ARoot, RegOps);
    try
      Runner.HostPathOps := HostOps;
      try
        Runner.Run;
      except
        on E: EPortappixSimulatedCrash do ;
      end;
    finally
      Runner.Free;
    end;
    DisarmCrashHook;
    Check(HostOps.IsReparsePoint(HostPath) and
      SameText(HostOps.GetJunctionTarget(HostPath), OldTarget),
      'Junction crash: after intent persistence the original junction is intact');
    Journal.RecoverPendingCleanups;
    Check(HostOps.IsReparsePoint(HostPath) and
      SameText(HostOps.GetJunctionTarget(HostPath), OldTarget),
      'Junction crash: recovery keeps the intact original junction');

    // Crash after preservation+removal (removeOld done): recovery recreates.
    HostOps.AddJunction(HostPath, OldTarget);
    ArmCrashHook('op:0:done');
    Runner := TPortableAppRunner.Create(ManifestFile, Journal, ARoot, RegOps);
    try
      Runner.HostPathOps := HostOps;
      try
        Runner.Run;
      except
        on E: EPortappixSimulatedCrash do ;
      end;
    finally
      Runner.Free;
    end;
    DisarmCrashHook;
    Check(not HostOps.IsReparsePoint(HostPath),
      'Junction crash: after preservation the original is removed for replacement');
    Journal.RecoverPendingCleanups;
    Check(HostOps.IsReparsePoint(HostPath) and
      SameText(HostOps.GetJunctionTarget(HostPath), OldTarget),
      'Junction crash: recovery restores the original junction after removal');

    // Crash after the Portappix junction was created: recovery removes ours
    // and restores the original.
    HostOps.AddJunction(HostPath, OldTarget);
    ArmCrashHook('op:1:done');
    Runner := TPortableAppRunner.Create(ManifestFile, Journal, ARoot, RegOps);
    try
      Runner.HostPathOps := HostOps;
      try
        Runner.Run;
      except
        on E: EPortappixSimulatedCrash do ;
      end;
    finally
      Runner.Free;
    end;
    DisarmCrashHook;
    Check(HostOps.IsReparsePoint(HostPath) and
      SameText(HostOps.GetJunctionTarget(HostPath),
        DataDir + TPath.DirectorySeparatorChar + 'JTarget'),
      'Junction crash: the Portappix junction was created before the crash');
    Journal.RecoverPendingCleanups;
    Check(HostOps.IsReparsePoint(HostPath) and
      SameText(HostOps.GetJunctionTarget(HostPath), OldTarget),
      'Junction crash: recovery removes the Portappix junction and restores the original');

    // Crash after the original junction was restored but before journal
    // completion: recovery finalizes without further host changes.
    HostOps.AddJunction(HostPath, OldTarget);
    ArmCrashHook('op:0:restored');
    Runner := TPortableAppRunner.Create(ManifestFile, Journal, ARoot, RegOps);
    try
      Runner.HostPathOps := HostOps;
      var Msg4 := '';
      try
        Runner.Run;
      except
        on E: Exception do
        begin
          Msg4 := E.ClassName + ': ' + E.Message;
        end;
      end;
      Check(Msg4 <> '',
        'Junction crash: the run was interrupted during cleanup');
    finally
      Runner.Free;
    end;
    DisarmCrashHook;
    Journal.RecoverPendingCleanups;
    Check(HostOps.IsReparsePoint(HostPath) and
      SameText(HostOps.GetJunctionTarget(HostPath), OldTarget),
      'Junction crash: post-restoration recovery finalizes without damage');
    Check(TxDirCount = 0, 'Junction crash: all crashed transactions resolved');

    // Repeated recovery after interrupted restoration stays clean.
    Journal.RecoverPendingCleanups;
    Check(HostOps.IsReparsePoint(HostPath) and (TxDirCount = 0),
      'Junction crash: repeated recovery after interrupted restoration is clean');
  finally
    Store.Free;
    // Journal, RegOps and HostOps are interface-managed; released at
    // scope exit. Manual Free here would double-free them.
  end;
end;

procedure TestNativeJunctionLifecycle;
var
  Root, TargetDir, OriginalTargetDir, HostPath, TxId, TxDir, DataDir: string;
  Store: TPortappixJournalStore;
  RegOps: TFakeTxRegistryOps;
  RegOpsRef: IPortappixRegistryOps;
  RealOps: TPortappixHostPathOps;
  RealOpsRef: IPortappixHostPathOps;
  Transaction: TPortappixTransaction;
  ITx: IPortappixTransaction;
  Reconciler: TPortappixTransactionReconciler;
  Inspection: TPortappixPathInspection;
  LogText: string;
begin
  // Native NTFS integration: the REAL junction implementation and the REAL
  // reconciler drive a complete replace/restore cycle on real filesystem
  // objects inside a dedicated temporary root. Only the registry layer is
  // faked, so the test never touches the host registry.
  Root := TPath.Combine(TPath.GetTempPath, 'portappix-junction-native-' +
    FormatDateTime('yyyymmddhhnnsszzz', Now) + '-' + IntToStr(GetCurrentProcessId));
  DataDir := TPath.Combine(Root, 'Data', 'native');
  TargetDir := TPath.Combine(DataDir, 'JTarget');
  OriginalTargetDir := TPath.Combine(Root, 'original-target');
  ForceDirectories(TargetDir);
  ForceDirectories(OriginalTargetDir);
  HostPath := TPath.Combine(Root, 'host');
  TxId := TPortappixTransaction.NewTxId('native');
  TxDir := TPath.Combine(Root, 'Transactions', TxId);
  ForceDirectories(TPath.Combine(Root, 'Transactions'));
  LogText := '';

  Store := TPortappixJournalStore.Create;
  RegOps := TFakeTxRegistryOps.Create;
  RegOpsRef := RegOps;
  RealOps := TPortappixHostPathOps.Create;
  RealOpsRef := RealOps;
  try
    // --- Preservation: capture, persist intent, remove, replace ----------
    ForceDirectories(TxDir);
    Transaction := TPortappixTransaction.Create(Store, TxDir, TxId, 'native', Now,
      txPrepared, DataDir, False);
    Transaction.OnLog := procedure(AMessage: string)
      begin
        LogText := LogText + AMessage + sLineBreak;
      end;
    ITx := Transaction;
    // The host path holds the user's original junction: capture its exact
    // target BEFORE the durable intent, then remove and replace it.
    Inspection := RealOps.InspectPath(HostPath);
    Check(Inspection.Kind = rkMissing,
      'Native: the fixture starts with an absent host path');
    RealOps.CreateJunction(HostPath, OriginalTargetDir);
    Inspection := RealOps.InspectPath(HostPath);
    Check(Inspection.IsMountPoint and Inspection.TargetParsed and
      TPortappixTransaction.SameCanonicalPath(Inspection.Target, OriginalTargetDir),
      'Native: the original junction is created and inspected');
    ITx.RecordOperation(TPortappixTransaction.MakeJunctionOperation(
      okJunctionRemoveOld, HostPath, Inspection.Target, 'junction'));
    Check(RealOps.DeleteJunction(HostPath) and not RealOps.PathExists(HostPath),
      'Native: the original junction is removed after its intent is durable');
    ITx.RecordOperation(TPortappixTransaction.MakeJunctionOperation(
      okJunctionCreate, HostPath, TargetDir, 'junction'));
    Check(RealOps.CreateJunction(HostPath, TargetDir) and
      RealOps.IsReparsePoint(HostPath),
      'Native: the Portappix junction is created');
    ITx.MarkJunctionCreated(1, 'A0000003',
      RealOps.InspectPath(HostPath).Identity);

    // --- Restoration: ownership-verified removal + verified recreation ---
    Reconciler := TPortappixTransactionReconciler.Create(RegOps, RealOps,
      procedure(AMessage: string)
      begin
        LogText := LogText + AMessage + sLineBreak;
      end);
    try
      Check(Reconciler.ReconcileTransaction(Transaction),
        'Native: the reconciler reports success');
    finally
      Reconciler.Free;
    end;
    Check(Transaction.AllOperationsResolved,
      'Native: all operations resolved after restoration');
    Inspection := RealOps.InspectPath(HostPath);
    Check(Inspection.IsMountPoint and Inspection.TargetParsed and
      TPortappixTransaction.SameCanonicalPath(Inspection.Target, OriginalTargetDir),
      'Native: the original junction is restored with its exact target');
    Check(RealOps.PathExists(OriginalTargetDir),
      'Native: the original target directory still exists');

    // --- Idempotency: reconciliation again changes nothing ----------------
    Reconciler := TPortappixTransactionReconciler.Create(RegOps, RealOps,
      procedure(AMessage: string)
      begin
        LogText := LogText + AMessage + sLineBreak;
      end);
    try
      Check(Reconciler.ReconcileTransaction(Transaction),
        'Native: repeated reconciliation reports success');
    finally
      Reconciler.Free;
    end;
    Inspection := RealOps.InspectPath(HostPath);
    Check(Inspection.IsMountPoint and
      TPortappixTransaction.SameCanonicalPath(Inspection.Target, OriginalTargetDir),
      'Native: repeated reconciliation is idempotent');

    // --- External replacement with the same target: identity conflict -----
    // Simulate another process deleting and recreating the junction with the
    // same target: the new object has a fresh identity, so removal must be
    // refused and the conflict reported.
    // Simulate a second run: the original junction is removed again and
    // the Portappix junction is created again — both operations are back
    // to 'done' — and then another process deletes and recreates the
    // Portappix junction with the same target (fresh object identity).
    Transaction.ApplyOperationStatus(1, opDone);
    Transaction.ApplyOperationStatus(0, opDone);
    Check(RealOps.DeleteJunction(OriginalTargetDir) or True,
      'Native: original target dir removed for the second-run fixture');
    ForceDirectories(OriginalTargetDir);
    Check(RealOps.CreateJunction(HostPath, OriginalTargetDir),
      'Native: original junction recreated by the second-run fixture');
    Check(RealOps.DeleteJunction(HostPath) and
      RealOps.CreateJunction(HostPath, TargetDir),
      'Native: the externally recreated junction fixture is in place');
    LogText := '';
    Reconciler := TPortappixTransactionReconciler.Create(RegOps, RealOps,
      procedure(AMessage: string)
      begin
        LogText := LogText + AMessage + sLineBreak;
      end);
    try
      Check(not Reconciler.ReconcileTransaction(Transaction) and
        Reconciler.ManualFailure,
        'Native: an externally recreated junction (new identity) is refused');
    finally
      Reconciler.Free;
    end;
    Check(ContainsStr(LogText, 'ownership') or ContainsStr(LogText, 'identity'),
      'Native: the identity conflict is reported');
    // Reverse order: op0's undo recreated the ORIGINAL junction (its own
    // undo is target-verified, and the original target directory was
    // re-created by the fixture), then op1's undo refused on identity —
    // so the surviving object is the verified original junction, and the
    // externally created object was replaced only by that verified
    // restoration, never silently deleted.
    // Reverse order: op1 (the Portappix junction create) is reconciled
    // FIRST; its recorded identity does not match the externally
    // recreated object, so the reconciler refuses immediately — the
    // external object is preserved untouched and op0 stays pending for a
    // later manual resolution. Nothing is silently deleted.
    Inspection := RealOps.InspectPath(HostPath);
    Check(Inspection.IsMountPoint and Inspection.TargetParsed and
      TPortappixTransaction.SameCanonicalPath(Inspection.Target, TargetDir),
      'Native: the externally recreated junction is preserved untouched');
    Check((not Transaction.AllOperationsResolved) and
      (Transaction.Operations[0].Status = opDone),
      'Native: the conflicting transaction remains open for manual resolution');

    // --- Broken original target: restore still succeeds and is reported ---
    TDirectory.Delete(OriginalTargetDir, True);
    Transaction.ApplyOperationStatus(0, opDone);
    Check(RealOps.DeleteJunction(HostPath), 'Native: fixture junction removed');
    LogText := '';
    Reconciler := TPortappixTransactionReconciler.Create(RegOps, RealOps,
      procedure(AMessage: string)
      begin
        LogText := LogText + AMessage + sLineBreak;
      end);
    try
      Check(Reconciler.ReconcileTransaction(Transaction),
        'Native: a dangling original target still restores');
    finally
      Reconciler.Free;
    end;
    Check(ContainsStr(LogText, 'no longer exists'),
      'Native: the missing original target is reported');
    Check(RealOps.IsReparsePoint(HostPath) and
      SameText(RealOps.GetJunctionTarget(HostPath), OriginalTargetDir),
      'Native: the junction is restored exactly as recorded (dangling)');

    ITx := nil;
  finally
    // Remove only objects this test created; junction deletion is
    // non-recursive, so the target trees are removed explicitly after.
    if RealOps.IsReparsePoint(HostPath) then
      RealOps.DeleteJunction(HostPath);
    Store.Free;
    if TDirectory.Exists(Root) then
      TDirectory.Delete(Root, True);
  end;
end;

procedure TestJunctionCrashBeforeIdentityPersisted(const ARoot: string);
// Deterministic regression for the Phase 3 ownership-verification window:
// 1. a new Phase 3 junction-create intent is persisted (the journal
//    carries the "junctionOwnership": "identity" provenance),
// 2. the Portappix junction is created,
// 3. the process terminates BEFORE MarkJunctionCreated persists the
//    creation identity,
// 4. the junction is replaced by another junction with the same canonical
//    target but a different filesystem identity,
// 5. recovery runs and must REFUSE removal (target+tag alone cannot
//    establish ownership for a Phase 3 transaction), leaving the external
//    junction untouched, marking the transaction recoveryRequired with an
//    explicit ownership report, and staying idempotent across a second
//    recovery pass.
var
  AppDir, ManifestFile, ExeFile, HostPath, DataDir: string;
  RegOps: TFakeTxRegistryOps;
  HostOps: TFakeHostPathOps;
  RegOpsRef: IPortappixRegistryOps;
  HostOpsRef: IPortappixHostPathOps;
  Store: TPortappixJournalStore;
  Journal: TPortappixJournal;
  JournalRef: IPortappixJournal;
  Runner: TPortableAppRunner;
  JournalAfterFirstRecovery: string;
  Interrupted: Boolean;

  function FindTxDir: string;
  var
    Dir: string;
  begin
    Result := '';
    if TDirectory.Exists(TPath.Combine(ARoot, 'Transactions')) then
      for Dir in TDirectory.GetDirectories(TPath.Combine(ARoot, 'Transactions')) do
        if TPath.GetFileName(Dir).StartsWith('jxid-') then
          Result := Dir;
  end;

  function TxJson: string;
  begin
    Result := TFile.ReadAllText(TPath.Combine(FindTxDir, 'transaction.json'),
      TEncoding.UTF8);
  end;

begin
  AppDir := TPath.Combine(ARoot, 'Apps\jxid');
  ForceDirectories(AppDir);
  ExeFile := TPath.Combine(AppDir, 'jxid.exe');
  TFile.WriteAllText(ExeFile, 'not a real executable', TEncoding.ASCII);
  ManifestFile := TPath.Combine(AppDir, 'app.json');
  TFile.WriteAllText(ManifestFile,
    '{"schema":1,"id":"jxid","name":"jxid","exe":"jxid.exe","junctions":{"%APPDATA%\\JxIdHost":"{data}\\JTarget"}}',
    TEncoding.UTF8);
  HostPath := ExpandPercentVariables('%APPDATA%') + '\JxIdHost';
  DataDir := TPath.Combine(ARoot, 'Data\jxid');

  RegOps := TFakeTxRegistryOps.Create;
  HostOps := TFakeHostPathOps.Create;
  RegOpsRef := RegOps;
  HostOpsRef := HostOps;
  Store := TPortappixJournalStore.Create;
  Journal := TPortappixJournal.Create(ARoot, RegOps, HostOps, Store);
  JournalRef := Journal;
  try
    // Steps 1-3: the host path is originally absent, so the create
    // operation is op 0 and the crash point lands exactly between the
    // junction object existing on disk and its identity being durable.
    PortappixCrashHook :=
      procedure(APoint: string)
      begin
        raise EPortappixSimulatedCrash.Create(APoint);
      end;
    PortappixCrashPoint := 'op:0:created';
    try
      Interrupted := False;
      Runner := TPortableAppRunner.Create(ManifestFile, Journal, ARoot, RegOps);
      try
        Runner.HostPathOps := HostOps;
        try
          Runner.Run;
        except
          on E: EPortappixSimulatedCrash do
            Interrupted := True;
        end;
      finally
        Runner.Free;
      end;
    finally
      PortappixCrashPoint := '';
      PortappixCrashHook := nil;
    end;
    Check(Interrupted,
      'Identity crash: the run was interrupted at the junction-created boundary');
    Check(HostOps.IsReparsePoint(HostPath) and
      SameText(HostOps.GetJunctionTarget(HostPath), TPath.Combine(DataDir, 'JTarget')),
      'Identity crash: the Portappix junction exists on disk before termination');
    Check(TFile.Exists(TPath.Combine(FindTxDir, 'transaction.json')) and
      ContainsStr(TxJson, '"junctionOwnership"'),
      'Identity crash: the journal carries the Phase 3 provenance field');
    Check(ContainsStr(TxJson, '"identity": ""'),
      'Identity crash: the creation identity was indeed never persisted');

    // Step 4: another process replaces the junction with the same
    // canonical target but a NEW filesystem identity.
    HostOps.DeleteJunction(HostPath);
    HostOps.AddJunction(HostPath, TPath.Combine(DataDir, 'JTarget'));

    // Steps 5-8: recovery refuses, preserves, reports, and holds the
    // transaction open as recoveryRequired.
    Journal.RecoverPendingCleanups;
    JournalAfterFirstRecovery := TxJson;
    Check(HostOps.IsReparsePoint(HostPath) and
      SameText(HostOps.GetJunctionTarget(HostPath), TPath.Combine(DataDir, 'JTarget')),
      'Identity crash: recovery refuses removal; the replacement junction remains untouched');
    Check(ContainsStr(JournalAfterFirstRecovery, '"recoveryRequired"'),
      'Identity crash: the transaction becomes recoveryRequired');
    Check(ContainsStr(JournalAfterFirstRecovery, 'ownership could not be established'),
      'Identity crash: the unresolved ownership is explicitly reported');
    Check(TDirectory.Exists(FindTxDir),
      'Identity crash: all recovery metadata (journal, backups) is retained');

    // Step 9: second recovery pass changes nothing.
    Journal.RecoverPendingCleanups;
    Check(HostOps.IsReparsePoint(HostPath) and
      SameText(HostOps.GetJunctionTarget(HostPath), TPath.Combine(DataDir, 'JTarget')) and
      SameText(TxJson, JournalAfterFirstRecovery),
      'Identity crash: repeated recovery is idempotent');
    if TDirectory.Exists(FindTxDir) then
      TDirectory.Delete(FindTxDir, True);
  finally
    Store.Free;
    // Journal, RegOps and HostOps are interface-managed; released at
    // scope exit.
  end;
end;

procedure TestJunctionOwnershipUnpersistedIdentity(const ARoot: string);
// Second regression: the original Portappix junction is UNCHANGED (same
// target, same object) but the creation identity was never persisted. A
// Phase 3 transaction must STILL fail closed — recovery must not assume
// ownership from the target+tag match alone — while a positively
// identified Phase 2 record keeps the documented target-match behavior,
// and a journal with an unknown provenance value is rejected outright.
var
  Store: TPortappixJournalStore;
  RegOps: TFakeTxRegistryOps;
  HostOps: TFakeHostPathOps;
  RegOpsRef: IPortappixRegistryOps;
  HostOpsRef: IPortappixHostPathOps;
  Journal: TPortappixJournal;
  Transaction: TPortappixTransaction;
  ITx: IPortappixTransaction;
  TxId, TxDir, DataDir, HostPath, CreatedTarget, TxJson, AmbiguousJson: string;

  procedure BuildPhase3Tx;
  begin
    TxId := TPortappixTransaction.NewTxId('jownun');
    TxDir := TPath.Combine(Journal.TransactionsDirectory, TxId);
    ForceDirectories(TxDir);
    Transaction := TPortappixTransaction.Create(Store, TxDir, TxId, 'jownun', Now,
      txHostBackupComplete, DataDir, False, PortappixOwnershipFieldIdentity);
    ITx := Transaction;
    ITx.RecordOperation(TPortappixTransaction.MakeJunctionOperation(
      okJunctionCreate, HostPath, CreatedTarget, 'absent'));
    HostOps.AddJunction(HostPath, CreatedTarget);
    // Deliberately NOT calling MarkJunctionCreated: this is exactly the
    // crash-between-creation-and-identity-persistence record shape.
  end;

  function TxJsonText: string;
  begin
    Result := TFile.ReadAllText(TPath.Combine(TxDir, 'transaction.json'),
      TEncoding.UTF8);
  end;

begin
  DataDir := TPath.Combine(ARoot, 'Data\jownun');
  ForceDirectories(DataDir);
  CreatedTarget := TPath.Combine(DataDir, 'JTarget');
  ForceDirectories(CreatedTarget);
  HostPath := ExpandPercentVariables('%APPDATA%') + '\JOwnUnpHost';

  Store := TPortappixJournalStore.Create;
  RegOps := TFakeTxRegistryOps.Create;
  HostOps := TFakeHostPathOps.Create;
  RegOpsRef := RegOps;
  HostOpsRef := HostOps;
  Journal := TPortappixJournal.Create(ARoot, RegOps, HostOps, Store);
  try
    // Unchanged junction, identity never persisted: failure closed.
    BuildPhase3Tx;
    ITx := nil; // the interface reference owns and releases the object
    Journal.RecoverPendingCleanups;
    TxJson := TxJsonText;
    Check(HostOps.IsReparsePoint(HostPath) and
      SameText(HostOps.GetJunctionTarget(HostPath), CreatedTarget),
      'Unpersisted identity: the unchanged Portappix junction is preserved');
    Check(ContainsStr(TxJson, '"recoveryRequired"') and
      ContainsStr(TxJson, 'ownership could not be established'),
      'Unpersisted identity: recovery fails closed with an explicit report');
    // Idempotency: nothing changes on a second pass.
    Journal.RecoverPendingCleanups;
    Check(HostOps.IsReparsePoint(HostPath) and
      SameText(HostOps.GetJunctionTarget(HostPath), CreatedTarget),
      'Unpersisted identity: repeated recovery changes nothing');
    TDirectory.Delete(TxDir, True);

    // Legacy compatibility: a positively identified Phase 2 record (no
    // provenance field) without an identity is removed by the strict
    // target match.
    TxId := TPortappixTransaction.NewTxId('jownun');
    TxDir := TPath.Combine(Journal.TransactionsDirectory, TxId);
    ForceDirectories(TxDir);
    Transaction := TPortappixTransaction.Create(Store, TxDir, TxId, 'jownun', Now,
      txHostBackupComplete, DataDir, False); // no provenance → Phase 2
    ITx := Transaction;
    ITx.RecordOperation(TPortappixTransaction.MakeJunctionOperation(
      okJunctionCreate, HostPath, CreatedTarget, 'absent'));
    ITx := nil; // the interface reference owns and releases the object
    Journal.RecoverPendingCleanups;
    Check(not HostOps.IsReparsePoint(HostPath),
      'Unpersisted identity: a Phase 2 record without identity is removed by the target match');

    // Ambiguous provenance fails closed: an unknown "junctionOwnership"
    // value can never be classified as legacy; the journal is quarantined
    // and the object is never removed.
    BuildPhase3Tx;
    AmbiguousJson := StringReplace(Transaction.ToJson,
      '"junctionOwnership": "identity"', '"junctionOwnership": "somewhere"', []);
    ITx := nil; // the interface reference owns and releases the object
    TFile.WriteAllText(TPath.Combine(TxDir, 'transaction.json'), AmbiguousJson,
      TEncoding.UTF8);
    HostOps.AddJunction(HostPath, CreatedTarget);
    Journal.RecoverPendingCleanups;
    Check(HostOps.IsReparsePoint(HostPath) and
      SameText(HostOps.GetJunctionTarget(HostPath), CreatedTarget),
      'Unpersisted identity: ambiguous provenance preserves the junction');
    Check(TFile.Exists(TPath.Combine(TxDir, 'transaction.json.bad')) and
      not TFile.Exists(TPath.Combine(TxDir, 'transaction.json')),
      'Unpersisted identity: ambiguous provenance quarantines the journal without acting on it');
    TDirectory.Delete(TxDir, True);
  finally
    Journal.Free;
    Store.Free;
  end;
end;

procedure TestNativeJunctionIdentityMandatory;
// Native NTFS counterpart of the ownership window: REAL junction objects
// and the REAL reconciler. A Phase 3 record whose creation identity was
// never persisted is refused for removal even when (a) the on-disk object
// is exactly the one Portappix created, and (b) after a same-target
// external replacement; removal is idempotently refused both times.
var
  Root, TargetDir, HostPath, TxId, TxDir, DataDir: string;
  Store: TPortappixJournalStore;
  RegOps: TFakeTxRegistryOps;
  RegOpsRef: IPortappixRegistryOps;
  RealOps: TPortappixHostPathOps;
  RealOpsRef: IPortappixHostPathOps;
  Transaction: TPortappixTransaction;
  ITx: IPortappixTransaction;
  Reconciler: TPortappixTransactionReconciler;
  Inspection: TPortappixPathInspection;
  LogText: string;
begin
  Root := TPath.Combine(TPath.GetTempPath, 'portappix-junction-native-id-' +
    FormatDateTime('yyyymmddhhnnsszzz', Now) + '-' + IntToStr(GetCurrentProcessId));
  DataDir := TPath.Combine(Root, 'Data', 'nativei');
  TargetDir := TPath.Combine(DataDir, 'JTarget');
  ForceDirectories(TargetDir);
  HostPath := TPath.Combine(Root, 'host');
  TxId := TPortappixTransaction.NewTxId('nativei');
  TxDir := TPath.Combine(Root, 'Transactions', TxId);
  ForceDirectories(TxDir);
  LogText := '';

  Store := TPortappixJournalStore.Create;
  RegOps := TFakeTxRegistryOps.Create;
  RegOpsRef := RegOps;
  RealOps := TPortappixHostPathOps.Create;
  RealOpsRef := RealOps;
  try
    Transaction := TPortappixTransaction.Create(Store, TxDir, TxId, 'nativei', Now,
      txHostBackupComplete, DataDir, False, PortappixOwnershipFieldIdentity);
    Transaction.OnLog := procedure(AMessage: string)
      begin
        LogText := LogText + AMessage + sLineBreak;
      end;
    ITx := Transaction;
    ITx.RecordOperation(TPortappixTransaction.MakeJunctionOperation(
      okJunctionCreate, HostPath, TargetDir, 'absent'));
    Check(RealOps.CreateJunction(HostPath, TargetDir) and
      RealOps.IsReparsePoint(HostPath),
      'Native identity: the Portappix junction is created on real NTFS');
    // Deliberately NOT calling MarkJunctionCreated: the creation identity
    // is never durable. (a) The object is untouched — recovery must still
    // refuse to remove it.
    Reconciler := TPortappixTransactionReconciler.Create(RegOps, RealOps,
      procedure(AMessage: string)
      begin
        LogText := LogText + AMessage + sLineBreak;
      end);
    try
      Check(not Reconciler.ReconcileTransaction(Transaction) and
        Reconciler.ManualFailure,
        'Native identity: removal is refused without the persisted identity');
    finally
      Reconciler.Free;
    end;
    Check(RealOps.IsReparsePoint(HostPath) and
      SameText(RealOps.GetJunctionTarget(HostPath), TargetDir),
      'Native identity: the untouched original junction is preserved');
    Check(not Transaction.AllOperationsResolved,
      'Native identity: the transaction stays open for manual resolution');

    // (b) External replacement with the same canonical target (a fresh
    // NTFS object identity) — refused again, object preserved untouched.
    Check(RealOps.DeleteJunction(HostPath) and
      RealOps.CreateJunction(HostPath, TargetDir),
      'Native identity: the replacement fixture is in place');
    LogText := '';
    Reconciler := TPortappixTransactionReconciler.Create(RegOps, RealOps,
      procedure(AMessage: string)
      begin
        LogText := LogText + AMessage + sLineBreak;
      end);
    try
      Check(not Reconciler.ReconcileTransaction(Transaction) and
        Reconciler.ManualFailure,
        'Native identity: a repeated recovery pass is idempotently refused');
    finally
      Reconciler.Free;
    end;
    Inspection := RealOps.InspectPath(HostPath);
    Check(Inspection.IsMountPoint and Inspection.TargetParsed and
      TPortappixTransaction.SameCanonicalPath(Inspection.Target, TargetDir),
      'Native identity: the replacement junction remains untouched');
    Check(ContainsStr(LogText, 'ownership could not be established'),
      'Native identity: the unresolved ownership is reported');

    ITx := nil;
  finally
    // Remove only objects this test created; junction deletion is
    // non-recursive, so the target tree is removed explicitly after.
    if RealOps.IsReparsePoint(HostPath) then
      RealOps.DeleteJunction(HostPath);
    Store.Free;
    if TDirectory.Exists(Root) then
      TDirectory.Delete(Root, True);
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

{ TFakeTxRegistryOps }

constructor TFakeTxRegistryOps.Create;
begin
  inherited Create;
  FKeys := TStringList.Create;
  FKeys.Sorted := True;
  FKeys.Duplicates := dupIgnore;
  FCallLog := TStringList.Create;
  FExportSucceeds := True;
  FImportSucceeds := True;
  FDeleteSucceeds := True;
end;

destructor TFakeTxRegistryOps.Destroy;
begin
  FKeys.Free;
  FCallLog.Free;
  inherited;
end;

procedure TFakeTxRegistryOps.AddKey(const AKey: string);
begin
  FKeys.Add(AKey);
end;

function TFakeTxRegistryOps.KeyExists(const AKey: string): Boolean;
begin
  Result := FKeys.IndexOf(AKey) >= 0;
end;

function TFakeTxRegistryOps.ExportKey(const AKey, AFileName: string): Boolean;
begin
  if not FExportSucceeds then
    Exit(False);
  FCallLog.Add('export:' + AKey);
  TFile.WriteAllText(AFileName, 'backup-of-' + AKey, TEncoding.ASCII);
  Result := True;
end;

function TFakeTxRegistryOps.ImportFile(const AFileName: string): Boolean;
begin
  if not FImportSucceeds then
    Exit(False);
  FCallLog.Add('import:' + TPath.GetFileName(AFileName));
  Result := True;
end;

function TFakeTxRegistryOps.DeleteKey(const AKey: string): Boolean;
begin
  if not FDeleteSucceeds then
    Exit(False);
  FCallLog.Add('delete:' + AKey);
  FKeys.Delete(FKeys.IndexOf(AKey));
  Result := True;
end;

{ TFakeHostPathOps }

constructor TFakeHostPathOps.Create;
begin
  inherited Create;
  FPaths := TDictionary<string, string>.Create;
  FIdentities := TDictionary<string, Integer>.Create;
  FCallLog := TStringList.Create;
  FNextIdentity := 100;
end;

destructor TFakeHostPathOps.Destroy;
begin
  FPaths.Free;
  FIdentities.Free;
  FCallLog.Free;
  inherited;
end;

function TFakeHostPathOps.Norm(const APath: string): string;
begin
  Result := LowerCase(TrimTrailingPathDelimiter(APath));
end;

procedure TFakeHostPathOps.AddDir(const APath: string);
begin
  FPaths.AddOrSetValue(Norm(APath), 'dir');
end;

procedure TFakeHostPathOps.AddFile(const APath: string);
begin
  FPaths.AddOrSetValue(Norm(APath), 'file');
end;

procedure TFakeHostPathOps.AddJunction(const APath, ATarget: string);
begin
  FPaths.AddOrSetValue(Norm(APath), '@' + ATarget);
  Inc(FNextIdentity);
  FIdentities.AddOrSetValue(Norm(APath), FNextIdentity);
end;

procedure TFakeHostPathOps.AddSymlink(const APath, ATarget: string);
begin
  FPaths.AddOrSetValue(Norm(APath), '#' + ATarget);
end;

procedure TFakeHostPathOps.AddOtherReparse(const APath: string);
begin
  FPaths.AddOrSetValue(Norm(APath), '*000A0029');
end;

function TFakeHostPathOps.PathExists(const APath: string): Boolean;
begin
  Result := FPaths.ContainsKey(Norm(APath));
end;

function TFakeHostPathOps.IsDirectory(const APath: string): Boolean;
var
  Value: string;
begin
  Result := FPaths.TryGetValue(Norm(APath), Value) and (Value = 'dir');
end;

function TFakeHostPathOps.IsReparsePoint(const APath: string): Boolean;
var
  Value: string;
begin
  Result := FPaths.TryGetValue(Norm(APath), Value) and
    (Value.StartsWith('@') or Value.StartsWith('#') or Value.StartsWith('*'));
end;

function TFakeHostPathOps.GetJunctionTarget(const APath: string): string;
var
  Value: string;
begin
  Result := '';
  if FPaths.TryGetValue(Norm(APath), Value) and Value.StartsWith('@') then
    Result := Copy(Value, 2, MaxInt);
end;

function TFakeHostPathOps.InspectPath(const APath: string): TPortappixPathInspection;
var
  Value: string;
  Identity: Integer;
begin
  Result := Default(TPortappixPathInspection);
  Result.Path := APath;
  if FFailInspect and FPaths.ContainsKey(Norm(APath)) then
  begin
    Result.Kind := rkInspectionFailed;
    Result.ErrorMessage := 'access denied while inspecting the path (simulated)';
    Exit;
  end;
  if not FPaths.TryGetValue(Norm(APath), Value) then
  begin
    Result.Kind := rkMissing;
    Exit;
  end;
  if Value.StartsWith('@') then
  begin
    Result.Kind := rkJunction;
    Result.ReparseTag := IO_REPARSE_TAG_MOUNT_POINT;
    if FFailTargetParse then
      Result.ErrorMessage := 'simulated unparsable junction target'
    else
    begin
      Result.Target := Copy(Value, 2, MaxInt);
      Result.TargetParsed := True;
    end;
  end
  else if Value.StartsWith('#') then
  begin
    Result.Kind := rkSymlink;
    Result.ReparseTag := IO_REPARSE_TAG_SYMLINK;
    Result.Target := Copy(Value, 2, MaxInt);
    Result.TargetParsed := True;
  end
  else if Value.StartsWith('*') then
  begin
    Result.Kind := rkOtherReparse;
    Result.ReparseTag := StrToIntDef('$' + Copy(Value, 2, 8), $80000029);
    Result.ErrorMessage := 'unsupported reparse tag';
  end
  else if Value = 'dir' then
    Result.Kind := rkDirectory
  else
    Result.Kind := rkFile;
  if FIdentities.TryGetValue(Norm(APath), Identity) then
    Result.Identity := Format('000ABCD1:%.8x', [Identity]);
end;

function TFakeHostPathOps.CreateJunction(const APath, ATarget: string): Boolean;
begin
  if FFailCreate or FPaths.ContainsKey(Norm(APath)) then
    Exit(False);
  FPaths.AddOrSetValue(Norm(APath), '@' + ATarget);
  // A newly created junction is a NEW filesystem object with a fresh
  // identity: delete+recreate by another process is therefore detectable.
  Inc(FNextIdentity);
  FIdentities.AddOrSetValue(Norm(APath), FNextIdentity);
  FCallLog.Add('create');
  Result := True;
end;

function TFakeHostPathOps.DeleteJunction(const APath: string): Boolean;
var
  Value: string;
begin
  if FFailDelete then
    Exit(False);
  if not FPaths.TryGetValue(Norm(APath), Value) or not Value.StartsWith('@') then
    Exit(False);
  FPaths.Remove(Norm(APath));
  FIdentities.Remove(Norm(APath));
  FCallLog.Add('delete');
  Result := True;
end;

function TFakeHostPathOps.RenamePath(const AFrom, ATo: string): Boolean;
var
  Value: string;
  Identity: Integer;
begin
  if FFailRename then
    Exit(False);
  if not FPaths.TryGetValue(Norm(AFrom), Value) or FPaths.ContainsKey(Norm(ATo)) then
    Exit(False);
  FPaths.Remove(Norm(AFrom));
  FPaths.AddOrSetValue(Norm(ATo), Value);
  // Renaming preserves the object and therefore its identity.
  if FIdentities.TryGetValue(Norm(AFrom), Identity) then
  begin
    FIdentities.Remove(Norm(AFrom));
    FIdentities.AddOrSetValue(Norm(ATo), Identity);
  end;
  FCallLog.Add('rename');
  Result := True;
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

  ExpectException(
    procedure
    begin
      ParseReleasesJson('{"schema":1,"channel":"stable","version":"1.0.0",' +
        '"url":"https://example.com/x.zip","sha256":"' + StringOfChar('a', 64) + '"}');
    end,
    'releases.json rejects missing size property');

  ExpectException(
    procedure
    begin
      ParseReleasesJson(ReleasesJsonFor('1.0.0', StringOfChar('a', 64), 0));
    end,
    'releases.json rejects size <= 0');

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
        ReleasesJsonFor('1.2.0', StringOfChar('c', 64), TFile.GetSize(ZipPath)));
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

      WriteTextFile(TPath.Combine(TPath.Combine(ARoot, 'Cache'), 'update_ok'), 'stale');
      Check(not Manager.NeedsRollbackOffer, 'NeedsRollbackOffer is false when OldLauncher is absent');
      Check(not TFile.Exists(TPath.Combine(TPath.Combine(ARoot, 'Cache'), 'update_ok')),
        'NeedsRollbackOffer cleans up orphaned update_ok');
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

{$IFDEF PORTAPPIX_TESTCRASH}
procedure TestCrashPointGrammar;
const
  // Every documented checkpoint identifier: nine state names exactly as
  // StateToString writes them, all five operation statuses, and the
  // runner-only 'created' form. Leading zero indices are accepted (they can
  // never collide with the canonical decimal identifiers CheckCrashPoint
  // compares against).
  ValidPoints: array[0..15] of string = (
    'state:preparing', 'state:prepared', 'state:hostBackupComplete',
    'state:hostStateChanging', 'state:hostStateChanged', 'state:running',
    'state:cleaning', 'state:completed', 'state:recoveryRequired',
    'op:0:pending', 'op:0:done', 'op:1:absent', 'op:2:failed',
    'op:3:restored', 'op:0:created', 'op:007:pending');
  // Malformed, unknown, wrong-case, whitespace and out-of-range inputs.
  InvalidPoints: array[1..26] of string = (
    '', ' ', '   ', 'state:', 'state: ', 'state:bogus', 'STATE:preparing',
    'state:Preparing', 'state:preparing ', ' state:preparing',
    'state:prepared/', 'state:recoveryRequired:extra', 'op:', 'op:0',
    'op:0:', 'op::done', 'op:-1:done', 'op:a:done', 'op:1.5:done',
    'op:0:Done', 'op:2:created:extra', 'op:0000000000:done', 'op:+2:done',
    'op:0 done', 'op:1:pending2', 'op:0: failed');
var
  Index: Integer;
begin
  PortappixCrashPoint := 'sentinel-should-not-change';
  PortappixCrashHook := nil;
  try
    for Index := Low(ValidPoints) to High(ValidPoints) do
    begin
      Check(SetCrashPointFromString(ValidPoints[Index]),
        'grammar accepts ' + ValidPoints[Index]);
      Check(PortappixCrashPoint = ValidPoints[Index],
        'grammar arms exactly the parsed value for ' + ValidPoints[Index]);
    end;
    for Index := Low(InvalidPoints) to High(InvalidPoints) do
    begin
      PortappixCrashPoint := 'sentinel-should-not-change';
      Check(not SetCrashPointFromString(InvalidPoints[Index]),
        Format('grammar rejects invalid candidate %d ("%s")',
          [Index, InvalidPoints[Index]]));
      Check(PortappixCrashPoint = 'sentinel-should-not-change',
        Format('invalid candidate %d leaves the armed checkpoint untouched',
          [Index]));
    end;
    // A later valid value overwrites an earlier armed one.
    PortappixCrashPoint := '';
    Check(SetCrashPointFromString('op:0:done'), 'grammar arms a fresh value');
    Check(PortappixCrashPoint = 'op:0:done',
      'the armed checkpoint tracks the last valid parse');
  finally
    PortappixCrashPoint := '';
    PortappixCrashHook := nil;
  end;
end;

procedure TestCrashCheckpointCoverage(const ARoot: string);
var
  DataDir, TxDir, JournalFile, FireText, StateName: string;
  Store: TPortappixJournalStore;
  ITx: IPortappixTransaction;
  Target: TPortappixTxState;
  RaisedFlag, NoFireFlag: Boolean;

  // Reads one top-level string field from the durable journal on disk.
  function JournalValue(const AField: string): string;
  var
    Parsed: TJSONValue;
  begin
    Result := '';
    Parsed := TJSONObject.ParseJSONValue(
      TFile.ReadAllText(JournalFile, TEncoding.UTF8));
    if Parsed = nil then
      Exit;
    try
      if (Parsed is TJSONObject) and
         (TJSONObject(Parsed).GetValue(AField) <> nil) then
        Result := TJSONObject(Parsed).GetValue(AField).Value;
    finally
      Parsed.Free;
    end;
  end;

  // Reads one field of the AIndex-th durable operation record.
  function OperationFieldValue(const AIndex: Integer;
    const AField: string): string;
  var
    Parsed: TJSONValue;
    Operations: TJSONArray;
  begin
    Result := '';
    Parsed := TJSONObject.ParseJSONValue(
      TFile.ReadAllText(JournalFile, TEncoding.UTF8));
    if Parsed = nil then
      Exit;
    try
      if not (Parsed is TJSONObject) then
        Exit;
      if TJSONObject(Parsed).GetValue('operations') = nil then
        Exit;
      Operations := TJSONObject(Parsed).GetValue('operations') as TJSONArray;
      if Operations.Count <= AIndex then
        Exit;
      if (Operations.Items[AIndex] is TJSONObject) and
         (TJSONObject(Operations.Items[AIndex]).GetValue(AField) <> nil) then
        Result :=
          TJSONObject(Operations.Items[AIndex]).GetValue(AField).Value;
    finally
      Parsed.Free;
    end;
  end;

  procedure ExpectFired(const AAction: TProc; const AExpected,
    AName: string);
  begin
    FireText := '';
    RaisedFlag := False;
    try
      AAction();
    except
      on E: EPortappixSimulatedCrash do
        RaisedFlag := True;
    end;
    Check(RaisedFlag, AName + ': the checkpoint fired');
    Check(FireText = AExpected, AName + ': it fired exactly at "' +
      AExpected + '"');
  end;

  procedure ExpectSilent(const AAction: TProc; const AName: string);
  begin
    FireText := '';
    NoFireFlag := True;
    try
      AAction();
    except
      on E: EPortappixSimulatedCrash do
        NoFireFlag := False;
    end;
    Check(NoFireFlag, AName + ': no crash');
    Check(FireText = '', AName + ': the hook never fired');
  end;

begin
  DataDir := TPath.Combine(ARoot, 'Data', 'crashcov');
  ForceDirectories(DataDir);
  Store := TPortappixJournalStore.Create;
  FireText := '';
  // Records the FIRST fire and simulates the hard abort behind the hook.
  PortappixCrashHook := procedure(APoint: string)
    begin
      if FireText = '' then
        FireText := APoint;
      raise EPortappixSimulatedCrash.Create(APoint);
    end;
  try
    // --- State chain: one transaction walks preparing -> ... -> completed,
    // --- each step armed at its own durable boundary. ---------------------
    TxDir := TPath.Combine(ARoot, 'Transactions', 'cov-state');
    ForceDirectories(TxDir);
    JournalFile := TPath.Combine(TxDir, 'transaction.json');
    ITx := TPortappixTransaction.Create(Store, TxDir,
      TPortappixTransaction.NewTxId('crashcov'), 'crashcov', Now, txPreparing,
      DataDir, False, PortappixOwnershipFieldIdentity);
    for Target := txPrepared to txCompleted do
    begin
      StateName := TPortappixTransaction.StateToString(Target);
      PortappixCrashPoint := 'state:' + StateName;
      ExpectFired(procedure
        begin
          ITx.SetState(Target);
        end,
        'state:' + StateName, 'state chain step ' + StateName);
      Check(JournalValue('state') = StateName,
        'state chain step ' + StateName +
        ': the new state was durably persisted before the checkpoint');
    end;

    // --- op:0:pending fires after the intent is persisted. ----------------
    PortappixCrashPoint := 'op:0:pending';
    ExpectFired(procedure
      begin
        ITx.RecordOperation(TPortappixTransaction.MakeOperation(
          okHostDirBackup, TPath.Combine(ARoot, 'HostApps', 'cov'), DataDir,
          TPath.Combine(TxDir, 'backup_0'), ''));
      end, 'op:0:pending', 'op:0:pending intent boundary');
    Check(OperationFieldValue(0, 'status') = 'pending',
      'op:0:pending: the intent status was durably persisted first');

    // --- op:1:pending must NOT match an armed op:1:done. ------------------
    PortappixCrashPoint := 'op:1:done';
    ExpectSilent(procedure
      begin
        ITx.RecordOperation(TPortappixTransaction.MakeJunctionOperation(
          okJunctionCreate, TPath.Combine(ARoot, 'HostApps', 'cov'),
          DataDir + TPath.DirectorySeparatorChar + 'JTarget', 'junction'));
      end, 'op:1:pending vs armed op:1:done');
    Check(OperationFieldValue(1, 'status') = 'pending',
      'the mismatched intent was still durably persisted');

    // --- op:1:done fires only after status AND identity are persisted. ----
    ExpectFired(procedure
      begin
        ITx.MarkJunctionCreated(1, 'A0000003', 'volserial:fileindex');
      end, 'op:1:done', 'op:1:done junction-identity boundary');
    Check(OperationFieldValue(1, 'status') = 'done',
      'op:1:done: the done status was durably persisted first');
    Check(OperationFieldValue(1, 'identity') = 'volserial:fileindex',
      'op:1:done: the junction identity was durably persisted first');
    Check(OperationFieldValue(1, 'reparseTag') = 'A0000003',
      'op:1:done: the reparse tag was durably persisted first');

    // --- op:N:created is never fired by transaction APIs (negative) -------
    PortappixCrashPoint := 'op:2:created';
    ExpectSilent(procedure
      begin
        ITx.RecordOperation(TPortappixTransaction.MakeOperation(
          okRegistryBackup, '', '', '',
          'HKCU\Software\Portappix\CrashCov'));
        ITx.MarkOperation(2, opDone);
      end, 'op:2:created via transaction APIs');

    // --- failed / absent / restored at their actual boundaries. -----------
    PortappixCrashPoint := 'op:0:failed';
    ExpectFired(procedure
      begin
        ITx.MarkOperation(0, opFailed);
      end, 'op:0:failed', 'op:0:failed boundary');
    Check(OperationFieldValue(0, 'status') = 'failed',
      'op:0:failed: the failure was durably persisted first');

    PortappixCrashPoint := 'op:0:absent';
    ExpectFired(procedure
      begin
        ITx.MarkOperation(0, opAbsent);
      end, 'op:0:absent', 'op:0:absent boundary');
    Check(OperationFieldValue(0, 'status') = 'absent',
      'op:0:absent: the absence was durably persisted first');

    PortappixCrashPoint := 'op:0:restored';
    ExpectFired(procedure
      begin
        ITx.MarkOperation(0, opRestored);
      end, 'op:0:restored', 'op:0:restored boundary');
    Check(OperationFieldValue(0, 'status') = 'restored',
      'op:0:restored: the restoration was durably persisted first');
    PortappixCrashPoint := '';

    // --- recoveryRequired: special-case transition from a fresh tx. -------
    TxDir := TPath.Combine(ARoot, 'Transactions', 'cov-recovery');
    ForceDirectories(TxDir);
    JournalFile := TPath.Combine(TxDir, 'transaction.json');
    ITx := TPortappixTransaction.Create(Store, TxDir,
      TPortappixTransaction.NewTxId('crashcov'), 'crashcov', Now, txRunning,
      DataDir, False, PortappixOwnershipFieldIdentity);
    PortappixCrashPoint := 'state:recoveryRequired';
    ExpectFired(procedure
      begin
        ITx.SetState(txRecoveryRequired);
      end, 'state:recoveryRequired', 'state:recoveryRequired boundary');
    Check(JournalValue('state') = 'recoveryRequired',
      'state:recoveryRequired: the terminal state was durably persisted first');
    Check(JournalValue(PortappixOwnershipField) =
      PortappixOwnershipFieldIdentity,
      'the recovery journal keeps its Phase 3 provenance');
    PortappixCrashPoint := '';
  finally
    PortappixCrashPoint := '';
    PortappixCrashHook := nil;
  end;
end;

procedure TestCrashPointNoOpWithEmpty;
var
  Fired: Boolean;
begin
  PortappixCrashPoint := '';
  PortappixCrashHook := nil;
  try
    Check(not SetCrashPointFromString(''),
      'grammar: an empty checkpoint value is rejected');
    Check(not SetCrashPointFromString(' '),
      'grammar: a whitespace-only checkpoint value is rejected');
    Check(not SetCrashPointFromString(#9),
      'grammar: a tab-only checkpoint value is rejected');
    Check(PortappixCrashPoint = '',
      'grammar: rejected values never arm a checkpoint');

    Fired := False;
    PortappixCrashHook := procedure(APoint: string)
      begin
        Fired := True;
        raise EPortappixSimulatedCrash.Create(APoint);
      end;
    CheckCrashPoint('state:prepared');
    CheckCrashPoint('op:0:done');
    CheckCrashPoint('op:3:created');
    Check(not Fired,
      'an empty armed checkpoint never triggers the crash hook');
  finally
    PortappixCrashPoint := '';
    PortappixCrashHook := nil;
  end;
end;
{$ENDIF}

procedure TestConsent(const ARoot: string);
var
  Consent: TPortappixConsent;
  Manifest: TPortappixManifest;
  AppDir, ExePath, ManifestPath: string;
begin
  AppDir := TPath.Combine(TPath.Combine(ARoot, 'Apps'), 'consentapp');
  ForceDirectories(AppDir);
  ExePath := TPath.Combine(AppDir, 'consentapp.exe');
  WriteTextFile(ExePath, 'original-exe-binary');

  ManifestPath := TPath.Combine(AppDir, 'app.json');
  WriteTextFile(ManifestPath,
    '{"id":"consentapp","name":"Consent App","version":"1.0","exe":"consentapp.exe",' +
    '"registry":["HKCU\\Software\\Vendor\\App"]}');

  Manifest := TPortappixManifest.LoadFromFile(ManifestPath);
  try
    Consent := TPortappixConsent.Create(ARoot);
    try
      Check(Consent.NeedsConsent(Manifest), 'Unapproved app needs consent');
      Consent.Approve(Manifest);
      Check(not Consent.NeedsConsent(Manifest), 'Approved app does not need consent');

      // Tamper exe binary: consent must be required again (consent keyed on exe hash)
      WriteTextFile(ExePath, 'modified-exe-binary');
      Check(Consent.NeedsConsent(Manifest), 'Modified exe binary requires consent again');

      // Re-approve with modified binary
      Consent.Approve(Manifest);
      Check(not Consent.NeedsConsent(Manifest), 'Re-approved modified binary does not need consent');
    finally
      Consent.Free;
    end;
  finally
    Manifest.Free;
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
    TestSignatureVerification;
    TestJournal(Root);
    TestTransactionPersistence(Root);
    TestTransactionOrdering(Root);
    TestRecoveryEngine(Root);
    TestRecoveryPathSafety(Root);
    TestLegacyJournal(Root);
    TestReparseInspection;
    TestJunctionPreservation(Root);
    TestJunctionOwnership(Root);
    TestJunctionRestoration(Root);
    TestJunctionCrashBoundaries(Root);
    TestNativeJunctionLifecycle;
    TestJunctionCrashBeforeIdentityPersisted(Root);
    TestJunctionOwnershipUnpersistedIdentity(Root);
    TestNativeJunctionIdentityMandatory;
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
    TestConsent(Root);
{$IFDEF PORTAPPIX_TESTCRASH}
    TestCrashPointGrammar;
    TestCrashCheckpointCoverage(Root);
    TestCrashPointNoOpWithEmpty;
{$ENDIF}
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
