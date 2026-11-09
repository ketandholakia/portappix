unit Portappix.PackageManager;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  System.Hash,
  System.Zip,
  System.Net.HttpClient,
  System.Net.URLClient,
  Portappix.Common,
  Portappix.Catalog,
  Portappix.Manifest,
  Portappix.Policy;

type
  EPortappixPackageError = class(Exception);

  TDownloadProgressEvent = reference to procedure(const AAppId: string;
    ASent, ATotal: Int64; var AAbort: Boolean);

  TPortappixPackageManager = class
  private
    FRootPath: string;
    FAppsDir: string;
    FCacheDir: string;
    FOnLog: TProc<string>;
    procedure Log(const AMessage: string);
    procedure EnsureDirectories;
    function CacheFile(const AppDef: TCatalogApp): string;
    procedure DownloadPackage(const AppDef: TCatalogApp; const ADestination: string;
      const AProgress: TDownloadProgressEvent);
    procedure VerifyPackage(const AppDef: TCatalogApp; const AFileName: string);
    procedure DeleteDirectoryQuiet(const ADirectory: string);
    procedure DeleteFileQuiet(const AFileName: string);
    procedure AtomicSwap(const ATempDir, AFinalDir: string);
    function SanitizeFileComponent(const AValue: string): string;
    procedure ValidateExtractedManifest(const AppDef: TCatalogApp; const ATempDir: string);
  public
    constructor Create(const ARootPath: string = '');
    procedure InstallApp(const AppDef: TCatalogApp; const AProgress: TDownloadProgressEvent = nil);
    procedure ExtractArchive(const AZipFile, ADestinationDir: string);
    class function ComputeSha256(const AFileName: string): string; static;
    property RootPath: string read FRootPath;
    property AppsDirectory: string read FAppsDir;
    property CacheDirectory: string read FCacheDir;
    property OnLog: TProc<string> read FOnLog write FOnLog;
  end;

implementation

const
  MaxZipEntries = 20000;
  MaxZipUncompressedBytes = Int64(2) * 1024 * 1024 * 1024;

constructor TPortappixPackageManager.Create(const ARootPath: string);
begin
  inherited Create;
  FRootPath := ResolveRootPath(ARootPath);
  FAppsDir := TPath.Combine(FRootPath, 'Apps');
  FCacheDir := TPath.Combine(FRootPath, 'Cache');
end;

procedure TPortappixPackageManager.Log(const AMessage: string);
begin
  if Assigned(FOnLog) then
    FOnLog(AMessage);
end;

procedure TPortappixPackageManager.EnsureDirectories;
begin
  ForceDirectories(FAppsDir);
  ForceDirectories(FCacheDir);
end;

function TPortappixPackageManager.SanitizeFileComponent(const AValue: string): string;
const
  InvalidCharacters: TSysCharSet = ['\', '/', ':', '*', '?', '"', '<', '>', '|'];
begin
  Result := AValue.Trim;
  for var Index := 1 to Length(Result) do
    if (Result[Index] < ' ') or CharInSet(Result[Index], InvalidCharacters) then
      Result[Index] := '_';
  if Result = '' then
    Result := 'package';
end;

function TPortappixPackageManager.CacheFile(const AppDef: TCatalogApp): string;
begin
  Result := TPath.Combine(FCacheDir,
    Format('%s_%s.zip', [SanitizeFileComponent(AppDef.Id), SanitizeFileComponent(AppDef.Version)]));
end;

procedure TPortappixPackageManager.DownloadPackage(const AppDef: TCatalogApp;
  const ADestination: string; const AProgress: TDownloadProgressEvent);
var
  Client: THTTPClient;
  Stream: TFileStream;
  Response: IHTTPResponse;
  TempDestination: string;
  Aborted: Boolean;
begin
  TempDestination := ADestination + '.download';
  if TFile.Exists(TempDestination) then
    TFile.Delete(TempDestination);

  Aborted := False;
  Stream := TFileStream.Create(TempDestination, fmCreate);
  Client := THTTPClient.Create;
  try
    Client.UserAgent := 'Portappix';
    Client.ReceiveDataCallback :=
      procedure(const Sender: TObject; AContentLength, AReadCount: Int64; var AAbort: Boolean)
      var
        ShouldAbort: Boolean;
      begin
        ShouldAbort := False;
        if Assigned(AProgress) then
          AProgress(AppDef.Id, AReadCount, AContentLength, ShouldAbort);
        AAbort := ShouldAbort;
        if ShouldAbort then
          Aborted := True;
      end;

    try
      Response := Client.Get(AppDef.Url, Stream);
    except
      on E: Exception do
      begin
        DeleteFileQuiet(TempDestination);
        if Aborted then
          raise EPortappixPackageError.CreateFmt('Download aborted for "%s".', [AppDef.Id]);
        raise EPortappixPackageError.CreateFmt('Unable to download "%s": %s',
          [AppDef.Id, E.Message]);
      end;
    end;
  finally
    Client.Free;
    Stream.Free;
  end;

  if Aborted then
  begin
    DeleteFileQuiet(TempDestination);
    raise EPortappixPackageError.CreateFmt('Download aborted for "%s".', [AppDef.Id]);
  end;

  if (Response = nil) or (Response.StatusCode < 200) or (Response.StatusCode >= 300) then
  begin
    DeleteFileQuiet(TempDestination);
    if Response = nil then
      raise EPortappixPackageError.CreateFmt('Unable to download "%s".', [AppDef.Id]);
    raise EPortappixPackageError.CreateFmt('Unable to download "%s" (HTTP %d).',
      [AppDef.Id, Response.StatusCode]);
  end;

  if TFile.Exists(ADestination) then
    TFile.Delete(ADestination);
  TFile.Move(TempDestination, ADestination);
end;

class function TPortappixPackageManager.ComputeSha256(const AFileName: string): string;
var
  Stream: TFileStream;
begin
  Stream := TFileStream.Create(AFileName, fmOpenRead or fmShareDenyWrite);
  try
    Result := THashSHA2.GetHashString(Stream, THashSHA2.TSHA2Version.SHA256).ToLower;
  finally
    Stream.Free;
  end;
end;

procedure TPortappixPackageManager.VerifyPackage(const AppDef: TCatalogApp;
  const AFileName: string);
var
  ActualHash: string;
  ExpectedHash: string;
  ActualSize: Int64;
begin
  ExpectedHash := AppDef.Sha256.Trim.ToLower;
  ActualHash := ComputeSha256(AFileName);
  if not SameText(ActualHash, ExpectedHash) then
  begin
    DeleteFileQuiet(AFileName);
    raise EPortappixPackageError.CreateFmt(
      'SHA-256 mismatch for "%s". Expected %s but got %s.',
      [AppDef.Id, ExpectedHash, ActualHash]);
  end;

  if AppDef.Size > 0 then
  begin
    ActualSize := TFile.GetSize(AFileName);
    if ActualSize <> AppDef.Size then
    begin
      DeleteFileQuiet(AFileName);
      raise EPortappixPackageError.CreateFmt(
        'Size mismatch for "%s". Expected %d bytes but got %d bytes.',
        [AppDef.Id, AppDef.Size, ActualSize]);
    end;
  end;
end;

procedure TPortappixPackageManager.ExtractArchive(const AZipFile, ADestinationDir: string);
var
  Zip: TZipFile;
  FileName: string;
  DestinationPath: string;
  TotalUncompressed: Int64;
  EntrySize: Int64;
begin
  if TDirectory.Exists(ADestinationDir) then
    TDirectory.Delete(ADestinationDir, True);
  ForceDirectories(ADestinationDir);

  TotalUncompressed := 0;
  Zip := TZipFile.Create;
  try
    Zip.Open(AZipFile, TZipMode.zmRead);
    try
      if Zip.FileCount > MaxZipEntries then
        raise EPortappixPackageError.CreateFmt(
          'Package contains %d entries; the limit is %d.', [Zip.FileCount, MaxZipEntries]);

      for var Index := 0 to Zip.FileCount - 1 do
      begin
        EntrySize := Zip.FileInfo[Index].UncompressedSize;
        TotalUncompressed := TotalUncompressed + EntrySize;
        if TotalUncompressed > MaxZipUncompressedBytes then
          raise EPortappixPackageError.CreateFmt(
            'Package expands to more than %d bytes; refusing to extract.',
            [MaxZipUncompressedBytes]);

        FileName := StringReplace(Zip.FileNames[Index], '/', '\', [rfReplaceAll]);
        if (FileName = '') or FileName.EndsWith('\') then
        begin
          if (FileName <> '') and IsZipSlip(ADestinationDir, FileName) then
            raise EPortappixPackageError.CreateFmt('Unsafe zip entry path: "%s".', [FileName]);
          if FileName <> '' then
            ForceDirectories(TPath.Combine(ADestinationDir, FileName));
          Continue;
        end;

        if IsZipSlip(ADestinationDir, FileName) then
          raise EPortappixPackageError.CreateFmt('Unsafe zip entry path: "%s".', [FileName]);

        DestinationPath := TPath.Combine(ADestinationDir, FileName);
        ForceDirectories(TPath.GetDirectoryName(DestinationPath));
        Zip.Extract(Index, ADestinationDir, True);
      end;
    finally
      Zip.Close;
    end;
  finally
    Zip.Free;
  end;
end;

procedure TPortappixPackageManager.DeleteDirectoryQuiet(const ADirectory: string);
begin
  try
    if TDirectory.Exists(ADirectory) then
      TDirectory.Delete(ADirectory, True);
  except
    on E: Exception do
      Log(Format('Unable to delete directory "%s": %s', [ADirectory, E.Message]));
  end;
end;

procedure TPortappixPackageManager.DeleteFileQuiet(const AFileName: string);
begin
  try
    if TFile.Exists(AFileName) then
      TFile.Delete(AFileName);
  except
    on E: Exception do
      Log(Format('Unable to delete file "%s": %s', [AFileName, E.Message]));
  end;
end;

procedure TPortappixPackageManager.AtomicSwap(const ATempDir, AFinalDir: string);
var
  OldDir: string;
begin
  OldDir := AFinalDir + '.old';
  if TDirectory.Exists(OldDir) then
    TDirectory.Delete(OldDir, True);

  if TDirectory.Exists(AFinalDir) then
  begin
    if not RenameFile(AFinalDir, OldDir) then
      raise EPortappixPackageError.CreateFmt('Unable to move existing app directory "%s" to "%s": %s',
        [AFinalDir, OldDir, SysErrorMessage(Integer(GetLastError))]);
  end;

  try
    if not RenameFile(ATempDir, AFinalDir) then
      raise EPortappixPackageError.CreateFmt('Unable to install app directory "%s": %s',
        [AFinalDir, SysErrorMessage(Integer(GetLastError))]);
  except
    if TDirectory.Exists(OldDir) and not TDirectory.Exists(AFinalDir) then
      if not RenameFile(OldDir, AFinalDir) then
        Log(Format('Unable to restore previous app directory "%s".', [AFinalDir]));
    raise;
  end;

  DeleteDirectoryQuiet(OldDir);
end;

procedure TPortappixPackageManager.ValidateExtractedManifest(const AppDef: TCatalogApp;
  const ATempDir: string);
var
  ManifestPath: string;
  Manifest: TPortappixManifest;
  Policy: TPolicyResult;
begin
  ManifestPath := TPath.Combine(ATempDir, 'app.json');
  if not TFile.Exists(ManifestPath) then
    raise EPortappixPackageError.CreateFmt(
      'Package "%s" does not contain app.json at the archive root.', [AppDef.Id]);

  Manifest := TPortappixManifest.LoadFromFile(ManifestPath);
  try
    if not SameText(Manifest.Id, AppDef.Id) then
      raise EPortappixPackageError.CreateFmt(
        'Package "%s" contains a manifest for "%s"; the catalog id must match.',
        [AppDef.Id, Manifest.Id]);

    Policy := TPortappixPolicy.ValidateManifest(Manifest);
    try
      if not Policy.Allowed then
        raise EPortappixPackageError.CreateFmt(
          'Package "%s" violates the Portappix policy:' + sLineBreak + '%s',
          [AppDef.Id, Policy.Summary]);
    finally
      Policy.Free;
    end;
  finally
    Manifest.Free;
  end;
end;

procedure TPortappixPackageManager.InstallApp(const AppDef: TCatalogApp;
  const AProgress: TDownloadProgressEvent);
var
  PackageFile: string;
  TempDir: string;
  FinalDir: string;
begin
  if AppDef = nil then
    raise EPortappixPackageError.Create('App definition must not be nil.');
  if AppDef.Id.Trim = '' then
    raise EPortappixPackageError.Create('App definition id must not be empty.');
  if AppDef.Url.Trim = '' then
    raise EPortappixPackageError.CreateFmt('App "%s" has no download URL.', [AppDef.Id]);
  if not IsHttpsUrl(AppDef.Url) then
    raise EPortappixPackageError.CreateFmt('App "%s" must use an https:// download URL.',
      [AppDef.Id]);

  EnsureDirectories;

  PackageFile := CacheFile(AppDef);
  TempDir := TPath.Combine(FAppsDir, SanitizeFileComponent(AppDef.Id) + '.new');
  FinalDir := TPath.Combine(FAppsDir, SanitizeFileComponent(AppDef.Id));

  Log(Format('Downloading %s %s.', [AppDef.Id, AppDef.Version]));
  DownloadPackage(AppDef, PackageFile, AProgress);

  Log(Format('Verifying %s.', [PackageFile]));
  VerifyPackage(AppDef, PackageFile);

  Log(Format('Extracting %s.', [PackageFile]));
  try
    ExtractArchive(PackageFile, TempDir);
    ValidateExtractedManifest(AppDef, TempDir);

    Log(Format('Installing %s.', [AppDef.Id]));
    AtomicSwap(TempDir, FinalDir);
  except
    DeleteDirectoryQuiet(TempDir);
    raise;
  end;

  DeleteFileQuiet(PackageFile);
  Log(Format('Installed %s %s.', [AppDef.Id, AppDef.Version]));
end;

end.
