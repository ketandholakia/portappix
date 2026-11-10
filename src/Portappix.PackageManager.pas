unit Portappix.PackageManager;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  System.Hash,
  System.JSON,
  System.Zip,
  System.Net.HttpClient,
  System.Net.URLClient,
  System.Generics.Collections,
  System.Generics.Defaults,
  Portappix.Common,
  Portappix.Catalog,
  Portappix.Manifest,
  Portappix.Policy,
  Portappix.Process,
  Portappix.Version;

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
    procedure DownloadPackage(const AppDef: TCatalogApp; const ADestination: string;
      const AProgress: TDownloadProgressEvent);
    procedure VerifyPackage(const AppDef: TCatalogApp; const AFileName: string);
    procedure DeleteDirectoryQuiet(const ADirectory: string);
    procedure DeleteFileQuiet(const AFileName: string);
    procedure AtomicSwap(const ATempDir, AFinalDir, APrevDir: string);
    function SanitizeFileComponent(const AValue: string): string;
    procedure ValidateExtractedManifest(const AppDef: TCatalogApp; const ATempDir: string);
    function PendingFile: string;
    function LoadPendingUpdates: TObjectList<TCatalogApp>;
    procedure SavePendingUpdates(const AUpdates: TObjectList<TCatalogApp>);
  public
    function CacheFile(const AppDef: TCatalogApp): string;
    constructor Create(const ARootPath: string = '');
    procedure InstallApp(const AppDef: TCatalogApp; const AProgress: TDownloadProgressEvent = nil);
    procedure RollbackApp(const AAppId: string);
    procedure QueueUpdate(const AppDef: TCatalogApp);
    procedure RemovePendingUpdate(const AAppId: string);
    procedure ApplyPendingUpdates(const AProgress: TDownloadProgressEvent = nil);
    function PendingUpdateIds: TArray<string>;
    function HasPendingUpdate(const AAppId: string): Boolean;
    procedure ValidateUpdateAllowed(const AIncoming: TPortappixManifest);
    class function IsAppRunning(const ARootPath, AAppId: string): Boolean; static;
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

function IsReservedDeviceName(const AName: string): Boolean;
const
  ReservedBases: array[0..21] of string = (
    'CON', 'PRN', 'AUX', 'NUL',
    'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
    'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
  );
var
  Base: string;
  DotPos: Integer;
begin
  Base := AName.Trim;
  DotPos := Base.IndexOf('.');
  if DotPos >= 0 then
    Base := Base.Substring(0, DotPos);
  for var Reserved in ReservedBases do
    if SameText(Base, Reserved) then
      Exit(True);
  Result := False;
end;

procedure TPortappixPackageManager.ExtractArchive(const AZipFile, ADestinationDir: string);
var
  Zip: TZipFile;
  FileName: string;
  DestinationPath: string;
  TotalUncompressed: Int64;
  TotalActualBytes: Int64;
  EntrySize: Int64;
  SeenEntries: TDictionary<string, Integer>;
  SeenKey: string;
  EntryStream: TStream;
  LocalHeader: TZipHeader;
  OutStream: TFileStream;
begin
  if TDirectory.Exists(ADestinationDir) then
    TDirectory.Delete(ADestinationDir, True);
  ForceDirectories(ADestinationDir);

  TotalUncompressed := 0;
  TotalActualBytes := 0;
  SeenEntries := TDictionary<string, Integer>.Create;
  Zip := TZipFile.Create;
  try
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

          if FileName.IndexOf(':') >= 0 then
            raise EPortappixPackageError.CreateFmt(
              'Zip entry "%s" contains Alternate Data Stream separator (:); refusing to extract.', [FileName]);

          for var Component in FileName.Split(['\']) do
            if IsReservedDeviceName(Component) then
              raise EPortappixPackageError.CreateFmt(
                'Zip entry "%s" contains reserved Windows device name; refusing to extract.', [FileName]);

          SeenKey := FileName.ToLower;
          if SeenEntries.ContainsKey(SeenKey) then
            raise EPortappixPackageError.CreateFmt(
              'Duplicate or case-colliding zip entry: "%s".', [FileName]);
          SeenEntries.Add(SeenKey, Index);

          if IsZipSlip(ADestinationDir, FileName) then
            raise EPortappixPackageError.CreateFmt('Unsafe zip entry path: "%s".', [FileName]);

          DestinationPath := TPath.Combine(ADestinationDir, FileName);
          ForceDirectories(TPath.GetDirectoryName(DestinationPath));

          EntryStream := nil;
          Zip.Read(Index, EntryStream, LocalHeader);
          try
            if EntryStream <> nil then
            begin
              TotalActualBytes := TotalActualBytes + EntryStream.Size;
              if TotalActualBytes > MaxZipUncompressedBytes then
                raise EPortappixPackageError.CreateFmt(
                  'Package uncompressed size exceeds limit of %d bytes; refusing to extract.',
                  [MaxZipUncompressedBytes]);

              OutStream := TFileStream.Create(DestinationPath, fmCreate);
              try
                EntryStream.Position := 0;
                OutStream.CopyFrom(EntryStream, EntryStream.Size);
              finally
                OutStream.Free;
              end;
            end;
          finally
            EntryStream.Free;
          end;
        end;
      finally
        Zip.Close;
      end;
    finally
      Zip.Free;
    end;
  finally
    SeenEntries.Free;
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

procedure TPortappixPackageManager.AtomicSwap(const ATempDir, AFinalDir,
  APrevDir: string);
begin
  // Keep exactly one previous generation so an update can be rolled back.
  if TDirectory.Exists(APrevDir) then
    TDirectory.Delete(APrevDir, True);

  if TDirectory.Exists(AFinalDir) then
  begin
    if not RenameFile(AFinalDir, APrevDir) then
      raise EPortappixPackageError.CreateFmt('Unable to move existing app directory "%s" to "%s": %s',
        [AFinalDir, APrevDir, SysErrorMessage(Integer(GetLastError))]);
  end;

  try
    if not RenameFile(ATempDir, AFinalDir) then
      raise EPortappixPackageError.CreateFmt('Unable to install app directory "%s": %s',
        [AFinalDir, SysErrorMessage(Integer(GetLastError))]);
  except
    if TDirectory.Exists(APrevDir) and not TDirectory.Exists(AFinalDir) then
      if not RenameFile(APrevDir, AFinalDir) then
        Log(Format('Unable to restore previous app directory "%s".', [AFinalDir]));
    raise;
  end;
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

procedure TPortappixPackageManager.ValidateUpdateAllowed(
  const AIncoming: TPortappixManifest);
var
  InstalledManifestPath: string;
  Installed: TPortappixManifest;
  DataDir: string;
  InstalledDataVersion: Integer;
begin
  // Downgrade protection: never silently replace a newer app with an older one.
  InstalledManifestPath := TPath.Combine(FAppsDir,
    SanitizeFileComponent(AIncoming.Id) + '\app.json');
  if TFile.Exists(InstalledManifestPath) then
  begin
    Installed := TPortappixManifest.LoadFromFile(InstalledManifestPath);
    try
      if (AIncoming.Version <> '') and (Installed.Version <> '') then
        if TPortappixSemVer.CompareText(AIncoming.Version, Installed.Version) < 0 then
          raise EPortappixPackageError.CreateFmt(
            'Refusing to downgrade "%s" from %s to %s. Install the older ' +
            'package manually with downgrade protection disabled if this is intended.',
            [AIncoming.Id, Installed.Version, AIncoming.Version]);
    finally
      Installed.Free;
    end;
  end;

  // Data written by a newer data version must not be opened by an older app.
  DataDir := TPath.Combine(TPath.Combine(FRootPath, 'Data'),
    SanitizeFileComponent(AIncoming.Id));
  InstalledDataVersion := TPortappixManifest.ReadDataVersion(DataDir);
  if (InstalledDataVersion > 0) and (AIncoming.DataVersion > 0) and
     (InstalledDataVersion > AIncoming.DataVersion) then
    raise EPortappixPackageError.CreateFmt(
      'Refusing to update "%s": its portable data was written by data version %d, ' +
      'but this package ships data version %d. Rolling back or forcing this ' +
      'update risks losing data.',
      [AIncoming.Id, InstalledDataVersion, AIncoming.DataVersion]);
end;

procedure StripArchivePrefix(const ADestDir, APrefix: string);
var
  CleanPrefix, PrefixDir, CurDir, ParentDir: string;
begin
  CleanPrefix := APrefix.Trim.Replace('/', '\').Trim(['\']);
  if CleanPrefix = '' then
    Exit;
  PrefixDir := TPath.Combine(ADestDir, CleanPrefix);
  if TDirectory.Exists(PrefixDir) then
  begin
    for var FilePath in TDirectory.GetFiles(PrefixDir) do
    begin
      var Target := TPath.Combine(ADestDir, TPath.GetFileName(FilePath));
      if TFile.Exists(Target) then
        TFile.Delete(Target);
      TFile.Move(FilePath, Target);
    end;
    for var SubDir in TDirectory.GetDirectories(PrefixDir) do
    begin
      var TargetDir := TPath.Combine(ADestDir, TPath.GetFileName(SubDir));
      if TDirectory.Exists(TargetDir) then
        TDirectory.Delete(TargetDir, True);
      TDirectory.Move(SubDir, TargetDir);
    end;
    CurDir := PrefixDir;
    while (CurDir <> '') and not SameText(CurDir, ADestDir) do
    begin
      ParentDir := TPath.GetDirectoryName(CurDir);
      try
        if TDirectory.Exists(CurDir) then
          TDirectory.Delete(CurDir, True);
      except
      end;
      CurDir := ParentDir;
    end;
  end;
end;

procedure GenerateManifest(const AppDef: TCatalogApp; const ADestDir: string);
var
  Json: TJSONObject;
  OverlayVal: TJSONValue;
  OverlayObj: TJSONObject;
  ManifestPath: string;
begin
  ManifestPath := TPath.Combine(ADestDir, 'app.json');
  if TFile.Exists(ManifestPath) and not AppDef.IsVendorLink then
    Exit;

  Json := TJSONObject.Create;
  try
    Json.AddPair('schema', TJSONNumber.Create(1));
    Json.AddPair('id', AppDef.Id);
    Json.AddPair('name', AppDef.Name);
    if AppDef.Publisher <> '' then
      Json.AddPair('publisher', AppDef.Publisher);
    Json.AddPair('version', AppDef.Version);
    if AppDef.Category <> '' then
      Json.AddPair('category', AppDef.Category);

    if AppDef.ManifestOverlay <> '' then
    begin
      OverlayVal := TJSONObject.ParseJSONValue(AppDef.ManifestOverlay);
      try
        if (OverlayVal <> nil) and (OverlayVal is TJSONObject) then
        begin
          OverlayObj := TJSONObject(OverlayVal);
          for var Pair in OverlayObj do
          begin
            if not SameText(Pair.JsonString.Value, 'id') and
               not SameText(Pair.JsonString.Value, 'name') and
               not SameText(Pair.JsonString.Value, 'version') then
              Json.AddPair(Pair.JsonString.Value, Pair.JsonValue.Clone as TJSONValue);
          end;
        end;
      finally
        OverlayVal.Free;
      end;
    end;

    if (Json.FindValue('exe') = nil) and (AppDef.ExePath <> '') then
      Json.AddPair('exe', AppDef.ExePath);

    TFile.WriteAllText(ManifestPath, Json.Format(2), TEncoding.UTF8);
  finally
    Json.Free;
  end;
end;

procedure TPortappixPackageManager.InstallApp(const AppDef: TCatalogApp;
  const AProgress: TDownloadProgressEvent);
var
  PackageFile: string;
  TempDir: string;
  FinalDir: string;
  PrevDir: string;
  Incoming: TPortappixManifest;
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
  PrevDir := FinalDir + '.prev';

  var CacheValid := TFile.Exists(PackageFile) and
    SameText(ComputeSha256(PackageFile), AppDef.Sha256.Trim) and
    ((AppDef.Size <= 0) or (TFile.GetSize(PackageFile) = AppDef.Size));
  if not CacheValid then
  begin
    Log(Format('Downloading %s %s.', [AppDef.Id, AppDef.Version]));
    DownloadPackage(AppDef, PackageFile, AProgress);
  end;

  Log(Format('Verifying %s.', [PackageFile]));
  VerifyPackage(AppDef, PackageFile);

  Log(Format('Extracting %s.', [PackageFile]));
  Incoming := nil;
  try
    try
      ExtractArchive(PackageFile, TempDir);
      if AppDef.StripPrefix <> '' then
        StripArchivePrefix(TempDir, AppDef.StripPrefix);
      if AppDef.IsVendorLink or not TFile.Exists(TPath.Combine(TempDir, 'app.json')) then
        GenerateManifest(AppDef, TempDir);
      ValidateExtractedManifest(AppDef, TempDir);
      Incoming := TPortappixManifest.LoadFromFile(TPath.Combine(TempDir, 'app.json'));
      ValidateUpdateAllowed(Incoming);

      Log(Format('Installing %s.', [AppDef.Id]));
      var LockHandle: THandle := 0;
      if not TryAcquireMutex(AppMutexName(FRootPath, AppDef.Id), LockHandle) then
        raise EPortappixPackageError.CreateFmt(
          'Cannot install or update "%s": application is currently running or locked.',
          [AppDef.Id]);
      try
        AtomicSwap(TempDir, FinalDir, PrevDir);
      finally
        ReleaseMutexHandle(LockHandle);
      end;
    except
      DeleteDirectoryQuiet(TempDir);
      raise;
    end;
  finally
    Incoming.Free;
  end;

  DeleteFileQuiet(PackageFile);
  Log(Format('Installed %s %s.', [AppDef.Id, AppDef.Version]));
end;

class function TPortappixPackageManager.IsAppRunning(const ARootPath,
  AAppId: string): Boolean;
var
  AppDir: string;
begin
  // The per-app mutex is authoritative while a launcher instance is alive;
  // the process-path scan catches apps that outlived a launcher crash.
  Result := Portappix.Common.IsAppRunning(ARootPath, AAppId);
  if Result then
    Exit;

  AppDir := TPath.Combine(TPath.Combine(ResolveRootPath(ARootPath), 'Apps'),
    AAppId);
  if TDirectory.Exists(AppDir) then
    Result := IsProcessRunningUnderPath(AppDir);
end;

procedure TPortappixPackageManager.RollbackApp(const AAppId: string);
var
  SafeId: string;
  FinalDir: string;
  PrevDir: string;
  StaleDir: string;
begin
  SafeId := SanitizeFileComponent(AAppId);
  FinalDir := TPath.Combine(FAppsDir, SafeId);
  PrevDir := FinalDir + '.prev';
  StaleDir := FinalDir + '.stale';

  if not TDirectory.Exists(PrevDir) then
    raise EPortappixPackageError.CreateFmt(
      'No previous version of "%s" is available ("%s" does not exist).',
      [AAppId, PrevDir]);
  if IsAppRunning(FRootPath, AAppId) then
    raise EPortappixPackageError.CreateFmt(
      '"%s" is running; close it before rolling back.', [AAppId]);

  var LockHandle: THandle := 0;
  if not TryAcquireMutex(AppMutexName(FRootPath, AAppId), LockHandle) then
    raise EPortappixPackageError.CreateFmt(
      '"%s" is currently running or locked; close it before rolling back.', [AAppId]);
  try
    EnsureDirectories;
    DeleteDirectoryQuiet(StaleDir);

    if TDirectory.Exists(FinalDir) then
    begin
      if not RenameFile(FinalDir, StaleDir) then
        raise EPortappixPackageError.CreateFmt(
          'Unable to move "%s" to "%s": %s',
          [FinalDir, StaleDir, SysErrorMessage(Integer(GetLastError))]);
    end;

    try
      if not RenameFile(PrevDir, FinalDir) then
        raise EPortappixPackageError.CreateFmt('Unable to restore "%s": %s',
          [FinalDir, SysErrorMessage(Integer(GetLastError))]);
    except
      if TDirectory.Exists(StaleDir) and not TDirectory.Exists(FinalDir) then
        if not RenameFile(StaleDir, FinalDir) then
          Log(Format('Unable to restore the current version of "%s".', [AAppId]));
      raise;
    end;
  finally
    ReleaseMutexHandle(LockHandle);
  end;

  DeleteDirectoryQuiet(StaleDir);
  Log(Format('Rolled back "%s" to the previous version. Data\<id> was untouched.',
    [AAppId]));
end;

function TPortappixPackageManager.PendingFile: string;
begin
  Result := TPath.Combine(FCacheDir, 'pending_updates.json');
end;

function TPortappixPackageManager.LoadPendingUpdates: TObjectList<TCatalogApp>;
var
  JsonValue: TJSONValue;
  UpdatesValue: TJSONValue;
  UpdatesArray: TJSONArray;
  Item: TJSONValue;
  Entry: TJSONObject;
  App: TCatalogApp;

  function ReadStringField(const AObject: TJSONObject; const AName: string): string;
  var
    Value: TJSONValue;
  begin
    Result := '';
    Value := AObject.GetValue(AName);
    if Value is TJSONString then
      Result := TJSONString(Value).Value.Trim;
  end;

begin
  Result := TObjectList<TCatalogApp>.Create(True);
  if not TFile.Exists(PendingFile) then
    Exit;

  try
    JsonValue := TJSONObject.ParseJSONValue(
      TFile.ReadAllText(PendingFile, TEncoding.UTF8));
    try
      if (JsonValue = nil) or not (JsonValue is TJSONObject) then
        Exit;
      UpdatesValue := TJSONObject(JsonValue).GetValue('updates');
      if not (UpdatesValue is TJSONArray) then
        Exit;

      UpdatesArray := TJSONArray(UpdatesValue);
      for var Index := 0 to UpdatesArray.Count - 1 do
      begin
        Item := UpdatesArray.Items[Index];
        if not (Item is TJSONObject) then
          Continue;
        Entry := TJSONObject(Item);
        App := TCatalogApp.Create;
        App.Id := ReadStringField(Entry, 'id');
        if not IsSafeFileComponent(App.Id) then
        begin
          App.Free;
          Continue;
        end;
        App.Version := ReadStringField(Entry, 'version');
        App.Url := ReadStringField(Entry, 'url');
        App.Sha256 := ReadStringField(Entry, 'sha256').ToLower;
        var SizeValue := Entry.GetValue('size');
        if SizeValue is TJSONNumber then
          App.Size := TJSONNumber(SizeValue).AsInt64;
        Result.Add(App);
      end;
    finally
      JsonValue.Free;
    end;
  except
    on E: Exception do
      Log(Format('Unable to read pending updates ("%s"); treating the queue as empty.',
        [E.Message]));
  end;
end;

procedure TPortappixPackageManager.SavePendingUpdates(
  const AUpdates: TObjectList<TCatalogApp>);
var
  Root: TJSONObject;
  Updates: TJSONArray;
begin
  Root := TJSONObject.Create;
  Updates := TJSONArray.Create;
  try
    for var App in AUpdates do
    begin
      var Entry := TJSONObject.Create;
      Entry.AddPair('id', App.Id);
      Entry.AddPair('version', App.Version);
      Entry.AddPair('url', App.Url);
      Entry.AddPair('sha256', App.Sha256);
      Entry.AddPair('size', TJSONNumber.Create(App.Size));
      Updates.Add(Entry);
    end;
    Root.AddPair('schema', TJSONNumber.Create(1));
    Root.AddPair('updates', Updates);
    ForceDirectories(FCacheDir);
    if not WriteTextFileAtomic(PendingFile, Root.Format(2)) then
      raise EPortappixPackageError.Create('Unable to write pending_updates.json.');
  finally
    Root.Free;
  end;
end;

procedure TPortappixPackageManager.QueueUpdate(const AppDef: TCatalogApp);
var
  Pending: TObjectList<TCatalogApp>;
begin
  if (AppDef = nil) or (AppDef.Id.Trim = '') then
    raise EPortappixPackageError.Create('App definition must not be nil.');

  Pending := LoadPendingUpdates;
  try
    for var Existing in Pending do
      if SameText(Existing.Id, AppDef.Id) then
      begin
        // Refresh the entry: version, URL, hash and size may have changed.
        Existing.Version := AppDef.Version;
        Existing.Url := AppDef.Url;
        Existing.Sha256 := AppDef.Sha256.Trim.ToLower;
        Existing.Size := AppDef.Size;
        SavePendingUpdates(Pending);
        Log(Format('Update for "%s" is already queued; the entry was refreshed.',
          [AppDef.Id]));
        Exit;
      end;

    var Clone := TCatalogApp.Create;
    Clone.Id := AppDef.Id;
    Clone.Name := AppDef.Name;
    Clone.Version := AppDef.Version;
    Clone.Category := AppDef.Category;
    Clone.Url := AppDef.Url;
    Clone.Sha256 := AppDef.Sha256;
    Clone.Size := AppDef.Size;
    Pending.Add(Clone);
    SavePendingUpdates(Pending);
    Log(Format('Update for "%s" %s queued; it will install after the app closes.',
      [AppDef.Id, AppDef.Version]));
  finally
    Pending.Free;
  end;
end;

procedure TPortappixPackageManager.RemovePendingUpdate(const AAppId: string);
var
  Pending: TObjectList<TCatalogApp>;
  Removed: Boolean;
begin
  Removed := False;
  Pending := LoadPendingUpdates;
  try
    for var Index := Pending.Count - 1 downto 0 do
      if SameText(Pending[Index].Id, AAppId) then
      begin
        Pending.Delete(Index);
        Removed := True;
      end;

    if Removed then
    begin
      SavePendingUpdates(Pending);
      Log(Format('Removed the queued update for "%s".', [AAppId]));
    end;
  finally
    Pending.Free;
  end;
end;

procedure TPortappixPackageManager.ApplyPendingUpdates(
  const AProgress: TDownloadProgressEvent);
var
  Pending: TObjectList<TCatalogApp>;
  Catalog: TPortappixCatalog;
  CatalogPath: string;
  CatalogApp: TCatalogApp;
begin
  Pending := LoadPendingUpdates;
  try
    if Pending.Count = 0 then
      Exit;

    CatalogPath := TPath.Combine(FRootPath, 'catalog.json');
    if not TFile.Exists(CatalogPath) then
      CatalogPath := TPath.Combine(FCacheDir, 'catalog.json');

    Catalog := TPortappixCatalog.Create;
    try
      try
        Catalog.LoadFromFile(CatalogPath);
      except
        on E: Exception do
        begin
          Log(Format('Unable to verify pending updates against catalog: %s', [E.Message]));
          Exit;
        end;
      end;

      // Iterate downwards: applied entries are removed from the same list.
      for var Index := Pending.Count - 1 downto 0 do
      begin
        var Def := Pending[Index];

        CatalogApp := Catalog.FindById(Def.Id);
        if (CatalogApp = nil) or
           not SameText(CatalogApp.Version, Def.Version) or
           not SameText(CatalogApp.Sha256, Def.Sha256) or
           (CatalogApp.Size <> Def.Size) or
           not SameText(CatalogApp.Url, Def.Url) then
        begin
          Log(Format('Pending update for "%s" does not match signed catalog; discarding.', [Def.Id]));
          Pending.Delete(Index);
          SavePendingUpdates(Pending);
          Continue;
        end;

        if IsAppRunning(FRootPath, Def.Id) then
        begin
          Log(Format('"%s" is still running; keeping its queued update to %s.',
            [Def.Id, Def.Version]));
          Continue;
        end;

        try
          Log(Format('Applying the queued update for "%s" to %s.', [Def.Id, Def.Version]));
          InstallApp(Def, AProgress);
          Pending.Delete(Index);
          SavePendingUpdates(Pending);
          Log(Format('Queued update for "%s" applied. Data\<id> was untouched.', [Def.Id]));
        except
          on E: Exception do
            Log(Format('Queued update for "%s" failed and stays queued: %s',
              [Def.Id, E.Message]));
        end;
      end;
    finally
      Catalog.Free;
    end;
  finally
    Pending.Free;
  end;
end;

function TPortappixPackageManager.PendingUpdateIds: TArray<string>;
var
  Pending: TObjectList<TCatalogApp>;
  Ids: TList<string>;
begin
  Pending := LoadPendingUpdates;
  Ids := TList<string>.Create;
  try
    for var App in Pending do
      Ids.Add(App.Id);
    Result := Ids.ToArray;
  finally
    Ids.Free;
    Pending.Free;
  end;
end;

function TPortappixPackageManager.HasPendingUpdate(const AAppId: string): Boolean;
var
  Pending: TObjectList<TCatalogApp>;
begin
  Result := False;
  Pending := LoadPendingUpdates;
  try
    for var App in Pending do
      if SameText(App.Id, AAppId) then
        Exit(True);
  finally
    Pending.Free;
  end;
end;

end.
