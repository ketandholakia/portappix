unit Portappix.Update;

(*
  Launcher self-update.

  releases.json (plus releases.json.sig, signed with the same embedded ECDSA
  P-256 key as catalog.json) describes the newest launcher release:

    {
      "schema": 1,
      "channel": "stable",
      "version": "1.1.0",
      "url": "https://example.com/portappix-1.1.0.zip",
      "sha256": "<64 hex>",
      "size": 12345,
      "notes": "optional"
    }

  Apply flow (--self-update):
    1. Verify the release signature and compare versions (downgrades refused).
    2. Download the zip into Cache\, verify sha256 and size.
    3. Extract into Cache\launcher_new\ (same zip-slip/entry caps as apps).
    4. Write Cache\update_pending.json, then swap: the running Launcher.exe is
       renamed to Launcher.exe.old (allowed while running) and the new exe
       takes its place. Extra root files from the zip replace the old ones.
    5. Start the new Launcher.exe with --post-update and let the caller exit.

  First start of the new version (--post-update):
    writes Cache\update_ok, records the installed version in
    Cache\launcher_version.json and removes update_pending.json.
    Launcher.exe.old is deliberately kept as the rollback copy until the next
    update replaces it.

  Watchdog (every normal start, UI + CLI):
    Launcher.exe.old present but update_ok missing means the new version
    never confirmed a successful start -> offer to restore the old launcher
    (see NeedsRollbackOffer / RollbackToOldLauncher).

  Test/tooling hooks: AllowInsecureReleaseUrls permits http:// URLs (the
  signature over the exact bytes is still enforced); the CI suite also uses
  it to serve releases.json from a local test server.
*)

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes,
  System.DateUtils,
  System.IOUtils,
  System.JSON,
  System.Net.HttpClient,
  System.Net.URLClient,
  System.Generics.Collections,
  Portappix.Common,
  Portappix.Catalog,
  Portappix.PackageManager,
  Portappix.Process,
  Portappix.Signature,
  Portappix.Version;

const
  ReleaseSchemaVersion = 1;

var
  AllowInsecureReleaseUrls: Boolean = False;

type
  EPortappixUpdateError = class(Exception);

  /// One entry from releases.json.
  TPortappixRelease = class
  private
    FSchema: Integer;
    FChannel: string;
    FVersion: string;
    FUrl: string;
    FSha256: string;
    FSize: Int64;
    FNotes: string;
  public
    property Schema: Integer read FSchema write FSchema;
    property Channel: string read FChannel write FChannel;
    property Version: string read FVersion write FVersion;
    property Url: string read FUrl write FUrl;
    property Sha256: string read FSha256 write FSha256;
    property Size: Int64 read FSize write FSize;
    property Notes: string read FNotes write FNotes;
  end;

/// Parses releases.json contents. Raises EPortappixUpdateError on any
/// structural problem.
function ParseReleasesJson(const AJson: string): TPortappixRelease;

/// Downloads releases.json from AUrl, verifies its signature and parses it.
function DownloadReleases(const AUrl: string): TPortappixRelease;

type
  TPortappixUpdateManager = class
  private
    FRootPath: string;
    FOnLog: TProc<string>;
    procedure Log(const AMessage: string);
    function LauncherExe: string;
    function OldLauncherExe: string;
    function PendingFile: string;
    function OkFile: string;
    function VersionFile: string;
    function NewDir: string;
    procedure VerifyZip(const ARelease: TPortappixRelease; const AZipFile: string);
    function ReadPendingVersion: string;
    procedure RemoveFileQuiet(const AFileName: string);
    procedure SpawnNewLauncher(const AArguments: string);
  public
    constructor Create(const ARootPath: string = '');
    function InstalledVersion: string;
    procedure SetInstalledVersion(const AVersion: string);
    function PendingUpdateVersion: string;
    function IsUpdateAvailable(const ARelease: TPortappixRelease): Boolean;
    function NeedsRollbackOffer: Boolean;
    procedure PrepareUpdate(const AZipFile: string; const ARelease: TPortappixRelease;
      const ALaunchNewExe: Boolean = True);
    procedure ApplyUpdateFromUrl(const AUrl: string);
    procedure ConfirmUpdate;
    function RollbackToOldLauncher(const ARestartLauncher: Boolean = True): Boolean;
    property RootPath: string read FRootPath;
    property OnLog: TProc<string> read FOnLog write FOnLog;
  end;

implementation

const
  LauncherFileName = 'Launcher.exe';

procedure DownloadToFile(const AUrl, ADestination: string);
var
  Client: THTTPClient;
  Stream: TFileStream;
  Response: IHTTPResponse;
begin
  if TFile.Exists(ADestination) then
    TFile.Delete(ADestination);
  ForceDirectories(TPath.GetDirectoryName(ADestination));

  Stream := TFileStream.Create(ADestination + '.download', fmCreate);
  Client := THTTPClient.Create;
  try
    Client.UserAgent := 'Portappix';
    try
      Response := Client.Get(AUrl, Stream);
    except
      on E: Exception do
      begin
        if TFile.Exists(ADestination + '.download') then
          TFile.Delete(ADestination + '.download');
        raise EPortappixUpdateError.CreateFmt('Unable to download "%s": %s',
          [AUrl, E.Message]);
      end;
    end;

    if (Response = nil) or (Response.StatusCode < 200) or (Response.StatusCode >= 300) then
    begin
      if TFile.Exists(ADestination + '.download') then
        TFile.Delete(ADestination + '.download');
      if Response = nil then
        raise EPortappixUpdateError.CreateFmt('Unable to download "%s".', [AUrl]);
      raise EPortappixUpdateError.CreateFmt('Unable to download "%s" (HTTP %d).',
        [AUrl, Response.StatusCode]);
    end;

    if Stream.Size > Int64(2) * 1024 * 1024 * 1024 then
    begin
      Stream.Free;
      Stream := nil;
      if TFile.Exists(ADestination + '.download') then
        TFile.Delete(ADestination + '.download');
      raise EPortappixUpdateError.CreateFmt(
        'Downloaded file "%s" exceeds size limit of 2 GiB.', [AUrl]);
    end;
  finally
    Client.Free;
    Stream.Free;
  end;

  TFile.Move(ADestination + '.download', ADestination);
end;

function ParseReleasesJson(const AJson: string): TPortappixRelease;
var
  JsonValue: TJSONValue;
  Root: TJSONObject;
  Ignored: TPortappixSemVer;

  function RequiredString(const AName: string): string;
  var
    Value: TJSONValue;
  begin
    Result := '';
    Value := Root.GetValue(AName);
    if not (Value is TJSONString) then
      raise EPortappixUpdateError.CreateFmt(
        'releases.json property "%s" must be a string.', [AName]);
    Result := TJSONString(Value).Value.Trim;
    if Result = '' then
      raise EPortappixUpdateError.CreateFmt(
        'releases.json property "%s" must not be empty.', [AName]);
  end;

begin
  Result := TPortappixRelease.Create;
  try
    JsonValue := TJSONObject.ParseJSONValue(AJson);
    try
      if (JsonValue = nil) or not (JsonValue is TJSONObject) then
        raise EPortappixUpdateError.Create('releases.json must contain a JSON object.');
      Root := TJSONObject(JsonValue);

      var SchemaValue := Root.FindValue('schema');
      if (SchemaValue <> nil) and (SchemaValue is TJSONNumber) then
        Result.Schema := TJSONNumber(SchemaValue).AsInt;
      if Result.Schema > ReleaseSchemaVersion then
        raise EPortappixUpdateError.CreateFmt(
          'releases.json uses schema %d but this launcher supports schema %d.',
          [Result.Schema, ReleaseSchemaVersion]);

      Result.Channel := RequiredString('channel');
      Result.Version := RequiredString('version');
      if not TPortappixSemVer.TryParse(Result.Version, Ignored) then
        raise EPortappixUpdateError.CreateFmt(
          'releases.json version "%s" is not a semantic version.', [Result.Version]);

      Result.Url := RequiredString('url');

      var NotesValue := Root.FindValue('notes');
      if NotesValue is TJSONString then
        Result.Notes := NotesValue.Value;

      var ShaValue := Root.FindValue('sha256');
      if not (ShaValue is TJSONString) then
        raise EPortappixUpdateError.Create('releases.json property "sha256" is required.');
      Result.Sha256 := TJSONString(ShaValue).Value.Trim.ToLower;
      if (Length(Result.Sha256) <> 64) then
        raise EPortappixUpdateError.Create(
          'releases.json property "sha256" must be 64 hex characters.');
      for var Character in Result.Sha256 do
        if not CharInSet(Character, ['0'..'9', 'a'..'f']) then
          raise EPortappixUpdateError.Create(
            'releases.json property "sha256" must be hexadecimal.');

      var SizeValue := Root.FindValue('size');
      if (SizeValue = nil) or not (SizeValue is TJSONNumber) then
        raise EPortappixUpdateError.Create('releases.json property "size" is required.');
      Result.Size := TJSONNumber(SizeValue).AsInt64;
      if Result.Size <= 0 then
        raise EPortappixUpdateError.Create(
          'releases.json property "size" must be greater than zero.');
    finally
      JsonValue.Free;
    end;
  except
    Result.Free;
    raise;
  end;
end;

function DownloadReleases(const AUrl: string): TPortappixRelease;
var
  Content: TBytes;
  SignatureBytes: TBytes;
begin
  if AUrl.Trim = '' then
    raise EPortappixUpdateError.Create('Release URL must not be empty.');
  if (not IsHttpsUrl(AUrl)) and (not AllowInsecureReleaseUrls) then
    raise EPortappixUpdateError.CreateFmt(
      'Release URL must use https://: "%s".', [AUrl]);

  Content := DownloadToBytes(AUrl.Trim);
  if Length(Content) = 0 then
    raise EPortappixUpdateError.CreateFmt('releases.json at "%s" is empty.', [AUrl]);

  SignatureBytes := DownloadToBytes(AUrl.Trim + '.sig');
  if not VerifySignature(Content, SignatureBytes) then
    raise EPortappixUpdateError.CreateFmt(
      'Signature verification failed for "%s". The file may have been tampered with.',
      [AUrl]);

  Result := ParseReleasesJson(TEncoding.UTF8.GetString(Content));
end;

{ TPortappixUpdateManager }

constructor TPortappixUpdateManager.Create(const ARootPath: string);
begin
  inherited Create;
  FRootPath := ResolveRootPath(ARootPath);
end;

procedure TPortappixUpdateManager.Log(const AMessage: string);
begin
  if Assigned(FOnLog) then
    FOnLog(AMessage);
end;

function TPortappixUpdateManager.LauncherExe: string;
begin
  Result := TPath.Combine(FRootPath, LauncherFileName);
end;

function TPortappixUpdateManager.OldLauncherExe: string;
begin
  Result := LauncherExe + '.old';
end;

function TPortappixUpdateManager.PendingFile: string;
begin
  Result := TPath.Combine(TPath.Combine(FRootPath, 'Cache'), 'update_pending.json');
end;

function TPortappixUpdateManager.OkFile: string;
begin
  Result := TPath.Combine(TPath.Combine(FRootPath, 'Cache'), 'update_ok');
end;

function TPortappixUpdateManager.VersionFile: string;
begin
  Result := TPath.Combine(TPath.Combine(FRootPath, 'Cache'), 'launcher_version.json');
end;

function TPortappixUpdateManager.NewDir: string;
begin
  Result := TPath.Combine(TPath.Combine(FRootPath, 'Cache'), 'launcher_new');
end;

procedure TPortappixUpdateManager.RemoveFileQuiet(const AFileName: string);
begin
  try
    if TFile.Exists(AFileName) then
      TFile.Delete(AFileName);
  except
    on E: Exception do
      Log(Format('Unable to delete "%s": %s', [AFileName, E.Message]));
  end;
end;

function GetExeFileVersion(const AExePath: string): string;
var
  Handle: DWORD;
  Size: DWORD;
  Buffer: TBytes;
  RawValue: Pointer;
  FixedLength: UINT;
  FixedInfo: PVSFixedFileInfo;
begin
  Result := '';
  if not TFile.Exists(AExePath) then
    Exit;
  Handle := 0;
  Size := GetFileVersionInfoSize(PChar(AExePath), Handle);
  if Size = 0 then
    Exit;
  SetLength(Buffer, Size);
  if not GetFileVersionInfo(PChar(AExePath), Handle, Size, @Buffer[0]) then
    Exit;
  RawValue := nil;
  FixedLength := 0;
  if VerQueryValue(@Buffer[0], '\', RawValue, FixedLength) and
     (RawValue <> nil) and (FixedLength >= SizeOf(TVSFixedFileInfo)) then
  begin
    FixedInfo := PVSFixedFileInfo(RawValue);
    Result := Format('%d.%d.%d', [
      HiWord(FixedInfo.dwFileVersionMS),
      LoWord(FixedInfo.dwFileVersionMS),
      HiWord(FixedInfo.dwFileVersionLS)]);
    if LoWord(FixedInfo.dwFileVersionLS) > 0 then
      Result := Result + Format('.%d', [LoWord(FixedInfo.dwFileVersionLS)]);
  end;
end;

function TPortappixUpdateManager.InstalledVersion: string;
var
  ExeVer: string;
  JsonValue: TJSONValue;
  VersionValue: TJSONValue;
begin
  Result := '0.0.0';
  if TFile.Exists(LauncherExe) then
  begin
    ExeVer := GetExeFileVersion(LauncherExe);
    if ExeVer <> '' then
      Exit(ExeVer);
  end;

  if not TFile.Exists(VersionFile) then
    Exit;
  try
    JsonValue := TJSONObject.ParseJSONValue(
      TFile.ReadAllText(VersionFile, TEncoding.UTF8));
    try
      if JsonValue = nil then
        Exit;
      VersionValue := JsonValue.FindValue('version');
      if VersionValue is TJSONString then
        Result := TJSONString(VersionValue).Value.Trim;
      if Result = '' then
        Result := '0.0.0';
    finally
      JsonValue.Free;
    end;
  except
    // A corrupt version file behaves like no version information.
  end;
end;

procedure TPortappixUpdateManager.SetInstalledVersion(const AVersion: string);
var
  Json: TJSONObject;
begin
  Json := TJSONObject.Create;
  try
    Json.AddPair('version', AVersion);
    Json.AddPair('recordedAt', DateToISO8601(Now));
    ForceDirectories(TPath.GetDirectoryName(VersionFile));
    if not WriteTextFileAtomic(VersionFile, Json.Format(2)) then
      raise EPortappixUpdateError.Create('Unable to write launcher_version.json.');
  finally
    Json.Free;
  end;
end;

function TPortappixUpdateManager.PendingUpdateVersion: string;
begin
  Result := ReadPendingVersion;
end;

function TPortappixUpdateManager.IsUpdateAvailable(
  const ARelease: TPortappixRelease): Boolean;
begin
  if ARelease = nil then
    Exit(False);
  Result := TPortappixSemVer.CompareText(ARelease.Version, InstalledVersion) > 0;
end;

function TPortappixUpdateManager.NeedsRollbackOffer: Boolean;
begin
  if not TFile.Exists(OldLauncherExe) then
  begin
    if TFile.Exists(OkFile) then
      RemoveFileQuiet(OkFile);
    Exit(False);
  end;
  Result := not TFile.Exists(OkFile);
end;

function TPortappixUpdateManager.ReadPendingVersion: string;
var
  JsonValue: TJSONValue;
  VersionValue: TJSONValue;
begin
  Result := '';
  if not TFile.Exists(PendingFile) then
    Exit;
  try
    JsonValue := TJSONObject.ParseJSONValue(
      TFile.ReadAllText(PendingFile, TEncoding.UTF8));
    try
      if JsonValue = nil then
        Exit;
      VersionValue := JsonValue.FindValue('toVersion');
      if VersionValue is TJSONString then
        Result := TJSONString(VersionValue).Value.Trim;
    finally
      JsonValue.Free;
    end;
  except
    // Tolerate a corrupt pending file; the swap state still governs.
  end;
end;

procedure TPortappixUpdateManager.VerifyZip(const ARelease: TPortappixRelease;
  const AZipFile: string);
var
  ActualHash: string;
  ActualSize: Int64;
begin
  ActualHash := Sha256File(AZipFile);
  if not SameText(ActualHash, ARelease.Sha256) then
  begin
    RemoveFileQuiet(AZipFile);
    raise EPortappixUpdateError.CreateFmt(
      'SHA-256 mismatch for the launcher package. Expected %s but got %s.',
      [ARelease.Sha256, ActualHash]);
  end;

  ActualSize := TFile.GetSize(AZipFile);
  if ActualSize <> ARelease.Size then
  begin
    RemoveFileQuiet(AZipFile);
    raise EPortappixUpdateError.CreateFmt(
      'Size mismatch for the launcher package. Expected %d bytes but got %d bytes.',
      [ARelease.Size, ActualSize]);
  end;
end;

procedure TPortappixUpdateManager.PrepareUpdate(const AZipFile: string;
  const ARelease: TPortappixRelease; const ALaunchNewExe: Boolean);
var
  Extractor: TPortappixPackageManager;
  NewExe: string;
  RollbackDir: string;
  MovedRootFiles: TList<string>;
  BaseName, Target, ExistingTarget: string;
begin
  if ARelease = nil then
    raise EPortappixUpdateError.Create('Release must not be nil.');

  Log(Format('Preparing the update to %s.', [ARelease.Version]));
  VerifyZip(ARelease, AZipFile);

  ForceDirectories(TPath.GetDirectoryName(NewDir));
  Extractor := TPortappixPackageManager.Create(FRootPath);
  try
    Extractor.ExtractArchive(AZipFile, NewDir);
  finally
    Extractor.Free;
  end;

  NewExe := TPath.Combine(NewDir, LauncherFileName);
  if not TFile.Exists(NewExe) then
  begin
    TDirectory.Delete(NewDir, True);
    raise EPortappixUpdateError.CreateFmt(
      'The launcher package does not contain "%s" at the archive root.',
      [LauncherFileName]);
  end;

  // Clean up any old update_ok marker so a crash during or after this update
  // will correctly trigger the watchdog.
  RemoveFileQuiet(OkFile);

  // Record the pending update BEFORE touching the exe, so a crash mid-swap
  // leaves the watchdog in charge (Launcher.exe.old present, update_ok missing).
  var Pending := TJSONObject.Create;
  try
    Pending.AddPair('fromVersion', InstalledVersion);
    Pending.AddPair('toVersion', ARelease.Version);
    Pending.AddPair('channel', ARelease.Channel);
    Pending.AddPair('appliedAt', DateToISO8601(Now));
    ForceDirectories(TPath.GetDirectoryName(PendingFile));
    if not WriteTextFileAtomic(PendingFile, Pending.Format(2)) then
      raise EPortappixUpdateError.Create('Unable to write update_pending.json.');
  finally
    Pending.Free;
  end;

  // All-or-nothing swap. Back up any existing root files that would be replaced.
  RollbackDir := TPath.Combine(TPath.Combine(FRootPath, 'Cache'),
    Format('launcher_rollback_%s', [FormatDateTime('yyyymmdd_hhnnss_zzz', Now)]));
  ForceDirectories(RollbackDir);
  MovedRootFiles := TList<string>.Create;
  try
    for var FileName in TDirectory.GetFiles(NewDir) do
    begin
      BaseName := TPath.GetFileName(FileName);
      if SameText(BaseName, LauncherFileName) then
        Continue;
      ExistingTarget := TPath.Combine(FRootPath, BaseName);
      if TFile.Exists(ExistingTarget) then
        TFile.Copy(ExistingTarget, TPath.Combine(RollbackDir, BaseName), True);
    end;

    // Swap. Renaming a running executable is allowed on Windows.
    if TFile.Exists(OldLauncherExe) then
      RemoveFileQuiet(OldLauncherExe);
    if not RenameFile(LauncherExe, OldLauncherExe) then
      raise EPortappixUpdateError.CreateFmt(
        'Unable to move the running launcher to "%s": %s',
        [OldLauncherExe, SysErrorMessage(Integer(GetLastError))]);

    try
      if not RenameFile(NewExe, LauncherExe) then
        raise EPortappixUpdateError.CreateFmt(
          'Unable to move the new launcher into place: %s',
          [SysErrorMessage(Integer(GetLastError))]);

      // Extra root files shipped with the release replace the old ones.
      for var FileName in TDirectory.GetFiles(NewDir) do
      begin
        BaseName := TPath.GetFileName(FileName);
        if SameText(BaseName, LauncherFileName) then
          Continue;
        Target := TPath.Combine(FRootPath, BaseName);
        RemoveFileQuiet(Target);
        TFile.Move(FileName, Target);
        MovedRootFiles.Add(Target);
      end;
    except
      // Roll the swap back completely (all-or-nothing)
      for var MovedFile in MovedRootFiles do
        RemoveFileQuiet(MovedFile);
      for var BackupFile in TDirectory.GetFiles(RollbackDir) do
      begin
        Target := TPath.Combine(FRootPath, TPath.GetFileName(BackupFile));
        RemoveFileQuiet(Target);
        TFile.Move(BackupFile, Target);
      end;
      if TFile.Exists(LauncherExe) then
        RemoveFileQuiet(LauncherExe);
      if TFile.Exists(OldLauncherExe) then
        RenameFile(OldLauncherExe, LauncherExe);
      Log('Update swap failed; all files rolled back and previous launcher was restored.');
      raise;
    end;
  finally
    MovedRootFiles.Free;
    try
      if TDirectory.Exists(RollbackDir) then
        TDirectory.Delete(RollbackDir, True);
    except
    end;
  end;

  try
    TDirectory.Delete(NewDir, True);
  except
    on E: Exception do
      Log(Format('Unable to remove the temporary update folder "%s": %s',
        [NewDir, E.Message]));
  end;
  RemoveFileQuiet(AZipFile);

  Log(Format('Update to %s applied; restarting the launcher.', [ARelease.Version]));
  if ALaunchNewExe then
    SpawnNewLauncher('--post-update');
end;

procedure TPortappixUpdateManager.ApplyUpdateFromUrl(const AUrl: string);
var
  Release: TPortappixRelease;
  ZipFile: string;
begin
  Release := DownloadReleases(AUrl);
  try
    if not IsUpdateAvailable(Release) then
      raise EPortappixUpdateError.CreateFmt(
        'Version %s is not newer than the installed %s; refusing to downgrade.',
        [Release.Version, InstalledVersion]);

    if (not IsHttpsUrl(Release.Url)) and (not AllowInsecureReleaseUrls) then
      raise EPortappixUpdateError.CreateFmt(
        'Release package URL must use https://: "%s".', [Release.Url]);

    ZipFile := TPath.Combine(TPath.Combine(FRootPath, 'Cache'),
      Format('Launcher_%s.zip', [TPortappixSemVer.Parse(Release.Version).Raw]));
    Log(Format('Downloading the launcher %s package.', [Release.Version]));
    DownloadToFile(Release.Url, ZipFile);
    try
      PrepareUpdate(ZipFile, Release);
    finally
      RemoveFileQuiet(ZipFile);
    end;
  finally
    Release.Free;
  end;
end;

procedure TPortappixUpdateManager.ConfirmUpdate;
var
  PendingVersion: string;
begin
  if not TFile.Exists(OldLauncherExe) then
  begin
    Log('No pending update found (Launcher.exe.old is missing).');
    Exit;
  end;

  PendingVersion := ReadPendingVersion;
  if PendingVersion = '' then
  begin
    Log('Launcher.exe.old exists without update_pending.json; leaving it in place.');
    Exit;
  end;

  var OkContent := TJSONObject.Create;
  try
    OkContent.AddPair('toVersion', PendingVersion);
    OkContent.AddPair('confirmedAt', DateToISO8601(Now));
    ForceDirectories(TPath.GetDirectoryName(OkFile));
    if not WriteTextFileAtomic(OkFile, OkContent.Format(2)) then
      raise EPortappixUpdateError.Create('Unable to write the update_ok marker.');
  finally
    OkContent.Free;
  end;

  SetInstalledVersion(PendingVersion);
  RemoveFileQuiet(PendingFile);
  Log(Format('Update to %s confirmed. Launcher.exe.old is kept as the rollback copy ' +
    'until the next update; delete it manually to remove the rollback offer.',
    [PendingVersion]));
end;

function TPortappixUpdateManager.RollbackToOldLauncher(
  const ARestartLauncher: Boolean): Boolean;
var
  StaleExe: string;
begin
  if not TFile.Exists(OldLauncherExe) then
    raise EPortappixUpdateError.Create('No Launcher.exe.old exists to restore.');

  Log('Restoring the previous launcher version...');
  StaleExe := Format('%s.failed_%s', [LauncherExe,
    FormatDateTime('yyyymmdd_hhnnss', Now)]);

  if not RenameFile(LauncherExe, StaleExe) then
    raise EPortappixUpdateError.CreateFmt(
      'Unable to move the failing launcher to "%s": %s',
      [StaleExe, SysErrorMessage(Integer(GetLastError))]);

  try
    if not RenameFile(OldLauncherExe, LauncherExe) then
      raise EPortappixUpdateError.CreateFmt(
        'Unable to restore "%s": %s',
        [LauncherExe, SysErrorMessage(Integer(GetLastError))]);
  except
    if RenameFile(StaleExe, LauncherExe) then
      Log('Rollback failed; the failing launcher was restored in place.');
    raise;
  end;

  RemoveFileQuiet(OkFile);
  RemoveFileQuiet(PendingFile);
  Log('Previous launcher restored. The failed build stays next to it as ' +
    LauncherFileName + '.failed_* and can be deleted.');

  if ARestartLauncher then
    SpawnNewLauncher('');
  Result := True;
end;

procedure TPortappixUpdateManager.SpawnNewLauncher(const AArguments: string);
var
  StartupInfo: TStartupInfo;
  ProcessInfo: TProcessInformation;
  CommandLine: string;
begin
  FillChar(StartupInfo, SizeOf(StartupInfo), 0);
  StartupInfo.cb := SizeOf(StartupInfo);

  CommandLine := QuoteArgument(LauncherExe);
  if AArguments <> '' then
    CommandLine := CommandLine + ' ' + AArguments;
  UniqueString(CommandLine);

  if not CreateProcess(nil, PChar(CommandLine), nil, nil, False,
    CREATE_NEW_PROCESS_GROUP or CREATE_UNICODE_ENVIRONMENT, nil,
    PChar(FRootPath), StartupInfo, ProcessInfo) then
    raise EPortappixUpdateError.CreateFmt('Unable to start "%s": %s',
      [LauncherExe, SysErrorMessage(Integer(GetLastError))]);
  CloseHandle(ProcessInfo.hThread);
  CloseHandle(ProcessInfo.hProcess);
end;

end.
