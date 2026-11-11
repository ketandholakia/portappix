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
  Portappix.Junction,
  Portappix.PackageManager,
  Portappix.Process,
  Portappix.RecordAuth,
  Portappix.Signature,
  Portappix.Version;

const
  ReleaseSchemaVersion = 1;
  OldLauncherRecordSchemaVersion = 2;
  /// Upper sanity bound for the recorded launcher size; anything larger is a
  /// corrupt or forged record, not a launcher.
  MaxRollbackLauncherBytes = Int64(512) * 1024 * 1024;

{$IFDEF PORTAPPIX_TESTUPDATE}
var
  AllowInsecureReleaseUrls: Boolean = False;
{$ENDIF}

{$IFDEF PORTAPPIX_TESTINJECT}
type
  /// Deterministic failure injection for file renames (test builds only).
  /// Returns 0 to proceed with the real rename, or a Win32 error code to
  /// fail the rename with. Production binaries contain no reference to this.
  TPortappixRenameHook = reference to function(const AFrom,
    ATo: string): Integer;
var
  PortappixRenameHook: TPortappixRenameHook = nil;
  /// Non-zero Win32 error code injected into the next SpawnNewLauncher call.
  PortappixSpawnErrorCode: Integer = 0;
{$ENDIF}

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

/// Checks if AUrl is permitted for release metadata and payload download.
function IsPermittedReleaseUrl(const AUrl: string): Boolean;

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
    procedure RecordOldLauncher(const AOldExePath, AOldVersion: string);
    function RecordHmac(const ASha256: string; ASize: Int64;
      const AVersion, ARecordedAt: string): string;
    procedure ReStampRecordWithHmac(const AJsonText: string);
    /// TOCTOU-safe core of RollbackToOldLauncher: opens Launcher.exe.old with
    /// a write-denying handle, validates the authenticated record and the
    /// file's size/hash through that handle, and returns the handle. The
    /// caller performs the rename while the handle is still open and closes
    /// it afterwards.
    function OpenVerifiedOldLauncher(out AHandle: THandle;
      out AError: string): Boolean;
    /// Reads and fully validates the old_launcher.json text (schema, hex
    /// sha256, size bounds, version, optional ISO-8601 fields, schema-2
    /// HMAC). Returns False with AError set on any problem.
    function ValidateOldLauncherRecordText(const AJsonText: string;
      out AError, ASha256: string; out ASize: Int64;
      out AVersion, ARecordedAt: string; out ASchema: Integer): Boolean;
    /// Checked all-or-nothing restore after a failed in-swap update; raises
    /// when any restore step fails so the failure is never silent.
    procedure RestoreFailedSwap(const ARollbackDir: string;
      const AOkExisted, APendingExisted, ARecordBackupExisted: Boolean;
      const APreSwapSha256: string; AMovedRootFiles: TList<string>);
  public
    constructor Create(const ARootPath: string = '');
    function OldLauncherRecordFile: string;
    function InstalledVersion: string;
    procedure SetInstalledVersion(const AVersion: string);
    function PendingUpdateVersion: string;
    function IsUpdateAvailable(const ARelease: TPortappixRelease): Boolean;
    function NeedsRollbackOffer: Boolean;
    function VerifyOldLauncher(out AError: string): Boolean;
    procedure VerifyOldLauncherForRollback;
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
  // Prefixed backup names inside launcher_rollback_<timestamp>: distinct from
  // any possible release root-file name, and mapped back to their original
  // (Cache) locations by RestoreFailedSwap.
  RecordBackupName = 'rollback_old_launcher.json';
  OkBackupName = 'rollback_update_ok';
  PendingBackupName = 'rollback_update_pending.json';
  PreSwapBackupName = 'rollback_pre_swap.json';

{$IFDEF PORTAPPIX_TESTINJECT}
function UpdateRenameFile(const AFrom, ATo: string): Boolean;
var
  ErrorCode: Integer;
begin
  if Assigned(PortappixRenameHook) then
  begin
    ErrorCode := PortappixRenameHook(AFrom, ATo);
    if ErrorCode <> 0 then
    begin
      SetLastError(DWORD(ErrorCode));
      Exit(False);
    end;
  end;
  Result := RenameFile(AFrom, ATo);
end;
{$ELSE}
function UpdateRenameFile(const AFrom, ATo: string): Boolean;
begin
  Result := RenameFile(AFrom, ATo);
end;
{$ENDIF}

/// Checked file move used by the failed-swap restore: raises with context
/// instead of failing silently.
procedure CheckedMoveFile(const ASource, ATarget: string);
begin
  if not RenameFile(ASource, ATarget) then
    raise EPortappixUpdateError.CreateFmt(
      'Unable to restore "%s" to "%s" during the update rollback: %s',
      [ASource, ATarget, SysErrorMessage(Integer(GetLastError))]);
end;

/// Checked file delete used by the failed-swap restore: raises with context
/// instead of failing silently.
procedure CheckedDeleteFile(const AFileName: string);
begin
  if not TFile.Exists(AFileName) then
    Exit;
  try
    TFile.Delete(AFileName);
  except
    on E: Exception do
      raise EPortappixUpdateError.CreateFmt(
        'Unable to delete "%s" during the update rollback: %s',
        [AFileName, E.Message]);
  end;
end;

function GetExeFileVersion(const AExePath: string): string; forward;

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
    // TJSONNumber inherits from TJSONString in the Delphi RTL; reject numbers.
    if (not (Value is TJSONString)) or (Value is TJSONNumber) then
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
      if not IsValidSha256Hex(Result.Sha256) then
        raise EPortappixUpdateError.Create(
          'releases.json property "sha256" must be 64 hex characters.');

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

function IsPermittedReleaseUrl(const AUrl: string): Boolean;
var
  CleanUrl: string;
begin
  CleanUrl := AUrl.Trim;
  if IsHttpsUrl(CleanUrl) then
    Exit(True);
{$IFDEF PORTAPPIX_TESTUPDATE}
  if AllowInsecureReleaseUrls then
    Exit(True);
  if TextStartsWith(CleanUrl, 'http://127.0.0.1:') or
     TextStartsWith(CleanUrl, 'http://127.0.0.1/') or
     (CleanUrl = 'http://127.0.0.1') or
     TextStartsWith(CleanUrl, 'http://localhost:') or
     TextStartsWith(CleanUrl, 'http://localhost/') or
     (CleanUrl = 'http://localhost') then
    Exit(True);
{$ENDIF}
  Result := False;
end;

function DownloadReleases(const AUrl: string): TPortappixRelease;
var
  Content: TBytes;
  SignatureBytes: TBytes;
begin
  if AUrl.Trim = '' then
    raise EPortappixUpdateError.Create('Release URL must not be empty.');
  if not IsPermittedReleaseUrl(AUrl) then
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

function TPortappixUpdateManager.OldLauncherRecordFile: string;
begin
  Result := TPath.Combine(TPath.Combine(FRootPath, 'Cache'), 'old_launcher.json');
end;

procedure TPortappixUpdateManager.RecordOldLauncher(const AOldExePath,
  AOldVersion: string);
var
  RecordObj: TJSONObject;
  OldSha256: string;
  OldSize: Int64;
  NowIso: string;
begin
  OldSha256 := Sha256File(AOldExePath).ToLower;
  OldSize := TFile.GetSize(AOldExePath);
  NowIso := DateToISO8601(Now);

  RecordObj := TJSONObject.Create;
  try
    RecordObj.AddPair('schema', TJSONNumber.Create(OldLauncherRecordSchemaVersion));
    RecordObj.AddPair('sha256', OldSha256);
    RecordObj.AddPair('size', TJSONNumber.Create(OldSize));
    RecordObj.AddPair('version', AOldVersion);
    RecordObj.AddPair('time', NowIso);
    RecordObj.AddPair('recordedAt', NowIso);
    RecordObj.AddPair('hmac', RecordHmac(OldSha256, OldSize, AOldVersion, NowIso));
    ForceDirectories(TPath.GetDirectoryName(OldLauncherRecordFile));
    // Durable so a crash right after the swap cannot leave a missing or
    // half-written verification record behind the renamed executable.
    if not WriteTextFileDurable(OldLauncherRecordFile, RecordObj.Format(2)) then
      raise EPortappixUpdateError.Create('Unable to write old_launcher.json.');
  finally
    RecordObj.Free;
  end;
end;

function TPortappixUpdateManager.RecordHmac(const ASha256: string;
  ASize: Int64; const AVersion, ARecordedAt: string): string;
var
  Key: TBytes;
begin
  Key := GetRollbackKey;
  Result := ComputeRecordHmac(Key, ASha256, ASize, AVersion, ARecordedAt);
end;

function TPortappixUpdateManager.ValidateOldLauncherRecordText(
  const AJsonText: string; out AError, ASha256: string; out ASize: Int64;
  out AVersion, ARecordedAt: string; out ASchema: Integer): Boolean;
var
  JsonValue: TJSONValue;
  Root: TJSONObject;
  SchemaVal, ShaVal, SizeVal, VersionVal, HmacVal, FieldVal: TJSONValue;
  ExpectedHmac, RecordedHmac: string;
  ParsedDate: TDateTime;
begin
  AError := '';
  ASha256 := '';
  ASize := -1;
  AVersion := '';
  ARecordedAt := '';
  ASchema := 0;

  JsonValue := TJSONObject.ParseJSONValue(AJsonText);
  if (JsonValue = nil) or not (JsonValue is TJSONObject) then
  begin
    if JsonValue <> nil then
      JsonValue.Free;
    AError := 'Refusing rollback: rollback verification record is malformed (not a JSON object).';
    Exit(False);
  end;

  Root := TJSONObject(JsonValue);
  try
    SchemaVal := Root.FindValue('schema');
    if (SchemaVal = nil) or not (SchemaVal is TJSONNumber) then
    begin
      AError := 'Refusing rollback: rollback verification record has missing or unsupported schema.';
      Exit(False);
    end;
    ASchema := TJSONNumber(SchemaVal).AsInt;
    if (ASchema <> 1) and (ASchema <> OldLauncherRecordSchemaVersion) then
    begin
      AError := 'Refusing rollback: rollback verification record has missing or unsupported schema.';
      Exit(False);
    end;

    ShaVal := Root.FindValue('sha256');
    // NOTE: TJSONNumber inherits from TJSONString in the Delphi RTL, so a
    // numeric value would pass a plain `is TJSONString` check.
    if (ShaVal = nil) or not (ShaVal is TJSONString) or (ShaVal is TJSONNumber) or
       not IsValidSha256Hex(TJSONString(ShaVal).Value.Trim) then
    begin
      AError := 'Refusing rollback: rollback verification record has missing or invalid sha256.';
      Exit(False);
    end;
    ASha256 := TJSONString(ShaVal).Value.Trim.ToLower;

    SizeVal := Root.FindValue('size');
    if (SizeVal = nil) or not (SizeVal is TJSONNumber) then
    begin
      AError := 'Refusing rollback: rollback verification record has missing or invalid size.';
      Exit(False);
    end;
    ASize := TJSONNumber(SizeVal).AsInt64;
    if ASize < 0 then
    begin
      AError := 'Refusing rollback: rollback verification record specifies a negative size.';
      Exit(False);
    end;
    if ASize > MaxRollbackLauncherBytes then
    begin
      AError := Format('Refusing rollback: rollback verification record specifies an ' +
        'unreasonably large size (%d bytes, maximum %d bytes).',
        [ASize, MaxRollbackLauncherBytes]);
      Exit(False);
    end;

    VersionVal := Root.FindValue('version');
    if (VersionVal = nil) or not (VersionVal is TJSONString) or
       (VersionVal is TJSONNumber) or
       (TJSONString(VersionVal).Value.Trim = '') then
    begin
      AError := 'Refusing rollback: rollback verification record has missing or invalid version.';
      Exit(False);
    end;
    AVersion := TJSONString(VersionVal).Value.Trim;

    // Optional fields, validated only when present (schema-1 records written
    // by earlier launchers may omit them; that is the documented migration
    // input, not a corruption signal).
    for var TimeField in TArray<string>.Create('time', 'recordedAt') do
    begin
      FieldVal := Root.FindValue(TimeField);
      if FieldVal = nil then
        Continue;
      if (not (FieldVal is TJSONString)) or (FieldVal is TJSONNumber) then
      begin
        AError := Format('Refusing rollback: rollback verification record has an invalid "%s".',
          [TimeField]);
        Exit(False);
      end;
      try
        ParsedDate := ISO8601ToDate(TJSONString(FieldVal).Value, True);
      except
        on E: Exception do
        begin
          AError := Format('Refusing rollback: rollback verification record has an invalid "%s".',
            [TimeField]);
          Exit(False);
        end;
      end;
      if ParsedDate = 0 then
      begin
        AError := Format('Refusing rollback: rollback verification record has an invalid "%s".',
          [TimeField]);
        Exit(False);
      end;
    end;
    FieldVal := Root.FindValue('recordedAt');
    if (FieldVal <> nil) and (FieldVal is TJSONString) then
      ARecordedAt := TJSONString(FieldVal).Value;

    // Authentication: schema 2 requires a valid HMAC over the canonical
    // serialization of sha256/size/version/recordedAt. Schema 1 records are
    // the pre-authentication migration input and are re-stamped by the
    // caller after full verification.
    if ASchema >= 2 then
    begin
      HmacVal := Root.FindValue('hmac');
      if (HmacVal = nil) or not (HmacVal is TJSONString) or (HmacVal is TJSONNumber) then
      begin
        AError := 'Refusing rollback: rollback verification record has no HMAC.';
        Exit(False);
      end;
      RecordedHmac := TJSONString(HmacVal).Value.Trim;
      try
        ExpectedHmac := RecordHmac(ASha256, ASize, AVersion, ARecordedAt);
      except
        on E: Exception do
        begin
          AError := 'Refusing rollback: rollback record key unavailable: ' + E.Message;
          Exit(False);
        end;
      end;
      if not RecordHmacMatches(ExpectedHmac, RecordedHmac) then
      begin
        AError := 'Refusing rollback: rollback verification record HMAC mismatch ' +
          '(the record was modified after it was written).';
        Exit(False);
      end;
    end;
  finally
    Root.Free;
  end;

  Result := True;
end;

function TPortappixUpdateManager.VerifyOldLauncher(out AError: string): Boolean;
var
  JsonText: string;
  RecordSchema: Integer;
  ExpectedSha256, ActualSha256: string;
  ExpectedSize, ActualSize: Int64;
  ExpectedVersion, ActualExeVersion, ExpectedRecordedAt: string;
begin
  AError := '';
  if IsReparsePoint(OldLauncherExe) then
  begin
    AError := Format('Refusing rollback: "%s" is a reparse point or symbolic link.',
      [TPath.GetFileName(OldLauncherExe)]);
    Exit(False);
  end;

  if not TFile.Exists(OldLauncherExe) then
  begin
    AError := 'No Launcher.exe.old exists to restore.';
    Exit(False);
  end;

  if not TFile.Exists(OldLauncherRecordFile) then
  begin
    AError := Format(
      'Refusing rollback: rollback verification record ("%s") is missing.',
      [TPath.GetFileName(OldLauncherRecordFile)]);
    Exit(False);
  end;

  try
    JsonText := TFile.ReadAllText(OldLauncherRecordFile, TEncoding.UTF8);
  except
    on E: Exception do
    begin
      AError := Format('Refusing rollback: unable to read "%s": %s',
        [TPath.GetFileName(OldLauncherRecordFile), E.Message]);
      Exit(False);
    end;
  end;

  if not ValidateOldLauncherRecordText(JsonText, AError, ExpectedSha256,
    ExpectedSize, ExpectedVersion, ExpectedRecordedAt, RecordSchema) then
    Exit(False);

  ActualSize := TFile.GetSize(OldLauncherExe);
  if ActualSize <> ExpectedSize then
  begin
    AError := Format('Refusing rollback: "%s" size mismatch (expected %d bytes, got %d bytes).',
      [TPath.GetFileName(OldLauncherExe), ExpectedSize, ActualSize]);
    Exit(False);
  end;

  ActualSha256 := Sha256File(OldLauncherExe).ToLower;
  if not SameText(ActualSha256, ExpectedSha256) then
  begin
    AError := Format('Refusing rollback: "%s" SHA-256 mismatch (expected %s, got %s).',
      [TPath.GetFileName(OldLauncherExe), ExpectedSha256, ActualSha256]);
    Exit(False);
  end;

  // Version consistency: when the .old executable carries a readable
  // version resource, it must match the recorded version. Plain files
  // without a version resource skip this check (documented limitation).
  ActualExeVersion := GetExeFileVersion(OldLauncherExe);
  if (ActualExeVersion <> '') and (not SameText(ActualExeVersion, ExpectedVersion)) then
  begin
    AError := Format('Refusing rollback: recorded version "%s" does not match the ' +
      'file version of "%s" ("%s").', [ExpectedVersion,
      TPath.GetFileName(OldLauncherExe), ActualExeVersion]);
    Exit(False);
  end;

  // Migration: a verified schema-1 record is re-stamped as an authenticated
  // schema-2 record so every subsequent verification is HMAC-checked. This
  // is best-effort: if the key or write fails, the (still valid) schema-1
  // record remains in place and verification stays no weaker than before.
  if RecordSchema = 1 then
    try
      ReStampRecordWithHmac(JsonText);
    except
      on E: Exception do
        Log(Format('Unable to re-stamp the rollback record with an HMAC: %s',
          [E.Message]));
    end;

  Result := True;
end;

procedure TPortappixUpdateManager.ReStampRecordWithHmac(const AJsonText: string);
var
  Root, RecordObj: TJSONObject;
  NowIso: string;
  RecordedAt: string;
  Sha256Value: string;
  SizeValue: Int64;
  VersionValue: string;
begin
  Root := TJSONObject.ParseJSONValue(AJsonText) as TJSONObject;
  if Root = nil then
    Exit;
  try
    Sha256Value := Root.FindValue('sha256').Value.Trim.ToLower;
    SizeValue := TJSONNumber(Root.FindValue('size')).AsInt64;
    VersionValue := Root.FindValue('version').Value.Trim;
    if (Root.FindValue('recordedAt') <> nil) and (Root.FindValue('recordedAt') is TJSONString) then
      RecordedAt := TJSONString(Root.FindValue('recordedAt')).Value
    else
    begin
      NowIso := DateToISO8601(Now);
      RecordedAt := NowIso;
    end;

    RecordObj := TJSONObject.Create;
    try
      RecordObj.AddPair('schema', TJSONNumber.Create(OldLauncherRecordSchemaVersion));
      RecordObj.AddPair('sha256', Sha256Value);
      RecordObj.AddPair('size', TJSONNumber.Create(SizeValue));
      RecordObj.AddPair('version', VersionValue);
      if (Root.FindValue('time') <> nil) and (Root.FindValue('time') is TJSONString) then
        RecordObj.AddPair('time', TJSONString(Root.FindValue('time')).Value)
      else
        RecordObj.AddPair('time', DateToISO8601(Now));
      RecordObj.AddPair('recordedAt', RecordedAt);
      RecordObj.AddPair('hmac', RecordHmac(Sha256Value, SizeValue, VersionValue, RecordedAt));
      if not WriteTextFileDurable(OldLauncherRecordFile, RecordObj.Format(2)) then
        raise EPortappixUpdateError.Create('Unable to write old_launcher.json.');
    finally
      RecordObj.Free;
    end;
  finally
    Root.Free;
  end;
end;

procedure TPortappixUpdateManager.VerifyOldLauncherForRollback;
var
  ErrorMsg: string;
begin
  if not VerifyOldLauncher(ErrorMsg) then
    raise EPortappixUpdateError.Create(ErrorMsg);
end;

function TPortappixUpdateManager.OpenVerifiedOldLauncher(out AHandle: THandle;
  out AError: string): Boolean;
var
  JsonText: string;
  RecordSchema: Integer;
  ExpectedSha256, ActualSha256, ExpectedVersion, ActualExeVersion,
  ExpectedRecordedAt: string;
  ExpectedSize, ActualSize: Int64;
  Info: TByHandleFileInformation;
  Verified: Boolean;
begin
  AError := '';
  AHandle := 0;

  // Path-level reparse check first so the error message matches the
  // path-based verification; the handle-level attribute check below closes
  // the same hole at use time.
  if IsReparsePoint(OldLauncherExe) then
  begin
    AError := Format('Refusing rollback: "%s" is a reparse point or symbolic link.',
      [TPath.GetFileName(OldLauncherExe)]);
    Exit(False);
  end;

  if not TFile.Exists(OldLauncherExe) then
  begin
    AError := 'No Launcher.exe.old exists to restore.';
    Exit(False);
  end;

  if not TFile.Exists(OldLauncherRecordFile) then
  begin
    AError := Format(
      'Refusing rollback: rollback verification record ("%s") is missing.',
      [TPath.GetFileName(OldLauncherRecordFile)]);
    Exit(False);
  end;

  try
    JsonText := TFile.ReadAllText(OldLauncherRecordFile, TEncoding.UTF8);
  except
    on E: Exception do
    begin
      AError := Format('Refusing rollback: unable to read "%s": %s',
        [TPath.GetFileName(OldLauncherRecordFile), E.Message]);
      Exit(False);
    end;
  end;

  if not ValidateOldLauncherRecordText(JsonText, AError, ExpectedSha256,
    ExpectedSize, ExpectedVersion, ExpectedRecordedAt, RecordSchema) then
    Exit(False);

  // Open with a write-denying, delete-sharing handle. Without
  // FILE_SHARE_WRITE, a concurrent replacement attempt fails with a sharing
  // violation for the whole verify-to-move window; FILE_SHARE_DELETE lets
  // our own MoveFileEx succeed while the handle stays open.
  // FILE_FLAG_OPEN_REPARSE_POINT prevents a junction from being silently
  // followed; a reparse point is then detected via the handle attributes.
  AHandle := CreateFile(PChar(OldLauncherExe), GENERIC_READ,
    FILE_SHARE_READ or FILE_SHARE_DELETE, nil, OPEN_EXISTING,
    FILE_FLAG_OPEN_REPARSE_POINT, 0);
  if (AHandle = INVALID_HANDLE_VALUE) or (AHandle = 0) then
  begin
    AHandle := 0;
    AError := Format('Refusing rollback: unable to open "%s" (share-denied): %s',
      [TPath.GetFileName(OldLauncherExe), SysErrorMessage(Integer(GetLastError))]);
    Exit(False);
  end;

  Verified := False;
  try
    if not GetFileInformationByHandle(AHandle, Info) then
    begin
      AError := Format('Refusing rollback: unable to query "%s": %s',
        [TPath.GetFileName(OldLauncherExe), SysErrorMessage(Integer(GetLastError))]);
      Exit(False);
    end;
    if (Info.dwFileAttributes and FILE_ATTRIBUTE_REPARSE_POINT) <> 0 then
    begin
      AError := Format('Refusing rollback: "%s" is a reparse point or symbolic link.',
        [TPath.GetFileName(OldLauncherExe)]);
      Exit(False);
    end;

    ActualSize := (Int64(Info.nFileSizeHigh) shl 32) or Int64(Info.nFileSizeLow);
    if ActualSize <> ExpectedSize then
    begin
      AError := Format('Refusing rollback: "%s" size mismatch (expected %d bytes, got %d bytes).',
        [TPath.GetFileName(OldLauncherExe), ExpectedSize, ActualSize]);
      Exit(False);
    end;

    // Hash through the still-open handle: what we verify is exactly what the
    // later rename moves.
    ActualSha256 := Sha256Handle(AHandle).ToLower;
    if not SameText(ActualSha256, ExpectedSha256) then
    begin
      AError := Format('Refusing rollback: "%s" SHA-256 mismatch (expected %s, got %s).',
        [TPath.GetFileName(OldLauncherExe), ExpectedSha256, ActualSha256]);
      Exit(False);
    end;

    // Version consistency, mirroring the path-based verification.
    ActualExeVersion := GetExeFileVersion(OldLauncherExe);
    if (ActualExeVersion <> '') and (not SameText(ActualExeVersion, ExpectedVersion)) then
    begin
      AError := Format('Refusing rollback: recorded version "%s" does not match the ' +
        'file version of "%s" ("%s").', [ExpectedVersion,
        TPath.GetFileName(OldLauncherExe), ActualExeVersion]);
      Exit(False);
    end;

    Verified := True;
  finally
    // Any failed check (Exit or exception) releases the handle immediately;
    // only a fully verified handle is handed back to the caller.
    if (not Verified) and (AHandle <> 0) then
    begin
      CloseHandle(AHandle);
      AHandle := 0;
    end;
  end;

  Result := Verified;
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
    if not WriteTextFileDurable(VersionFile, Json.Format(2)) then
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
  Root: TJSONObject;
  VersionValue: TJSONValue;
  Ignored: TPortappixSemVer;
begin
  Result := '';
  if not TFile.Exists(PendingFile) then
    Exit;
  try
    JsonValue := TJSONObject.ParseJSONValue(
      TFile.ReadAllText(PendingFile, TEncoding.UTF8));
    try
      if (JsonValue = nil) or not (JsonValue is TJSONObject) then
        Exit;
      Root := TJSONObject(JsonValue);
      VersionValue := Root.FindValue('toVersion');
      if (VersionValue is TJSONString) and (not (VersionValue is TJSONNumber)) then
        Result := TJSONString(VersionValue).Value.Trim;
      // Field validation: the pending marker is trusted for nothing more
      // than the version string, and that string must be a well-formed
      // semantic version. Anything else is treated as no pending update.
      if (Result <> '') and (not TPortappixSemVer.TryParse(Result, Ignored)) then
      begin
        Log(Format('Ignoring corrupt update_pending.json: "%s" is not a semantic version.',
          [Result]));
        Result := '';
      end;
      VersionValue := Root.FindValue('fromVersion');
      if (VersionValue <> nil) and
         ((not (VersionValue is TJSONString)) or (VersionValue is TJSONNumber)) then
      begin
        Log('Ignoring corrupt update_pending.json: "fromVersion" is not a string.');
        Result := '';
      end;
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
  PreSwapSha256: string;
  OkExisted, PendingExisted, RecordBackupExisted, RestoreVerified: Boolean;
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

  // All-or-nothing swap. Back up EVERYTHING the swap may destroy or replace
  // before any mutation, so a failure anywhere later can restore the exact
  // previous state: replaced root files, the previous rollback record, the
  // update_ok watchdog marker and any pre-existing pending marker.
  RollbackDir := TPath.Combine(TPath.Combine(FRootPath, 'Cache'),
    Format('launcher_rollback_%s', [FormatDateTime('yyyymmdd_hhnnss_zzz', Now)]));
  ForceDirectories(RollbackDir);
  MovedRootFiles := TList<string>.Create;
  OkExisted := False;
  PendingExisted := False;
  RecordBackupExisted := False;
  RestoreVerified := False;
  PreSwapSha256 := '';
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

    RecordBackupExisted := TFile.Exists(OldLauncherRecordFile);
    if RecordBackupExisted then
      TFile.Copy(OldLauncherRecordFile,
        TPath.Combine(RollbackDir, RecordBackupName), True);

    OkExisted := TFile.Exists(OkFile);
    if OkExisted then
      TFile.Copy(OkFile, TPath.Combine(RollbackDir, OkBackupName), True);
    PendingExisted := TFile.Exists(PendingFile);
    if PendingExisted then
      TFile.Copy(PendingFile, TPath.Combine(RollbackDir, PendingBackupName), True);

    // The pre-swap hash is the invariant every failure restore is verified
    // against: after a rolled-back swap the launcher must be byte-identical
    // to what it was before the update started.
    PreSwapSha256 := Sha256File(LauncherExe).ToLower;
    TFile.WriteAllText(TPath.Combine(RollbackDir, PreSwapBackupName),
      '{"sha256":"' + PreSwapSha256 + '"}', TEncoding.UTF8);

    // Clean up any old update_ok marker so a crash during or after this
    // update will correctly trigger the watchdog. A copy is preserved in
    // RollbackDir and restored by the failure path below.
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
      if not WriteTextFileDurable(PendingFile, Pending.Format(2)) then
        raise EPortappixUpdateError.Create('Unable to write update_pending.json.');
    finally
      Pending.Free;
    end;

    // Swap. Renaming a running executable is allowed on Windows.
    var OldVersionBeforeSwap := InstalledVersion;
    try
      // A rollback copy from a previous confirmed update is superseded by
      // this update: remove it so the rename below has a free target.
      if TFile.Exists(OldLauncherExe) then
        CheckedDeleteFile(OldLauncherExe);

      // Record the saved old launcher's SHA-256 and size BEFORE the rename:
      // a crash between the rename and a later record write would leave
      // Launcher.exe.old with no verification record, permanently refusing
      // rollback. Writing first means every post-record failure window is
      // protected by the watchdog instead of a wedge.
      RecordOldLauncher(LauncherExe, OldVersionBeforeSwap);

      if not UpdateRenameFile(LauncherExe, OldLauncherExe) then
        raise EPortappixUpdateError.CreateFmt(
          'Unable to move the running launcher to "%s": %s',
          [OldLauncherExe, SysErrorMessage(Integer(GetLastError))]);

      if not UpdateRenameFile(NewExe, LauncherExe) then
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
      // All-or-nothing restore of every mutation this method performed.
      // Raises when any restore step fails, so the failure is never silent.
      RestoreFailedSwap(RollbackDir, OkExisted, PendingExisted,
        RecordBackupExisted, PreSwapSha256, MovedRootFiles);
      raise;
    end;

    RestoreVerified := True;
  finally
    MovedRootFiles.Free;
    if RestoreVerified then
    begin
      try
        if TDirectory.Exists(RollbackDir) then
          TDirectory.Delete(RollbackDir, True);
      except
      end;
    end
    else if TDirectory.Exists(RollbackDir) then
      // A failed restore keeps the backup directory for forensics and
      // manual recovery; deleting it would destroy the only remaining copy
      // of the previous state.
      Log(Format('The rollback backup directory "%s" was kept for manual inspection.',
        [RollbackDir]));
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

procedure TPortappixUpdateManager.RestoreFailedSwap(const ARollbackDir: string;
  const AOkExisted, APendingExisted, ARecordBackupExisted: Boolean;
  const APreSwapSha256: string; AMovedRootFiles: TList<string>);
var
  BaseName, Target, BackupFile: string;
  RestoredSha256: string;
begin
  Log('Update swap failed; rolling back all files and previous metadata.');

  // 1. Remove any new release root files that were already moved into place.
  for var MovedFile in AMovedRootFiles do
    CheckedDeleteFile(MovedFile);

  // 2. Restore every backed-up file. Prefixed names map back to their
  //    original Cache locations; unprefixed names are release root files and
  //    restore to the root. Idempotent: files that were never touched have
  //    no current target to delete.
  for BackupFile in TDirectory.GetFiles(ARollbackDir) do
  begin
    BaseName := TPath.GetFileName(BackupFile);
    if SameText(BaseName, PreSwapBackupName) then
      Continue; // internal restore artifact, not a backed-up file
    if SameText(BaseName, RecordBackupName) then
      Target := OldLauncherRecordFile
    else if SameText(BaseName, OkBackupName) then
      Target := OkFile
    else if SameText(BaseName, PendingBackupName) then
      Target := PendingFile
    else
      Target := TPath.Combine(FRootPath, BaseName);
    CheckedDeleteFile(Target);
    CheckedMoveFile(BackupFile, Target);
  end;

  // 3. If this was the first update there was no previous record to back up,
  //    but RecordOldLauncher may already have written a new one; a swap
  //    failure must not leave a record describing a non-existent .old.
  if (not ARecordBackupExisted) and TFile.Exists(OldLauncherRecordFile) then
    CheckedDeleteFile(OldLauncherRecordFile);

  // 3b. The freshly written pending marker describes an update that never
  //     happened; remove it unless the pre-existing one was just restored.
  if (not APendingExisted) and TFile.Exists(PendingFile) then
    CheckedDeleteFile(PendingFile);

  // 4. Restore the original executable, then verify the invariant.
  if TFile.Exists(LauncherExe) then
  begin
    RestoredSha256 := Sha256File(LauncherExe).ToLower;
    if not SameText(RestoredSha256, APreSwapSha256) then
    begin
      // Launcher.exe is the new (partly installed) executable: remove it and
      // move the preserved original back.
      CheckedDeleteFile(LauncherExe);
      if TFile.Exists(OldLauncherExe) then
        CheckedMoveFile(OldLauncherExe, LauncherExe);
    end;
  end
  else if TFile.Exists(OldLauncherExe) then
    CheckedMoveFile(OldLauncherExe, LauncherExe);

  // 5. Post-restore invariant: the launcher must exist and be
  //    byte-identical to the pre-swap state.
  if not TFile.Exists(LauncherExe) then
    raise EPortappixUpdateError.Create(
      'Update rollback incomplete: Launcher.exe is missing after the restore.');
  RestoredSha256 := Sha256File(LauncherExe).ToLower;
  if not SameText(RestoredSha256, APreSwapSha256) then
    raise EPortappixUpdateError.CreateFmt(
      'Update rollback verification failed: the restored launcher does not ' +
      'match the pre-swap state (expected %s, got %s).',
      [APreSwapSha256, RestoredSha256]);

  // 6. Metadata invariants: previous record restored (or absent when there
  //    was none), previous markers restored (or absent when there were none).
  if not ARecordBackupExisted then
  begin
    if TFile.Exists(OldLauncherRecordFile) then
      raise EPortappixUpdateError.Create(
        'Update rollback incomplete: a stale rollback record survived the restore.');
    if TFile.Exists(OldLauncherExe) then
      raise EPortappixUpdateError.Create(
        'Update rollback incomplete: Launcher.exe.old survived the restore.');
  end
  else if not TFile.Exists(OldLauncherRecordFile) then
    raise EPortappixUpdateError.Create(
      'Update rollback incomplete: the previous rollback record was not restored.');
  if AOkExisted and (not TFile.Exists(OkFile)) then
    raise EPortappixUpdateError.Create(
      'Update rollback incomplete: the update_ok marker was not restored.');
  if (not AOkExisted) and TFile.Exists(OkFile) then
    raise EPortappixUpdateError.Create(
      'Update rollback incomplete: a stale update_ok marker survived the restore.');
  if APendingExisted and (not TFile.Exists(PendingFile)) then
    raise EPortappixUpdateError.Create(
      'Update rollback incomplete: the pending update marker was not restored.');
  if (not APendingExisted) and TFile.Exists(PendingFile) then
    raise EPortappixUpdateError.Create(
      'Update rollback incomplete: a stale pending update marker survived the restore.');

  Log('All files rolled back and the previous launcher was restored and verified.');
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

    if not IsPermittedReleaseUrl(Release.Url) then
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
    if not WriteTextFileDurable(OkFile, OkContent.Format(2)) then
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
  StaleExe, ErrorMsg: string;
  OldHandle: THandle;
begin
  // TOCTOU-safe restore: the same handle that verified size and hash stays
  // open (write-denying) until the rename has completed, so the file that
  // was verified is exactly the file that gets moved.
  if not OpenVerifiedOldLauncher(OldHandle, ErrorMsg) then
    raise EPortappixUpdateError.Create(ErrorMsg);
  try
    Log('Restoring the previous launcher version...');
    StaleExe := Format('%s.failed_%s', [LauncherExe,
      FormatDateTime('yyyymmdd_hhnnss', Now)]);

    if not UpdateRenameFile(LauncherExe, StaleExe) then
      raise EPortappixUpdateError.CreateFmt(
        'Unable to move the failing launcher to "%s": %s',
        [StaleExe, SysErrorMessage(Integer(GetLastError))]);

    try
      if not UpdateRenameFile(OldLauncherExe, LauncherExe) then
        raise EPortappixUpdateError.CreateFmt(
          'Unable to restore "%s": %s',
          [LauncherExe, SysErrorMessage(Integer(GetLastError))]);
    except
      // Checked restore of the failing launcher: a silent failure here would
      // leave the installation without any launcher.
      if RenameFile(StaleExe, LauncherExe) then
        Log('Rollback failed; the failing launcher was restored in place.')
      else
        raise EPortappixUpdateError.CreateFmt(
          'Rollback failed and "%s" could not be restored from "%s": %s',
          [LauncherFileName, StaleExe, SysErrorMessage(Integer(GetLastError))]);
      raise;
    end;
  finally
    CloseHandle(OldHandle);
  end;

  RemoveFileQuiet(OkFile);
  RemoveFileQuiet(PendingFile);
  RemoveFileQuiet(OldLauncherRecordFile);
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
  {$IFDEF PORTAPPIX_TESTINJECT}
  if PortappixSpawnErrorCode <> 0 then
    raise EPortappixUpdateError.CreateFmt('Unable to start "%s": %s',
      [LauncherFileName, SysErrorMessage(PortappixSpawnErrorCode)]);
  {$ENDIF}
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
