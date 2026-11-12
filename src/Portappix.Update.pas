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
  EPortappixSimulatedUpdateCrash = class(Exception);
var
  PortappixRenameHook: TPortappixRenameHook = nil;
  /// Non-zero Win32 error code injected into the next SpawnNewLauncher call.
  PortappixSpawnErrorCode: Integer = 0;
  /// Armed update-swap crash checkpoint (e.g. 'swap:after-rename-old').
  /// CheckUpdateCrashPoint raises when the armed point is reached. Test
  /// builds only; production binaries contain no reference to any of these.
  PortappixUpdateCrashPoint: string = '';
  /// Invoked inside RollbackToOldLauncher while the verified handle is open
  /// and before the restore rename — the deterministic window for concurrent
  /// rename-and-replace attack repro tests. Test builds only.
  PortappixRollbackAttackHook: TProc = nil;
  /// When True, a fired update crash point also suppresses the failure
  /// restore (RestoreFailedSwap) — simulating abrupt process death where the
  /// exception handler never runs. Test builds only.
  PortappixUpdateCrashKill: Boolean = False;
type
  /// Deterministic failure injection for the companion-file backup transfer,
  /// companion restore moves, companion/introduced-file deletes and the
  /// companion/staging directory deletes (R15/R16 repros). Return 0 to
  /// proceed with the real operation, or a Win32 error code to fail it with.
  /// Test builds only; production binaries contain no reference to these.
  TPortappixFileMoveHook = reference to function(const AFrom,
    ATo: string): Integer;
  TPortappixFileDeleteHook = reference to function(
    const APath: string): Integer;
  TPortappixDirectoryDeleteHook = reference to function(
    const APath: string): Integer;
var
  PortappixFileMoveHook: TPortappixFileMoveHook = nil;
  PortappixFileDeleteHook: TPortappixFileDeleteHook = nil;
  PortappixDirectoryDeleteHook: TPortappixDirectoryDeleteHook = nil;
const
  UpdateSwapCrashAfterRenameOld = 'swap:after-rename-old';
  UpdateFinalizeCrashBeforeSwap = 'finalize:before-swap';
  UpdateFinalizeCrashAfterSwap = 'finalize:after-swap';
  UpdateFinalizeCrashAfterRootFiles = 'finalize:after-root-files';
  UpdateFinalizeCrashAfterCompanions = 'finalize:after-preserve-companions';
  UpdateFinalizeCrashAfterNewDir = 'finalize:after-newdir-delete';
procedure CheckUpdateCrashPoint(const APoint: string);
{$ENDIF}

{$IFDEF PORTAPPIX_TESTINJECT}
/// Test-only entry point for the R18 rename repro (declared in the interface
/// so test projects can call it): performs a handle-based rename exactly as
/// the production rollback path does. Referenced nowhere in production code
/// (byte-scanned by the isolation suite).
function PortappixTestRenameByHandle(const AHandle: THandle;
  const ANewName: string): Boolean;
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
    /// Verification variant: never creates the key (fail closed when the
    /// key blob is missing). Returns False instead of raising.
    function TryRecordHmac(out AHmac, AKeyError: string; const ASha256: string;
      ASize: Int64; const AVersion, ARecordedAt: string): Boolean;
    /// Best-effort durable write of the R9 advisory establishment flag.
    procedure WriteMigrationFlag;
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
    /// Cache\rollback_migration.flag (R9 advisory establishment marker).
    function MigrationFlagFile: string;
    /// Persistent companion-file backup directory (R14).
    function CompanionBackupDir: string;
    /// R16: Cache\companion_rollback_staging — the fresh transfer directory.
    function CompanionTransferDir: string;
    /// R15/R16: the authoritative companion manifest inside the backup dir.
    function CompanionManifestFile: string;
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
    /// R11: True when an update was staged but the atomic finalize has not
    /// yet completed (recovery respawn condition).
    function UnfinalizedPendingUpdate: Boolean;
    /// R11: performs the atomic swap (ReplaceFileW with backup) and
    /// companion installation in the finalize-helper process. Idempotent:
    /// a completed swap is detected and only the remaining steps run.
    procedure FinalizePendingUpdate;
    /// R11: spawns launcher_new\Launcher.exe --finalize-update for this root.
    procedure SpawnUpdateHelper;
    function ReadPendingStagingDir: string;
    /// R20: Cache\update_swap_done.json — the durable marker written
    /// immediately after ReplaceFileW succeeds. It is the authoritative
    /// evidence of a completed swap on resume (the staged source binary is
    /// consumed by ReplaceFileW, so it can no longer be used as the signal).
    function SwapDoneFile: string;
    /// R20: True when the durable swap-done marker exists AND the installed
    /// launcher still matches the hash it records.
    function SwapAlreadyCompleted: Boolean;
    /// R20: records the completed swap durably (and removes it on restore).
    procedure WriteSwapDoneMarker(const ANewSha256, AOldSha256: string);
    procedure RemoveSwapDoneMarker;
    /// R14/R16: moves the surviving root-file backups from the staging dir
    /// into the persistent companion backup directory — only after every
    /// backup has been transferred AND verified, and only after the durable
    /// companion manifest (replaced vs introduced files) has been written.
    /// The previous companion directory and the staging directory are never
    /// destroyed on a failed transfer.
    procedure PreserveCompanionBackups(const AStagingDir: string);
    /// R15/R16: the file names the staged update INTRODUCED (shipped in the
    /// package without a previous version), read from the companion manifest.
    function ReadCompanionManifestIntroduced(
      const AManifestFile: string): TArray<string>;
    procedure SpawnProcess(const AExePath, AArguments: string);
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
  /// Persistent companion-file backup directory (R14): survives the swap and
  /// is consumed by ConfirmUpdate or RollbackToOldLauncher.
  CompanionBackupDirName = 'companion_rollback';
  /// R16: the fresh companion transfer directory. The new backups are moved
  /// here and verified FIRST; the previous companion directory is only
  /// replaced once every file is verified and the manifest is written.
  CompanionTransferDirName = 'companion_rollback_staging';
  /// R15/R16 manifest inside the companion backup directory: names the files
  /// the update REPLACED (with their verified sha256) and the files the
  /// update INTRODUCED (no previous version — rollback must delete them).
  CompanionManifestName = 'companion_manifest.json';
  /// Bookkeeping file inside launcher_rollback_<timestamp> (R15/R16): the
  /// non-launcher root files the package ships. Introduced files are the
  /// staged files without a backup; recorded before finalize so the
  /// manifest is correct even when finalize resumes after a crash.
  StagedFilesName = 'staged_files.json';
  /// R20: durable marker written IMMEDIATELY after ReplaceFileW succeeds.
  /// Without it, a resume had to infer the completed swap from a hash
  /// comparison — and ReplaceFileW consumes the staged source binary, so the
  /// next resume failed hard ("staged launcher binary is missing") even
  /// though the installation was already correct.
  SwapDoneName = 'update_swap_done.json';
  CompanionManifestSchema = 1;
  /// Unauthenticated advisory marker written when authenticated schema-2
  /// operation is established (R9): if it exists without the key blob,
  /// rollback is refused entirely (fail closed, no downgrade).
  MigrationFlagFileName = 'rollback_migration.flag';
  /// DELETE access right (winnt.h $10000). The bare identifier collides with
  /// the built-in System.Delete procedure.
  FILE_ACCESS_DELETE = $00010000;

type
  // FILE_RENAME_INFO (win32) header for handle-based renames (R10, R18):
  // the verified file is moved through its write-denying handle, so an
  // attacker cannot swap the pathname after verification. Only the fixed
  // header is declared; the variable-length FileName follows it in a
  // dynamically sized buffer at FILE_RENAME_INFO_NAME_OFFSET (R18 — a fixed
  // MAX_PATH array corrupts the stack for long paths, and on x64 the C name
  // offset (20) differs from Delphi's padded SizeOf (24)).
  TFileRenameInfoHeader = record
    Flags: DWORD;
    RootDirectory: THandle;
    FileNameLength: DWORD;
  end;

const
  FILE_INFO_CLASS_RENAME = 3;
  FILE_RENAME_FLAG_POSIX_SEMANTICS = 2; // no replace-if-exists
  /// offsetof(FILE_RENAME_INFO, FileName). The C layout is
  ///   {union{BOOLEAN ReplaceIfExists; DWORD Flags;}; HANDLE RootDirectory;
  ///    DWORD FileNameLength; WCHAR FileName[1];}
  /// On x86 the name starts at 4+4+4 = 12; on x64 the Flags field is padded
  /// to the 8-byte alignment of RootDirectory, so the name starts at
  /// 8+8+4 = 20. Delphi pads the header record the same way (SizeOf is 24
  /// on x64), so the name offset must NOT be derived from SizeOf (R18).
  FILE_RENAME_INFO_NAME_OFFSET = SizeOf(THandle) * 2 + SizeOf(DWORD);
  /// ReplaceFileW option: overwrite the backup file if it exists (winnt.h
  /// REPLACE_EXISTING; not declared in the Delphi RTL).
  REPLACEFILE_REPLACE_EXISTING = $00000001;

// Not declared by the Delphi RTL; kernel32 export used for handle-based
// renames (requires DELETE access on the handle).
function SetFileInformationByHandle(hFile: THandle; FileInformationClass: Integer;
  lpFileInformation: Pointer; dwBufferSize: DWORD): BOOL; stdcall;
  external 'kernel32.dll' name 'SetFileInformationByHandle';

/// Renames the file behind AHandle to ANewName (no replace) through the
/// handle itself. Requires DELETE access on the handle. R18: the buffer is
/// sized dynamically (name offset + name + null terminator) so long Windows
/// paths cannot overflow the fixed MAX_PATH-sized storage the previous
/// implementation used (which corrupted the stack for >261-char targets).
/// The name is placed at FILE_RENAME_INFO_NAME_OFFSET — the exact C-layout
/// offset on both x86 (12) and x64 (20), NOT at SizeOf(header) (24 on x64).
function RenameByHandle(const AHandle: THandle; const ANewName: string): Boolean;
var
  Buffer: TBytes;
  Info: ^TFileRenameInfoHeader;
  NameLength: Integer;
  NamePtr: PWideChar;
begin
  NameLength := Length(ANewName);
  SetLength(Buffer, FILE_RENAME_INFO_NAME_OFFSET +
    (NameLength + 1) * SizeOf(WideChar));
  FillChar(Buffer[0], Length(Buffer), 0);
  Info := @Buffer[0];
  Info.Flags := FILE_RENAME_FLAG_POSIX_SEMANTICS;
  Info.FileNameLength := DWORD(NameLength * SizeOf(WideChar));
  NamePtr := PWideChar(PByte(@Buffer[0]) + FILE_RENAME_INFO_NAME_OFFSET);
  if NameLength > 0 then
    Move(PChar(ANewName)^, NamePtr^, NameLength * SizeOf(WideChar));
  Result := SetFileInformationByHandle(AHandle, FILE_INFO_CLASS_RENAME,
    Info, DWORD(Length(Buffer)));
end;

{$IFDEF PORTAPPIX_TESTINJECT}
function PortappixTestRenameByHandle(const AHandle: THandle;
  const ANewName: string): Boolean;
begin
  Result := RenameByHandle(AHandle, ANewName);
end;
{$ENDIF}

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

/// Moves AFrom to ATo for the companion backup transfer and restore paths
/// (R15/R16). Test builds dispatch PortappixFileMoveHook first.
function CompanionMoveFile(const AFrom, ATo: string): Boolean;
{$IFDEF PORTAPPIX_TESTINJECT}
var
  ErrorCode: Integer;
begin
  if Assigned(PortappixFileMoveHook) then
  begin
    ErrorCode := PortappixFileMoveHook(AFrom, ATo);
    if ErrorCode <> 0 then
    begin
      SetLastError(DWORD(ErrorCode));
      Exit(False);
    end;
  end;
  Result := MoveFileEx(PChar(AFrom), PChar(ATo),
    MOVEFILE_REPLACE_EXISTING or MOVEFILE_WRITE_THROUGH);
end;
{$ELSE}
begin
  Result := MoveFileEx(PChar(AFrom), PChar(ATo),
    MOVEFILE_REPLACE_EXISTING or MOVEFILE_WRITE_THROUGH);
end;
{$ENDIF}

/// Deletes a single file for the companion restore paths (R15). Test builds
/// dispatch PortappixFileDeleteHook first.
function CompanionDeleteFile(const AFileName: string): Boolean;
{$IFDEF PORTAPPIX_TESTINJECT}
var
  ErrorCode: Integer;
begin
  if Assigned(PortappixFileDeleteHook) then
  begin
    ErrorCode := PortappixFileDeleteHook(AFileName);
    if ErrorCode <> 0 then
    begin
      SetLastError(DWORD(ErrorCode));
      Exit(False);
    end;
  end;
  try
    TFile.Delete(AFileName);
    Result := True;
  except
    Exit(False);
  end;
end;
{$ELSE}
begin
  try
    TFile.Delete(AFileName);
    Result := True;
  except
    Result := False;
  end;
end;
{$ENDIF}

/// Deletes a directory for the companion/staging cleanup paths (R15/R16).
/// Test builds dispatch PortappixDirectoryDeleteHook first.
function CompanionDeleteDirectory(const APath: string;
  const ARecursive: Boolean): Boolean;
{$IFDEF PORTAPPIX_TESTINJECT}
var
  ErrorCode: Integer;
begin
  if Assigned(PortappixDirectoryDeleteHook) then
  begin
    ErrorCode := PortappixDirectoryDeleteHook(APath);
    if ErrorCode <> 0 then
    begin
      SetLastError(DWORD(ErrorCode));
      Exit(False);
    end;
  end;
  try
    TDirectory.Delete(APath, ARecursive);
    Result := True;
  except
    Exit(False);
  end;
end;
{$ELSE}
begin
  try
    TDirectory.Delete(APath, ARecursive);
    Result := True;
  except
    Result := False;
  end;
end;
{$ENDIF}

{$IFDEF PORTAPPIX_TESTINJECT}
procedure CheckUpdateCrashPoint(const APoint: string);
begin
  if PortappixUpdateCrashPoint = APoint then
    raise EPortappixSimulatedUpdateCrash.Create(APoint);
end;
{$ELSE}
function UpdateKillSimulated(const E: Exception): Boolean;
begin
  Result := False;
end;
{$ENDIF}

{$IFDEF PORTAPPIX_TESTINJECT}
function UpdateKillSimulated(const E: Exception): Boolean;
begin
  // A simulated abrupt termination suppresses the failure restore: the
  // process is gone, no exception handler could have run.
  Result := PortappixUpdateCrashKill and (E is EPortappixSimulatedUpdateCrash);
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
    try
      Client.UserAgent := 'Portappix';
      Response := Client.Get(AUrl, Stream);

      if (Response = nil) or (Response.StatusCode < 200) or (Response.StatusCode >= 300) then
      begin
        if Response = nil then
          raise EPortappixUpdateError.CreateFmt('Unable to download "%s".', [AUrl]);
        raise EPortappixUpdateError.CreateFmt('Unable to download "%s" (HTTP %d).',
          [AUrl, Response.StatusCode]);
      end;

      if Stream.Size > Int64(2) * 1024 * 1024 * 1024 then
        raise EPortappixUpdateError.CreateFmt(
          'Downloaded file "%s" exceeds size limit of 2 GiB.', [AUrl]);
    finally
      // Release the .download handle BEFORE any cleanup touches the file
      // (the previous handler deleted it under the open stream and masked
      // the real error with a raw sharing violation).
      Client.Free;
      Stream.Free;
    end;
  except
    on E: EPortappixUpdateError do
    begin
      if TFile.Exists(ADestination + '.download') then
        try
          TFile.Delete(ADestination + '.download');
        except
        end;
      raise;
    end;
    on E: Exception do
    begin
      if TFile.Exists(ADestination + '.download') then
        try
          TFile.Delete(ADestination + '.download');
        except
        end;
      raise EPortappixUpdateError.CreateFmt('Unable to download "%s": %s',
        [AUrl, E.Message]);
    end;
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

function TPortappixUpdateManager.MigrationFlagFile: string;
begin
  Result := TPath.Combine(TPath.Combine(FRootPath, 'Cache'),
    MigrationFlagFileName);
end;

function TPortappixUpdateManager.CompanionBackupDir: string;
begin
  Result := TPath.Combine(TPath.Combine(FRootPath, 'Cache'),
    CompanionBackupDirName);
end;

function TPortappixUpdateManager.CompanionTransferDir: string;
begin
  // R16 fresh transfer directory: never authoritative until renamed over
  // the previous companion directory (which requires the removal below).
  Result := TPath.Combine(TPath.Combine(FRootPath, 'Cache'),
    CompanionTransferDirName);
end;

function TPortappixUpdateManager.CompanionManifestFile: string;
begin
  Result := TPath.Combine(CompanionBackupDir, CompanionManifestName);
end;

/// R15/R16: reads the "introduced" file list from the companion manifest.
/// A missing manifest (pre-R15 companion directory) yields an empty list.
/// A malformed manifest yields an empty list with a logged warning — the
/// rollback of the launcher itself is never blocked by companion metadata;
/// the replacement files are still restored from their backups.
function TPortappixUpdateManager.ReadCompanionManifestIntroduced(
  const AManifestFile: string): TArray<string>;
var
  JsonValue: TJSONValue;
  Root: TJSONObject;
  Arr: TJSONArray;
  I: Integer;
  Name: string;
begin
  SetLength(Result, 0);
  if not TFile.Exists(AManifestFile) then
    Exit;
  try
    JsonValue := TJSONObject.ParseJSONValue(
      TFile.ReadAllText(AManifestFile, TEncoding.UTF8));
    if JsonValue = nil then
      Exit;
    try
      if not (JsonValue is TJSONObject) then
        Exit;
      Root := TJSONObject(JsonValue);
      if (Root.FindValue('schema') = nil) or
         (not (Root.FindValue('schema') is TJSONNumber)) or
         (TJSONNumber(Root.FindValue('schema')).AsInt <>
           CompanionManifestSchema) then
        Exit;
      Arr := Root.FindValue('introduced') as TJSONArray;
      if Arr = nil then
        Exit;
      SetLength(Result, Arr.Count);
      for I := 0 to Arr.Count - 1 do
      begin
        Name := Arr.Items[I].Value;
        if (Name = '') or (not IsSafeFileComponent(Name)) then
        begin
          // Fail closed for this list: a manifest entry that is not a safe
          // file component cannot be interpreted — drop the whole list so a
          // tampered manifest can never make rollback delete arbitrary paths.
          SetLength(Result, 0);
          Log('The companion manifest contains an unsafe file name; the ' +
            'introduced-file list is ignored.');
          Exit;
        end;
        Result[I] := Name;
      end;
    finally
      JsonValue.Free;
    end;
  except
    on E: Exception do
    begin
      SetLength(Result, 0);
      Log(Format('Unable to read the companion manifest "%s": %s',
        [AManifestFile, E.Message]));
    end;
  end;
end;

procedure TPortappixUpdateManager.WriteMigrationFlag;
var
  Flag: TJSONObject;
begin
  // Best-effort: the authoritative establishment marker is the DPAPI key
  // blob; this unauthenticated flag only enables the fail-closed detection
  // of a deleted key blob (R9).
  try
    ForceDirectories(TPath.GetDirectoryName(MigrationFlagFile));
    Flag := TJSONObject.Create;
    try
      Flag.AddPair('establishedAt', DateToISO8601(Now));
      Flag.AddPair('reason', 'authenticated rollback records established');
      if not WriteTextFileDurable(MigrationFlagFile, Flag.Format(2)) then
        Log('Unable to write the rollback establishment flag (advisory only).');
    finally
      Flag.Free;
    end;
  except
    on E: Exception do
      Log(Format('Unable to write the rollback establishment flag: %s',
        [E.Message]));
  end;
end;

function TPortappixUpdateManager.TryRecordHmac(out AHmac, AKeyError: string;
  const ASha256: string; ASize: Int64; const AVersion,
  ARecordedAt: string): Boolean;
var
  Key: TBytes;
begin
  Result := False;
  AHmac := '';
  AKeyError := '';
  if not TryGetInstallationRollbackKey(FRootPath, Key) then
  begin
    AKeyError := 'the rollback record key is not available on this ' +
      'installation (verification never creates it)';
    Exit;
  end;
  try
    AHmac := ComputeRecordHmac(Key, ASha256, ASize, AVersion, ARecordedAt);
    Result := True;
  except
    on E: Exception do
    begin
      AKeyError := E.Message;
      Result := False;
    end;
  end;
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
    // R9: this schema-2 record write establishes authenticated rollback
    // operation for this installation (key blob + advisory flag).
    WriteMigrationFlag;
  finally
    RecordObj.Free;
  end;
end;

function TPortappixUpdateManager.RecordHmac(const ASha256: string;
  ASize: Int64; const AVersion, ARecordedAt: string): string;
var
  Key: TBytes;
begin
  Key := GetInstallationRollbackKey(FRootPath);
  Result := ComputeRecordHmac(Key, ASha256, ASize, AVersion, ARecordedAt);
end;

function TPortappixUpdateManager.ValidateOldLauncherRecordText(
  const AJsonText: string; out AError, ASha256: string; out ASize: Int64;
  out AVersion, ARecordedAt: string; out ASchema: Integer): Boolean;
var
  JsonValue: TJSONValue;
  Root: TJSONObject;
  SchemaVal, ShaVal, SizeVal, VersionVal, HmacVal, FieldVal: TJSONValue;
  ExpectedHmac, RecordedHmac, KeyError: string;
  ParsedDate: TDateTime;
begin
  AError := '';
  ASha256 := '';
  ASize := -1;
  AVersion := '';
  ARecordedAt := '';
  ASchema := 0;

  // R9: establishment state gates. Once authenticated schema-2 operation is
  // established (key blob exists or the advisory flag is present), legacy
  // schema-1 records are rejected unconditionally — an attacker must not be
  // able to launder a new record through the migration path. The fail-closed
  // combination (flag present, key blob missing) refuses rollback entirely.
  if TFile.Exists(MigrationFlagFile) and
     (not InstallationKeyBlobExists(FRootPath)) then
  begin
    AError := 'Refusing rollback: the rollback authentication state is ' +
      'inconsistent (establishment flag present without the key blob); ' +
      'manual inspection is required.';
    Exit(False);
  end;

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
    // R9: schema-1 records are the migration input ONLY before authenticated
    // schema-2 operation was established. Afterwards they are refused —
    // accepting them would let an attacker downgrade around the HMAC.
    if ASchema = 1 then
    begin
      if InstallationKeyBlobExists(FRootPath) or TFile.Exists(MigrationFlagFile) then
      begin
        AError := 'Refusing rollback: legacy (schema-1) rollback records are ' +
          'not accepted once authenticated rollback records are established.';
        Exit(False);
      end;
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
      if not TryRecordHmac(ExpectedHmac, KeyError, ASha256, ASize, AVersion,
        ARecordedAt) then
      begin
        AError := 'Refusing rollback: rollback record key unavailable: ' + KeyError;
        Exit(False);
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
      // R9: the re-stamp establishes authenticated rollback operation.
      WriteMigrationFlag;
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

  // Open with a write-denying handle that ALSO denies delete sharing (R10):
  // without FILE_SHARE_DELETE, an external process cannot rename or delete
  // the file during the entire verify-to-move window. The handle carries
  // DELETE access so the verified file can be moved through it with
  // SetFileInformationByHandle(FileRenameInfo).
  // FILE_FLAG_OPEN_REPARSE_POINT prevents a junction from being silently
  // followed; a reparse point is then detected via the handle attributes.
  AHandle := CreateFile(PChar(OldLauncherExe), GENERIC_READ or FILE_ACCESS_DELETE,
    FILE_SHARE_READ, nil, OPEN_EXISTING,
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
      // P3: full field validation — every remaining optional field must be
      // well-formed, otherwise the whole marker is treated as no pending.
      VersionValue := Root.FindValue('channel');
      if (VersionValue <> nil) and
         ((not (VersionValue is TJSONString)) or (VersionValue is TJSONNumber)) then
      begin
        Log('Ignoring corrupt update_pending.json: "channel" is not a string.');
        Result := '';
      end;
      VersionValue := Root.FindValue('appliedAt');
      if (VersionValue <> nil) and (VersionValue is TJSONString) and
         (not (VersionValue is TJSONNumber)) then
      begin
        try
          ISO8601ToDate(TJSONString(VersionValue).Value, True);
        except
          Log('Ignoring corrupt update_pending.json: "appliedAt" is not ISO-8601.');
          Result := '';
        end;
      end
      else if VersionValue <> nil then
      begin
        Log('Ignoring corrupt update_pending.json: "appliedAt" is not a string.');
        Result := '';
      end;
      VersionValue := Root.FindValue('stagingDir');
      if (VersionValue <> nil) and
         ((not (VersionValue is TJSONString)) or (VersionValue is TJSONNumber)) then
      begin
        Log('Ignoring corrupt update_pending.json: "stagingDir" is not a string.');
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
  RollbackDir, StagingName: string;
  BaseName, ExistingTarget: string;
  PreSwapSha256: string;
  OkExisted, PendingExisted, RecordBackupExisted, RestoreVerified: Boolean;
  MovedRootFiles: TList<string>;
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

  // Staging phase (R11): NOTHING in the installation root is moved or
  // replaced here. Everything the finalize step may need is backed up, the
  // authenticated rollback record is written for the CURRENT launcher, and
  // the atomic swap itself (ReplaceFileW with backup) is performed by the
  // finalize helper once this process has exited — Launcher.exe is never
  // missing, not even for a moment between two renames.
  StagingName := Format('launcher_rollback_%s',
    [FormatDateTime('yyyymmdd_hhnnss_zzz', Now)]);
  RollbackDir := TPath.Combine(TPath.Combine(FRootPath, 'Cache'), StagingName);
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

    // R15/R16: record the package's non-launcher root-file names BEFORE the
    // finalize step runs. The companion manifest's introduced-file list is
    // derived from this (staged files without a backup), which stays correct
    // even when a resumed finalize no longer has the staged files to list.
    var StagedFiles := TJSONArray.Create;
    try
      for var StagedFile in TDirectory.GetFiles(NewDir) do
        if not SameText(TPath.GetFileName(StagedFile), LauncherFileName) then
          StagedFiles.Add(TPath.GetFileName(StagedFile));
      if not WriteTextFileDurable(TPath.Combine(RollbackDir, StagedFilesName),
        StagedFiles.Format(2)) then
        raise EPortappixUpdateError.Create('Unable to write staged_files.json.');
    finally
      StagedFiles.Free;
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
    // against and the marker the finalize helper uses to detect an already
    // completed swap (idempotent resume, R11).
    PreSwapSha256 := Sha256File(LauncherExe).ToLower;
    TFile.WriteAllText(TPath.Combine(RollbackDir, PreSwapBackupName),
      '{"sha256":"' + PreSwapSha256 + '"}', TEncoding.UTF8);

    // Clean up any old update_ok marker so a crash during or after this
    // update will correctly trigger the watchdog. A copy is preserved in
    // RollbackDir and restored by the failure path below.
    RemoveFileQuiet(OkFile);

    // A rollback copy from a previous confirmed update is superseded by
    // this update: remove it so the finalize's ReplaceFileW backup has a
    // free target.
    if TFile.Exists(OldLauncherExe) then
      CheckedDeleteFile(OldLauncherExe);

    // Record the saved old launcher's SHA-256 and size while it is still in
    // place — the finalize step later creates the backup copy of exactly
    // this binary, so record and backup always agree.
    RecordOldLauncher(LauncherExe, InstalledVersion);

    // Pending marker with the staging reference, written AFTER the backups
    // and BEFORE the finalize spawn: a crash anywhere after this point
    // leaves a recoverable staged state (recovery respawns the helper).
    var Pending := TJSONObject.Create;
    try
      Pending.AddPair('fromVersion', InstalledVersion);
      Pending.AddPair('toVersion', ARelease.Version);
      Pending.AddPair('channel', ARelease.Channel);
      Pending.AddPair('appliedAt', DateToISO8601(Now));
      Pending.AddPair('stagingDir', StagingName);
      ForceDirectories(TPath.GetDirectoryName(PendingFile));
      if not WriteTextFileDurable(PendingFile, Pending.Format(2)) then
        raise EPortappixUpdateError.Create('Unable to write update_pending.json.');
    finally
      Pending.Free;
    end;

    RemoveFileQuiet(AZipFile);
    RestoreVerified := True;
  except
    // Staging failures restore everything this method touched. Raises when
    // any restore step fails, so the failure is never silent.
    on E: Exception do
    begin
      if not UpdateKillSimulated(E) then
        RestoreFailedSwap(RollbackDir, OkExisted, PendingExisted,
          RecordBackupExisted, PreSwapSha256, MovedRootFiles);
      raise;
    end;
  end;
  MovedRootFiles.Free;

  Log(Format('Update to %s staged; launching the finalize step.', [ARelease.Version]));
  if ALaunchNewExe then
    SpawnUpdateHelper;
end;

procedure TPortappixUpdateManager.SpawnUpdateHelper;
var
  NewExe, Args: string;
begin
  // The finalize helper runs from the staged launcher: it is not the
  // running installation image, so it can atomically replace Launcher.exe.
  NewExe := TPath.Combine(NewDir, LauncherFileName);
  // The helper's own stdout/stderr go nowhere (it is spawned detached), so
  // pass a log file next to the pending marker: a failed finalize is then
  // diagnosable from the installation instead of leaving only stale state.
  Args := Format('--finalize-update --root "%s" --parent %d --log-file "%s"',
    [ExcludeTrailingPathDelimiter(FRootPath), GetCurrentProcessId,
     TPath.Combine(TPath.Combine(ExcludeTrailingPathDelimiter(FRootPath),
       'Cache'), 'update_finalize.log')]);
  SpawnProcess(NewExe, Args);
end;

function TPortappixUpdateManager.ReadPendingStagingDir: string;
var
  JsonValue: TJSONValue;
  Root: TJSONObject;
  Value: TJSONValue;
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
      Value := Root.FindValue('stagingDir');
      if (Value is TJSONString) and (not (Value is TJSONNumber)) then
        Result := TJSONString(Value).Value.Trim;
      if (Result <> '') and (not IsSafeFileComponent(Result)) then
        Result := '';
    finally
      JsonValue.Free;
    end;
  except
    Result := '';
  end;
end;

function TPortappixUpdateManager.SwapDoneFile: string;
begin
  Result := TPath.Combine(TPath.Combine(FRootPath, 'Cache'), SwapDoneName);
end;

function TPortappixUpdateManager.SwapAlreadyCompleted: Boolean;
var
  Marker: TJSONObject;
  Recorded: string;
begin
  Result := False;
  if not TFile.Exists(SwapDoneFile) then
    Exit;
  if not TFile.Exists(LauncherExe) then
    Exit;
  Recorded := '';
  try
    Marker := TJSONObject.ParseJSONValue(
      TFile.ReadAllText(SwapDoneFile, TEncoding.UTF8)) as TJSONObject;
    if Marker = nil then
      Exit;
    try
      if (Marker.FindValue('sha256') <> nil) then
        Recorded := Marker.FindValue('sha256').Value.ToLower.Trim;
    finally
      Marker.Free;
    end;
  except
    Exit;
  end;
  // The marker is evidence, not authority: it counts only while the
  // installed launcher still matches the hash it recorded. A launcher that
  // changed (manual restore, another update) invalidates it, and the normal
  // pre-swap inference below then governs.
  if (Recorded = '') or (not TFile.Exists(LauncherExe)) then
    Exit;
  Result := SameText(Sha256File(LauncherExe).ToLower, Recorded);
end;

procedure TPortappixUpdateManager.WriteSwapDoneMarker(
  const ANewSha256, AOldSha256: string);
var
  Marker: TJSONObject;
begin
  Marker := TJSONObject.Create;
  try
    Marker.AddPair('schema', TJSONNumber.Create(1));
    Marker.AddPair('sha256', ANewSha256.ToLower);
    Marker.AddPair('previousSha256', AOldSha256.ToLower);
    Marker.AddPair('completedAt', DateToISO8601(Now));
    ForceDirectories(TPath.GetDirectoryName(SwapDoneFile));
    if not WriteTextFileDurable(SwapDoneFile, Marker.Format(2)) then
      raise EPortappixUpdateError.Create(
        'Unable to write the update swap marker.');
  finally
    Marker.Free;
  end;
end;

procedure TPortappixUpdateManager.RemoveSwapDoneMarker;
begin
  RemoveFileQuiet(SwapDoneFile);
end;

function TPortappixUpdateManager.UnfinalizedPendingUpdate: Boolean;
var
  StagingDir: string;
begin
  Result := False;
  if not TFile.Exists(PendingFile) then
    Exit;
  // R20: a swap that already completed is not "unfinalized": the staged
  // binary is gone by design (ReplaceFileW consumed it) and the remaining
  // work is the marker/finalize bookkeeping, not a respawn of the helper.
  if SwapAlreadyCompleted then
    Exit;
  // The finalize step deletes launcher_new when it completes; its presence
  // with a live pending marker means the staged update was never finalized.
  if not TFile.Exists(TPath.Combine(NewDir, LauncherFileName)) then
    Exit;
  StagingDir := ReadPendingStagingDir;
  if StagingDir = '' then
    Exit; // pre-Phase-2 pending marker: legacy watchdog semantics apply
  Result := TDirectory.Exists(TPath.Combine(TPath.Combine(FRootPath, 'Cache'),
    StagingDir));
end;

procedure TPortappixUpdateManager.PreserveCompanionBackups(
  const AStagingDir: string);
var
  Name, BackupFile, Target, TransferDir, Hash, StagedFilesJson: string;
  Introduced: TArray<string>;
  Remaining: TArray<string>;
  Failures, RecoverFailures: Integer;
  Manifest: TJSONObject;
  Entry: TJSONObject;

  function TransferFailureMessage(const ASource, ADest: string): string;
  begin
    Result := Format('Unable to preserve companion backup "%s" as "%s": %s',
      [ASource, ADest, SysErrorMessage(Integer(GetLastError))]);
  end;

  /// Swap-time bookkeeping is not a backed-up root file: it stays in the
  /// staging dir until the staging dir is consumed, because a failed or
  /// interrupted finalize needs it intact (SwapDone inference, marker
  /// restore, introduced-list computation on resume).
  function IsBookkeepingName(const AName: string): Boolean;
  begin
    Result := SameText(AName, RecordBackupName) or
      SameText(AName, OkBackupName) or SameText(AName, PendingBackupName) or
      SameText(AName, PreSwapBackupName) or SameText(AName, StagedFilesName);
  end;

  /// Adds one "replaced" manifest entry for a backup file that exists at
  /// AFile, hashing the copy that will actually ship in the companion dir.
  procedure AddReplacedEntry(const AManifest: TJSONObject; const AFile: string);
  begin
    Entry := TJSONObject.Create;
    Entry.AddPair('name', TPath.GetFileName(AFile));
    Entry.AddPair('sha256', Sha256File(AFile).ToLower);
    (AManifest.FindValue('replaced') as TJSONArray).AddElement(Entry);
  end;

begin
  // R15/R16: which files did this update INTRODUCE? Staged package root
  // files that have no backup in the staging dir had no previous version —
  // rollback must delete them, and the manifest must say so. Computed BEFORE
  // any transfer so a resumed finalize (which no longer has the staged
  // files) still derives the same list from the durable staged_files.json.
  Introduced := nil;
  StagedFilesJson := TPath.Combine(AStagingDir, StagedFilesName);
  if TFile.Exists(StagedFilesJson) then
  begin
    var StagedVal := TJSONObject.ParseJSONValue(
      TFile.ReadAllText(StagedFilesJson, TEncoding.UTF8));
    if StagedVal is TJSONArray then
      try
        SetLength(Introduced, 0);
        for var I := 0 to TJSONArray(StagedVal).Count - 1 do
        begin
          Name := TJSONArray(StagedVal).Items[I].Value;
          if (Name = '') or (not IsSafeFileComponent(Name)) then
            Continue;
          if not TFile.Exists(TPath.Combine(AStagingDir, Name)) then
          begin
            SetLength(Introduced, Length(Introduced) + 1);
            Introduced[High(Introduced)] := Name;
          end;
        end;
      finally
        StagedVal.Free;
      end
    else if StagedVal <> nil then
      StagedVal.Free;
  end;

  // The transfer list: backed-up root files only (bookkeeping excluded and
  // retained in the staging dir).
  Remaining := TDirectory.GetFiles(AStagingDir, '*', TSearchOption.soTopDirectoryOnly);
  for var I := High(Remaining) downto 0 do
    if IsBookkeepingName(TPath.GetFileName(Remaining[I])) then
      Delete(Remaining, I, 1);
  var TransferCount := Length(Remaining);

  if (TransferCount = 0) and (Length(Introduced) = 0) then
  begin
    // Nothing to preserve at all: consume the staging dir (including its
    // bookkeeping — the swap has completed at this point).
    CompanionDeleteDirectory(AStagingDir, True);
    Exit;
  end;

  if TransferCount = 0 then
  begin
    // R16 (resume path): a retried finalize whose replaced-file backups were
    // already consumed by the failure restore still records the introduced
    // files. The previous companion directory and every backup in it are
    // NEVER touched here — only the manifest is updated in place, listing
    // the backups that still exist (verified by hash) plus the introduced
    // list of the current update.
    ForceDirectories(CompanionBackupDir);
    Manifest := TJSONObject.Create;
    try
      Manifest.AddPair('schema', TJSONNumber.Create(CompanionManifestSchema));
      Manifest.AddPair('replaced', TJSONArray.Create);
      for BackupFile in TDirectory.GetFiles(CompanionBackupDir, '*',
        TSearchOption.soTopDirectoryOnly) do
        if not SameText(TPath.GetFileName(BackupFile), CompanionManifestName) then
          AddReplacedEntry(Manifest, BackupFile);
      var IntroducedArr := TJSONArray.Create;
      for Name in Introduced do
        IntroducedArr.AddElement(TJSONString.Create(Name));
      Manifest.AddPair('introduced', IntroducedArr);
      if not WriteTextFileDurable(CompanionManifestFile, Manifest.Format(2)) then
        raise EPortappixUpdateError.Create(
          'Unable to write the companion manifest.');
    finally
      Manifest.Free;
    end;
    CompanionDeleteDirectory(AStagingDir, True);
    Exit;
  end;

  // R16: the replacement is transferred into a FRESH directory and verified
  // in full BEFORE the previous companion directory is touched. Any failure
  // leaves the staging dir (the authoritative source) and any previous
  // companion dir (the authoritative old backups) untouched and raises —
  // the finalize failure path then restores everything from the staging dir.
  TransferDir := CompanionTransferDir;
  CompanionDeleteDirectory(TransferDir, True); // stale leftovers only
  ForceDirectories(TransferDir);
  Failures := 0;
  try
    for var I := 0 to TransferCount - 1 do
    begin
      BackupFile := Remaining[I];
      Hash := Sha256File(BackupFile).ToLower;
      Target := TPath.Combine(TransferDir, TPath.GetFileName(BackupFile));
      if not CompanionMoveFile(BackupFile, Target) then
      begin
        Log(TransferFailureMessage(BackupFile, Target));
        Inc(Failures);
        Continue;
      end;
      // Verified transfer: the moved bytes must be exactly the source bytes.
      if (not TFile.Exists(Target)) or
         (not SameText(Sha256File(Target).ToLower, Hash)) then
      begin
        Log(Format('Companion backup "%s" did not transfer intact.', [Target]));
        Inc(Failures);
        Continue;
      end;
    end;

    if Failures > 0 then
      raise EPortappixUpdateError.Create(Format(
        'Unable to preserve the companion backups (%d of %d failed); the ' +
        'staging directory was kept and nothing was deleted.',
        [Failures, TransferCount]));

    // Union merge (R16): backups in the previous companion dir that the new
    // set does not carry (root files replaced by an EARLIER update that this
    // package does not ship, or backups already consumed by a failure
    // restore) are copied in so the activated directory is never a subset of
    // the old one. New backups shadow old ones with the same name — the
    // newer backup is the correct pre-this-update state.
    if TDirectory.Exists(CompanionBackupDir) then
      for BackupFile in TDirectory.GetFiles(CompanionBackupDir, '*',
        TSearchOption.soTopDirectoryOnly) do
      begin
        Name := TPath.GetFileName(BackupFile);
        if SameText(Name, CompanionManifestName) then
          Continue;
        Target := TPath.Combine(TransferDir, Name);
        if TFile.Exists(Target) then
          Continue;
        TFile.Copy(BackupFile, Target, False);
      end;

    // The authoritative manifest: replaced files (with verified hashes) and
    // introduced files. Written durably BEFORE the activation. The manifest
    // object takes ownership of every sub-array added to it.
    Manifest := TJSONObject.Create;
    try
      Manifest.AddPair('schema', TJSONNumber.Create(CompanionManifestSchema));
      Manifest.AddPair('replaced', TJSONArray.Create);
      for BackupFile in TDirectory.GetFiles(TransferDir, '*',
        TSearchOption.soTopDirectoryOnly) do
        if not SameText(TPath.GetFileName(BackupFile), CompanionManifestName) then
          AddReplacedEntry(Manifest, BackupFile);
      var IntroducedArr := TJSONArray.Create;
      for Name in Introduced do
        IntroducedArr.AddElement(TJSONString.Create(Name));
      Manifest.AddPair('introduced', IntroducedArr);
      if not WriteTextFileDurable(TPath.Combine(TransferDir,
        CompanionManifestName), Manifest.Format(2)) then
        raise EPortappixUpdateError.Create(
          'Unable to write the companion manifest.');
    finally
      Manifest.Free;
    end;

    // Activation: the previous companion directory is only replaced once the
    // replacement is completely transferred and verified (R16). The window
    // between the delete and the rename is recoverable: every file lives in
    // the transfer dir, and the handler below moves them all back to the
    // staging dir if the rename fails — no backup copy is ever destroyed.
    if TDirectory.Exists(CompanionBackupDir) then
      if not CompanionDeleteDirectory(CompanionBackupDir, True) then
        raise EPortappixUpdateError.CreateFmt(
          'Unable to replace the previous companion backup directory "%s": %s',
          [CompanionBackupDir, SysErrorMessage(Integer(GetLastError))]);
    try
      TDirectory.Move(TransferDir, CompanionBackupDir);
    except
      on E: Exception do
        raise EPortappixUpdateError.CreateFmt(
          'Unable to activate the companion backup directory "%s": %s',
          [CompanionBackupDir, E.Message]);
    end;
  except
    // Never destroy the only copy of a backup: everything the fresh
    // transfer dir holds is moved back to the staging dir (the authoritative
    // source). If even that fails for a file, the transfer dir is KEPT —
    // only a fully drained transfer dir is deleted. The caller restores
    // everything from the staging dir and a retry starts over.
    RecoverFailures := 0;
    if TDirectory.Exists(TransferDir) then
      for BackupFile in TDirectory.GetFiles(TransferDir, '*',
        TSearchOption.soTopDirectoryOnly) do
        if not CompanionMoveFile(BackupFile,
          TPath.Combine(AStagingDir, TPath.GetFileName(BackupFile))) then
          Inc(RecoverFailures);
    if (RecoverFailures = 0) and TDirectory.Exists(TransferDir) then
      CompanionDeleteDirectory(TransferDir, True)
    else if RecoverFailures > 0 then
      Log(Format('Unable to move %d transferred backup(s) back to "%s"; the ' +
        'transfer directory "%s" was kept so no backup is lost.',
        [RecoverFailures, AStagingDir, TransferDir]));
    raise;
  end;

  // The staging directory is NOT deleted here: the caller owns that decision,
  // because a later finalize step can still fail and the RestoreFailedSwap
  // path needs the staging directory (bookkeeping files,
  // rollback_pre_swap.json, any backups not transferred) to restore the
  // installation. Deleting it eagerly made every post-companion failure
  // unrecoverable (the restore raised "The specified path was not found").
  // Stale bookkeeping is harmless: it is excluded from later transfers.
end;

procedure TPortappixUpdateManager.FinalizePendingUpdate;
var
  StagingDir, StagingName, NewExe, PreSwapSha256, CurrentHash: string;
  NewSha256: string;
  Target: string;
  MovedRootFiles: TList<string>;
  SwapDone, SwapSucceeded: Boolean;
  Retries: Integer;
  Replaced: Boolean;
  LastError: Integer;
  InstallSource, SelfExe: string;

  /// R20: removes the staging artifacts that only the finalize consumes.
  procedure FinishConsumedStaging;
  begin
    if TDirectory.Exists(NewDir) then
      try
        TDirectory.Delete(NewDir, True);
      except
        on E: Exception do
          Log(Format('Unable to remove the temporary update folder "%s": %s',
            [NewDir, E.Message]));
      end;
  end;

begin
  if not TFile.Exists(PendingFile) then
    raise EPortappixUpdateError.Create(
      'No pending update to finalize (update_pending.json is missing).');
  StagingName := ReadPendingStagingDir;
  if StagingName = '' then
    raise EPortappixUpdateError.Create(
      'The pending update marker has no staging reference.');
  StagingDir := TPath.Combine(TPath.Combine(FRootPath, 'Cache'), StagingName);

  // R20: an interrupted finalize must be recoverable no matter WHERE it
  // stopped. Two independent pieces of evidence are used:
  //  - the durable swap-done marker, written immediately after ReplaceFileW
  //    (the staged source binary is consumed by that call, so its absence
  //    must never be read as "nothing was done");
  //  - the pre-swap hash recorded in the staging dir (fallback for an
  //    installation whose swap completed before the marker existed).
  // A swap that already completed with the staging dir already consumed is
  // a SUCCESSFUL finalize: report completion instead of failing.
  SwapDone := SwapAlreadyCompleted;
  PreSwapSha256 := '';
  if TDirectory.Exists(StagingDir) and
     TFile.Exists(TPath.Combine(StagingDir, PreSwapBackupName)) then
  begin
    var PreSwapJson := TJSONObject.ParseJSONValue(
      TFile.ReadAllText(TPath.Combine(StagingDir, PreSwapBackupName),
        TEncoding.UTF8)) as TJSONObject;
    if PreSwapJson <> nil then
      try
        if (PreSwapJson.FindValue('sha256') <> nil) then
          PreSwapSha256 := PreSwapJson.FindValue('sha256').Value;
      finally
        PreSwapJson.Free;
      end;
  end;
  if (not SwapDone) and (PreSwapSha256 <> '') and TFile.Exists(LauncherExe) then
  begin
    CurrentHash := Sha256File(LauncherExe).ToLower;
    SwapDone := not SameText(CurrentHash, PreSwapSha256);
  end;

  if not TDirectory.Exists(StagingDir) then
  begin
    if SwapDone then
    begin
      // The finalize ran through the companion step (which consumes the
      // staging dir) and died before its own cleanup: finish it. The marker
      // stays until ConfirmUpdate: while the pending marker is live, it is
      // the evidence that a repeated finalize has nothing left to do.
      FinishConsumedStaging;
      Log('Update finalization already complete; nothing left to do.');
      Exit;
    end;
    raise EPortappixUpdateError.CreateFmt(
      'The staging directory "%s" is missing.', [StagingDir]);
  end;

  NewExe := TPath.Combine(NewDir, LauncherFileName);
  if not SwapDone and not TFile.Exists(NewExe) then
    raise EPortappixUpdateError.Create(
      'The staged launcher binary is missing (launcher_new\Launcher.exe).');

  SwapSucceeded := False;
  MovedRootFiles := TList<string>.Create;
  try
    if not SwapDone then
    begin
      {$IFDEF PORTAPPIX_TESTINJECT}
      CheckUpdateCrashPoint(UpdateFinalizeCrashBeforeSwap);
      {$ENDIF}
      // Atomic replacement (R11): ReplaceFileW swaps the staged launcher
      // into place and preserves the current binary as Launcher.exe.old in
      // ONE operation — there is no window in which Launcher.exe is
      // missing.
      //
      // The replacement SOURCE must not be the file this process is running
      // from. The finalize helper is started as launcher_new\Launcher.exe, so
      // handing that same path to ReplaceFileW fails with
      // ERROR_SHARING_VIOLATION (32) for as long as the helper is alive —
      // i.e. always. The helper therefore installs from a private copy in a
      // neutral temp location, which it can freely consume. If the copy
      // cannot be made, fall back to the staged path (correct, but only
      // succeeds when this process is not the staged image).
      Replaced := False;
      LastError := 0;
      InstallSource := NewExe;
      SelfExe := TPath.GetFullPath(ParamStr(0));
      if SameText(TPath.GetFullPath(NewExe), SelfExe) then
      begin
        InstallSource := TPath.Combine(TPath.GetDirectoryName(NewExe),
          Format('install_%d.exe', [GetCurrentProcessId]));
        if (not CopyFile(PChar(NewExe), PChar(InstallSource), False)) then
          InstallSource := NewExe;
      end;
      Replaced := False;
      for Retries := 1 to 20 do
      begin
        if ReplaceFile(PChar(LauncherExe), PChar(InstallSource),          PChar(OldLauncherExe), REPLACEFILE_REPLACE_EXISTING, nil, nil) then
        begin
          Replaced := True;
          Break;
        end;
        // Capture the error ONCE: Log() and SysErrorMessage() call Windows
        // APIs that overwrite the thread's last-error value, so comparing
        // GetLastError after logging would compare the wrong error (and the
        // retry loop would give up after a single transient sharing
        // violation).
        LastError := Integer(GetLastError);
        Log(Format('ReplaceFileW attempt %d failed (error %d): %s',
          [Retries, LastError, SysErrorMessage(LastError)]));
        if (LastError <> ERROR_SHARING_VIOLATION) and
           (LastError <> ERROR_ACCESS_DENIED) then
          Break;
        Sleep(250);
      end;
      if (not SameText(InstallSource, NewExe)) and TFile.Exists(InstallSource) then
        RemoveFileQuiet(InstallSource);
      if not Replaced then
        raise EPortappixUpdateError.CreateFmt(
          'Unable to atomically install the staged launcher (ReplaceFileW): %s',
          [SysErrorMessage(LastError)]);
      Log('The staged launcher was installed atomically; the previous ' +
        'launcher is preserved as Launcher.exe.old.');
      // R20: record the completed swap durably and immediately. ReplaceFileW
      // consumed the staged source binary, so every later resume depends on
      // this marker to know that the installation is already correct.
      NewSha256 := Sha256File(LauncherExe).ToLower;
      WriteSwapDoneMarker(NewSha256, PreSwapSha256);
      {$IFDEF PORTAPPIX_TESTINJECT}
      CheckUpdateCrashPoint(UpdateFinalizeCrashAfterSwap);
      {$ENDIF}
    end;

    // Companion root files (unchanged move semantics from the staged dir).
    for var FileName in TDirectory.GetFiles(NewDir) do
    begin
      var BaseName := TPath.GetFileName(FileName);
      if SameText(BaseName, LauncherFileName) then
        Continue;
      Target := TPath.Combine(FRootPath, BaseName);
      RemoveFileQuiet(Target);
      TFile.Move(FileName, Target);
      MovedRootFiles.Add(Target);
    end;

    {$IFDEF PORTAPPIX_TESTINJECT}
    CheckUpdateCrashPoint(UpdateFinalizeCrashAfterRootFiles);
    {$ENDIF}

    // R14: the replaced companions survive until confirmation.
    PreserveCompanionBackups(StagingDir);

    {$IFDEF PORTAPPIX_TESTINJECT}
    CheckUpdateCrashPoint(UpdateFinalizeCrashAfterCompanions);
    {$ENDIF}

    try
      TDirectory.Delete(NewDir, True);
    except
      on E: Exception do
        Log(Format('Unable to remove the temporary update folder "%s": %s',
          [NewDir, E.Message]));
    end;

    {$IFDEF PORTAPPIX_TESTINJECT}
    CheckUpdateCrashPoint(UpdateFinalizeCrashAfterNewDir);
    {$ENDIF}

    SwapSucceeded := True;
    // R15/R20: only NOW, with every mutation committed, is the staging
    // directory no longer needed. Deleting it earlier would make a failure in
    // any later step's restore impossible (the restore reads it).
    if not CompanionDeleteDirectory(StagingDir, True) then
      Log(Format('Unable to remove the staging directory "%s": %s',
        [StagingDir, SysErrorMessage(Integer(GetLastError))]));
    // R20: the transition marker intentionally SURVIVES a successful
    // finalize. While the pending marker is live (the new launcher has not
    // confirmed yet), a repeated finalize must be able to see that the swap
    // is already done; ConfirmUpdate and RollbackToOldLauncher clear it.
    Log('Update finalization complete; restarting the launcher.');
    // Best-effort: the atomic install is done; if the new launcher cannot
    // be started automatically, the watchdog still offers rollback on its
    // next start (update_ok is missing until it confirms).
    try
      SpawnNewLauncher('--post-update');
    except
      on E: Exception do
        Log(Format('The finalized launcher could not be started automatically: %s',
          [E.Message]));
    end;
  except
    // Checked all-or-nothing restore of the finalize mutations. Raises when
    // any restore step fails, so the failure is never silent. The staging
    // directory tells which backups exist (it was already converted into
    // the companion dir only after the root files moved).
    on E: Exception do
    begin
      if not UpdateKillSimulated(E) then
      begin
        RestoreFailedSwap(StagingDir,
          TFile.Exists(TPath.Combine(StagingDir, OkBackupName)),
          TFile.Exists(TPath.Combine(StagingDir, PendingBackupName)),
          TFile.Exists(TPath.Combine(StagingDir, RecordBackupName)),
          PreSwapSha256, MovedRootFiles);
        // After a verified restore the staging directory is recoverable
        // state nobody needs: clean it (best-effort).
        try
          if SameText(Sha256File(LauncherExe).ToLower, PreSwapSha256) then
            TDirectory.Delete(StagingDir, True);
        except
        end;
      end;
      raise;
    end;
  end;
  MovedRootFiles.Free;
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
    if SameText(BaseName, StagedFilesName) then
      Continue; // R15/R16 bookkeeping: the staged package file list
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

  // 4b. R20: the swap no longer exists once the pre-swap launcher is back;
  // the durable marker would otherwise keep claiming a completed swap.
  RemoveSwapDoneMarker;

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
  // R20: the update is confirmed; the swap marker served its purpose.
  RemoveSwapDoneMarker;

  // R14: the update is confirmed healthy — the old companion files are
  // discarded and the new ones stay in place.
  if TDirectory.Exists(CompanionBackupDir) then
    try
      TDirectory.Delete(CompanionBackupDir, True);
    except
      on E: Exception do
        Log(Format('Unable to remove the companion backup directory: %s',
          [E.Message]));
    end;

  Log(Format('Update to %s confirmed. Launcher.exe.old is kept as the rollback copy ' +
    'until the next update; delete it manually to remove the rollback offer.',
    [PendingVersion]));
end;

function TPortappixUpdateManager.RollbackToOldLauncher(
  const ARestartLauncher: Boolean): Boolean;
var
  StaleExe, ErrorMsg, Target: string;
  Introduced: TArray<string>;
  Failures: Integer;
  BaseName: string;
  OldHandle: THandle;
begin
  // TOCTOU-safe restore: the same handle that verified size and hash stays
  // open (write-denying) until the rename has completed, so the file that
  // was verified is exactly the file that gets moved.
  if not OpenVerifiedOldLauncher(OldHandle, ErrorMsg) then
    raise EPortappixUpdateError.Create(ErrorMsg);
  try
    {$IFDEF PORTAPPIX_TESTINJECT}
    if Assigned(PortappixRollbackAttackHook) then
      PortappixRollbackAttackHook();
    {$ENDIF}
    Log('Restoring the previous launcher version...');
    StaleExe := Format('%s.failed_%s', [LauncherExe,
      FormatDateTime('yyyymmdd_hhnnss', Now)]);

    if not UpdateRenameFile(LauncherExe, StaleExe) then
      raise EPortappixUpdateError.CreateFmt(
        'Unable to move the failing launcher to "%s": %s',
        [StaleExe, SysErrorMessage(Integer(GetLastError))]);

    try
      // R10: the verified file is renamed THROUGH the still-open handle
      // (FileRenameInfo), so what was verified is exactly what is moved —
      // a pathname swap after verification is impossible while the
      // delete-unshared handle is held.
      if not RenameByHandle(OldHandle, LauncherExe) then
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
  // R20: the swap is undone; no marker may claim otherwise.
  RemoveSwapDoneMarker;

  // R14/R15/R16: restore the companion files the update replaced, delete the
  // files it introduced (manifest-authoritative), and only remove the backup
  // directory when EVERY restore and removal succeeded. This runs for
  // watchdog rollbacks (before the update was confirmed); after a confirmed
  // update the directory was already deleted by ConfirmUpdate.
  if TDirectory.Exists(CompanionBackupDir) then
  begin
    Introduced := ReadCompanionManifestIntroduced(CompanionManifestFile);
    Failures := 0;
    for var BackupFile in TDirectory.GetFiles(CompanionBackupDir, '*',
      TSearchOption.soTopDirectoryOnly) do
    begin
      BaseName := TPath.GetFileName(BackupFile);
      if SameText(BaseName, CompanionManifestName) then
        Continue; // bookkeeping, consumed with the directory
      Target := TPath.Combine(FRootPath, BaseName);
      if not CompanionDeleteFile(Target) then
      begin
        // R15: a delete failure must not consume the backup — report it and
        // keep the directory so a later rollback can retry the restore.
        Log(Format('Unable to delete "%s" before restoring the companion file: %s',
          [Target, SysErrorMessage(Integer(GetLastError))]));
        Inc(Failures);
        Continue;
      end;
      if not CompanionMoveFile(BackupFile, Target) then
      begin
        Log(Format('Unable to restore companion file "%s": %s',
          [BackupFile, SysErrorMessage(Integer(GetLastError))]));
        Inc(Failures);
      end;
    end;

    // Files the update introduced have no backup: the manifest is the only
    // record that they are update artifacts, and rollback must remove them.
    for var IntroducedName in Introduced do
    begin
      Target := TPath.Combine(FRootPath, IntroducedName);
      if not TFile.Exists(Target) then
        Continue; // already removed (idempotent re-rollback)
      if not CompanionDeleteFile(Target) then
      begin
        Log(Format('Unable to delete the update file "%s" introduced by the ' +
          'update: %s', [Target, SysErrorMessage(Integer(GetLastError))]));
        Inc(Failures);
      end;
    end;

    // R15: the backup directory is NEVER destroyed while any restore or
    // removal failed — the surviving backups are the only copies of the
    // pre-update state.
    if Failures = 0 then
    begin
      if not CompanionDeleteDirectory(CompanionBackupDir, True) then
        Log(Format('Unable to remove the companion backup directory: %s',
          [SysErrorMessage(Integer(GetLastError))]))
      else
        Log('Companion files restored to their pre-update state.');
    end
    else
      Log(Format('%d companion file(s) could not be restored; the backup ' +
        'directory was kept so the rollback can be retried.', [Failures]));
  end;

  Log('Previous launcher restored. The failed build stays next to it as ' +
    LauncherFileName + '.failed_* and can be deleted.');

  if ARestartLauncher then
    SpawnNewLauncher('');
  Result := True;
end;

procedure TPortappixUpdateManager.SpawnNewLauncher(const AArguments: string);
begin
  SpawnProcess(LauncherExe, AArguments);
end;

procedure TPortappixUpdateManager.SpawnProcess(const AExePath, AArguments: string);
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

  CommandLine := QuoteArgument(AExePath);
  if AArguments <> '' then
    CommandLine := CommandLine + ' ' + AArguments;
  UniqueString(CommandLine);

  if not CreateProcess(nil, PChar(CommandLine), nil, nil, False,
    CREATE_NEW_PROCESS_GROUP or CREATE_UNICODE_ENVIRONMENT, nil,
    PChar(FRootPath), StartupInfo, ProcessInfo) then
    raise EPortappixUpdateError.CreateFmt('Unable to start "%s": %s',
      [AExePath, SysErrorMessage(Integer(GetLastError))]);
  CloseHandle(ProcessInfo.hThread);
  CloseHandle(ProcessInfo.hProcess);
end;

end.
