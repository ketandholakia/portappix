unit Portappix.RecordAuth;

{
  Authentication for rollback metadata (Cache\old_launcher.json).

  Threat model (see docs/security/UPDATE_ROLLBACK_INTEGRITY.md):
  - Defends the rollback record against accidental corruption, tampering by
    processes running as a different (or lower-privileged) user, and tampering
    by same-user processes that cannot read the key file.
  - Does NOT defend against arbitrary code running with the same user
    privileges that can read the DPAPI-protected key: such code can decrypt
    the key and forge a matching HMAC. No locally-stored secret can do better;
    this residual risk is documented, not hidden.

  Mechanism: a 32-byte random key PER INSTALLATION, DPAPI-protected
  (CryptProtectData, user scope) and stored under
  %LOCALAPPDATA%\Portappix\keys\<identity-hash>\rollback_key.bin, where the
  identity hash is derived from the canonical installation root path (R19).
  Two installations under the same user account therefore never share key
  material: a record forged in one does not verify in the other.
  The HMAC-SHA256 covers a canonical, length-prefixed serialization of the
  record's security-relevant fields (sha256, size, version, recordedAt) in a
  fixed documented order, so any modification of those fields is detected.
}

interface

uses
  Winapi.Windows,
  System.SysUtils;

type
  EPortappixRecordAuthError = class(Exception);

/// Returns the rollback key for the installation rooted at AInstallationRoot
/// (32 bytes), creating and DPAPI-protecting it on first use. The key is
/// scoped to that installation: two installations under the same account
/// have independent keys (R19). Raises EPortappixRecordAuthError when the
/// key cannot be created or decrypted (callers must fail closed).
/// First-time creation is serialized across processes (R13).
function GetInstallationRollbackKey(
  const AInstallationRoot: string): TBytes;

/// Reads the installation's stored key WITHOUT creating it (R9):
/// verification paths use this and fail closed when the blob does not exist.
function TryGetInstallationRollbackKey(const AInstallationRoot: string;
  out AKey: TBytes): Boolean;

/// True when this installation's DPAPI-protected key blob exists on disk.
/// Blob existence is the authenticated "schema-2 operation established"
/// marker (R9).
function InstallationKeyBlobExists(const AInstallationRoot: string): Boolean;

/// The on-disk key path for an installation root (exposed for diagnostics
/// and for the migration/scope tests).
function InstallationKeyFilePath(const AInstallationRoot: string): string;

/// Returns the per-installation rollback key using the process-wide default
/// installation root. Prefer the explicit-root overloads; this exists for
/// compatibility and is resolved from the loaded module path.
function GetRollbackKey: TBytes;

/// Reads the default installation's key WITHOUT creating it (R9).
function TryGetRollbackKey(out AKey: TBytes): Boolean;

/// True when the default installation's key blob exists on disk (R9).
function KeyBlobExists: Boolean;

/// Computes the record HMAC (lowercase hex) over the canonical field
/// serialization. ASha256 must already be lowercase hex; AVersion and
/// ARecordedAt are taken verbatim from the record.
function ComputeRecordHmac(const AKey: TBytes; const ASha256: string;
  ASize: Int64; const AVersion, ARecordedAt: string): string;

/// Compares two hex HMAC strings; True only on a full case-insensitive match.
function RecordHmacMatches(const AExpected, AActual: string): Boolean;

{$IFDEF PORTAPPIX_TESTCRASH}
var
  /// Test override for the key file location (unit tests must not touch the
  /// real %LOCALAPPDATA%). Empty string = default location. The variable
  /// exists only in test builds (PORTAPPIX_TESTCRASH is never defined for
  /// production artifacts, which is enforced by byte scan).
  PortappixRecordKeyPathOverride: string = '';
  /// Test override for the per-installation key BASE directory (R19). When
  /// set, key paths are resolved under this directory using the same
  /// canonical-installation-identity scoping as production, so tests can
  /// exercise two installations under one account without touching the real
  /// %LOCALAPPDATA%. Empty string = default location. Takes precedence over
  /// PortappixRecordKeyPathOverride being empty only (the full-path override
  /// wins when both are set).
  PortappixKeyRootOverride: string = '';
{$ENDIF}
{$IFDEF PORTAPPIX_TESTINJECT}
var
  /// Milliseconds slept inside GetRollbackKey after the existence check and
  /// before the key is generated/written — deterministically widens the
  /// first-creation race window in repro tests. Test builds only.
  PortappixKeyCreateDelayMs: Integer = 0;
{$ENDIF}

implementation

uses
  System.Classes,
  System.Hash,
  System.IOUtils,
  Portappix.Common;

const
  KeyFileDirectory = 'Portappix';
  /// R19: per-installation key subdirectory under %LOCALAPPDATA%\Portappix.
  KeySubDirectory = 'keys';
  KeyFileName = 'rollback_key.bin';
  /// R19: previous (unscoped) key location, migrated on first authenticated
  /// use and then removed. Bounded migration: only read, never invented.
  LegacyKeyFileName = 'rollback_key.bin';
  KeySizeBytes = 32;
  KeyBlobMagic: array[0..7] of Byte = (Ord('P'), Ord('X'), Ord('P'), Ord('X'),
    Ord('R'), Ord('K'), Ord('E'), Ord('Y'));
  KeyBlobFormatVersion = 2;

type
  TDataBlob = record
    cbData: DWORD;
    pbData: PByte;
  end;
  PDataBlob = ^TDataBlob;

function CryptProtectData(pDataIn: PDataBlob; szDataDescr: PWideChar;
  pOptionalEntropy: PDataBlob; pvReserved: Pointer; pPromptStruct: Pointer;
  dwFlags: DWORD; var pDataOut: TDataBlob): BOOL; stdcall;
  external 'crypt32.dll' name 'CryptProtectData';
function CryptUnprotectData(pDataIn: PDataBlob; var ppszDataDescr: PWideChar;
  pOptionalEntropy: PDataBlob; pvReserved: Pointer; pPromptStruct: Pointer;
  dwFlags: DWORD; var pDataOut: TDataBlob): BOOL; stdcall;
  external 'crypt32.dll' name 'CryptUnprotectData';
function BCryptGenRandom(hAlgorithm: Pointer; pbBuffer: PByte;
  cbBuffer: ULONG; dwFlags: ULONG): LONG; stdcall;
  external 'bcrypt.dll' name 'BCryptGenRandom';

const
  CRYPTPROTECT_UI_FORBIDDEN = $1;
  BCRYPT_USE_SYSTEM_PREFERRED_RNG = $2;
  STATUS_SUCCESS = 0;

var
  GDurableTempCounter: Integer = 0;

/// R19: canonical installation identity. The key scope must not depend on
/// spelling variants of the same installation (case, separators, trailing
/// delimiter, accessors): the resolved full path is normalized to lowercase
/// with backslashes only, then hashed. Two DIFFERENT installations produce
/// different identities; the SAME installation reached via different
/// spellings produces one identity (and therefore one key).
function CanonicalInstallationIdentity(const AInstallationRoot: string): string;
var
  Root: string;
begin
  Root := AInstallationRoot.Trim;
  if Root = '' then
    Root := LauncherDirectory
  else if IsRelativePath(Root) then
    Root := TPath.Combine(LauncherDirectory, Root);
  // GetFullPath normalizes separators, dot segments and case of the volume
  // and collapses a trailing delimiter. The \\?\ prefix is stripped and
  // re-added by the caller never (key paths stay ordinary paths).
  Root := TPath.GetFullPath(Root);
  if TextStartsWith(Root, '\\?\') then
    Delete(Root, 1, 4);
  Root := TrimTrailingPathDelimiter(Root).Replace('/', '\').ToLower;
  Result := Sha256Text(Root).ToLower;
end;

function InstallationKeyFilePath(const AInstallationRoot: string): string;
var
  BaseDir: string;
begin
  {$IFDEF PORTAPPIX_TESTCRASH}
  if PortappixRecordKeyPathOverride <> '' then
    Exit(PortappixRecordKeyPathOverride);
  {$ENDIF}
  {$IFDEF PORTAPPIX_TESTCRASH}
  if PortappixKeyRootOverride <> '' then
    BaseDir := PortappixKeyRootOverride
  else
  {$ENDIF}
    BaseDir := TPath.GetHomePath;
  Result := TPath.Combine(
    TPath.Combine(
      TPath.Combine(BaseDir, KeyFileDirectory), KeySubDirectory),
    CanonicalInstallationIdentity(AInstallationRoot));
  Result := TPath.Combine(Result, KeyFileName);
end;

/// The process-wide default installation root: the directory of the module
/// that loaded this unit (the launcher executable), so every caller that does
/// not pass an explicit root still gets a per-installation key.
function DefaultInstallationRoot: string;
begin
  Result := LauncherDirectory;
end;

function RandomBytes(ACount: Integer): TBytes;
begin
  SetLength(Result, ACount);
  if BCryptGenRandom(nil, @Result[0], DWORD(ACount),
    BCRYPT_USE_SYSTEM_PREFERRED_RNG) <> STATUS_SUCCESS then
    raise EPortappixRecordAuthError.Create(
      'Unable to generate the rollback record key (BCryptGenRandom failed).');
end;

procedure LocalFreeBlob(var ABlob: TDataBlob);
begin
  if ABlob.pbData <> nil then
  begin
    LocalFree(HLOCAL(ABlob.pbData));
    ABlob.pbData := nil;
    ABlob.cbData := 0;
  end;
end;

/// The pre-R19 key location: a single key shared by every installation under
/// the account. Read only for bounded migration; never created here.
function LegacyKeyFilePath: string;
var
  BaseDir: string;
begin
  {$IFDEF PORTAPPIX_TESTCRASH}
  if PortappixRecordKeyPathOverride <> '' then
    Exit(PortappixRecordKeyPathOverride);
  {$ENDIF}
  {$IFDEF PORTAPPIX_TESTCRASH}
  if PortappixKeyRootOverride <> '' then
    BaseDir := PortappixKeyRootOverride
  else
  {$ENDIF}
    BaseDir := TPath.GetHomePath;
  Result := TPath.Combine(
    TPath.Combine(BaseDir, KeyFileDirectory), LegacyKeyFileName);
end;

function InstallationKeyBlobExists(const AInstallationRoot: string): Boolean;
begin
  Result := TFile.Exists(InstallationKeyFilePath(AInstallationRoot)) or
    TFile.Exists(LegacyKeyFilePath);
end;

function KeyBlobExists: Boolean;
begin
  Result := InstallationKeyBlobExists(DefaultInstallationRoot);
end;

/// Unwraps a decrypted blob into the 32-byte key. Accepts the versioned
/// format (magic + version + key) and the legacy v1 format (raw 32 bytes
/// written by the first remediation round, which never wrote anything but
/// authenticated schema-2 records).
function DecodeKeyBlob(const ADpapiPlain: TBytes; out AKey: TBytes;
  out ALegacy: Boolean): Boolean;
var
  I: Integer;
begin
  SetLength(AKey, 0);
  ALegacy := False;
  Result := False;
  if Length(ADpapiPlain) = KeySizeBytes then
  begin
    // Legacy v1 payload: the raw key without a header.
    AKey := Copy(ADpapiPlain, 0, KeySizeBytes);
    ALegacy := True;
    Exit(True);
  end;
  if Length(ADpapiPlain) < 16 then
    Exit;
  for I := 0 to 7 do
    if ADpapiPlain[I] <> KeyBlobMagic[I] then
      Exit;
  if (ADpapiPlain[8] <> KeyBlobFormatVersion) or
     (ADpapiPlain[9] <> 0) or (ADpapiPlain[10] <> 0) or (ADpapiPlain[11] <> 0) then
    Exit;
  if Length(ADpapiPlain) <> 16 + KeySizeBytes then
    Exit;
  AKey := Copy(ADpapiPlain, 16, KeySizeBytes);
  Result := True;
end;

function EncodeKeyBlob(const AKey: TBytes): TBytes;
var
  I: Integer;
begin
  SetLength(Result, 16 + KeySizeBytes);
  for I := 0 to 7 do
    Result[I] := KeyBlobMagic[I];
  Result[8] := KeyBlobFormatVersion;
  Result[9] := 0;
  Result[10] := 0;
  Result[11] := 0;
  for I := 0 to 12 do
    Result[12 + I] := 0; // reserved
  for I := 0 to KeySizeBytes - 1 do
    Result[16 + I] := AKey[I];
end;

function ReadKeyFileAt(const AKeyFile: string): TBytes;
var
  BlobBytes: TBytes;
  InputBlob, OutputBlob: TDataBlob;
  Descr: PWideChar;
  Plain: TBytes;
  Legacy: Boolean;
begin
  SetLength(Result, 0);
  BlobBytes := TFile.ReadAllBytes(AKeyFile);
  if Length(BlobBytes) = 0 then
    raise EPortappixRecordAuthError.Create(
      'The rollback record key file is empty.');

  FillChar(InputBlob, SizeOf(InputBlob), 0);
  FillChar(OutputBlob, SizeOf(OutputBlob), 0);
  Descr := nil;
  InputBlob.cbData := DWORD(Length(BlobBytes));
  InputBlob.pbData := @BlobBytes[0];
  try
    if not CryptUnprotectData(@InputBlob, Descr, nil, nil, nil,
      CRYPTPROTECT_UI_FORBIDDEN, OutputBlob) then
      raise EPortappixRecordAuthError.CreateFmt(
        'Unable to decrypt the rollback record key (error %d).',
        [Integer(GetLastError)]);
    try
      if (OutputBlob.cbData = 0) or (OutputBlob.pbData = nil) then
        raise EPortappixRecordAuthError.Create(
          'DPAPI returned an empty decrypted key blob.');
      SetLength(Plain, OutputBlob.cbData);
      Move(OutputBlob.pbData^, Plain[0], OutputBlob.cbData);
      if not DecodeKeyBlob(Plain, Result, Legacy) then
        raise EPortappixRecordAuthError.Create(
          'The rollback record key blob has an unexpected format.');
      if Length(Result) <> KeySizeBytes then
        raise EPortappixRecordAuthError.Create(
          'The decrypted rollback record key has an unexpected length.');
    finally
      LocalFreeBlob(OutputBlob);
    end;
  finally
    if Descr <> nil then
      LocalFree(HLOCAL(Descr));
  end;
end;

/// Crash-safe and overwrite-safe blob write (R13): the protected blob goes
/// to a per-process temp file created with CREATE_NEW semantics, is
/// flushed, verified, then atomically replaces the target with
/// WRITE_THROUGH and a directory flush. Any failure removes the temp file
/// and leaves the previous key file untouched.
procedure WriteKeyFileAt(const AKeyFile: string; const AProtected: TBytes);
var
  TemporaryFile: string;
  Handle: THandle;
  Written: DWORD;
begin
  ForceDirectories(TPath.GetDirectoryName(TPath.GetFullPath(AKeyFile)));
  TemporaryFile := Format('%s.%d.%d.tmp', [AKeyFile, GetCurrentProcessId,
    InterlockedIncrement(GDurableTempCounter)]);
  // CREATE_NEW: a concurrent creator (outside our mutex) loses the race
  // here instead of overwriting the winner's blob.
  Handle := CreateFile(PChar(TemporaryFile), GENERIC_WRITE, 0, nil,
    CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
  if Handle = INVALID_HANDLE_VALUE then
    raise EPortappixRecordAuthError.CreateFmt(
      'Unable to stage the rollback record key (temp file): %s',
      [SysErrorMessage(Integer(GetLastError))]);
  try
    if not WriteFile(Handle, AProtected[0], DWORD(Length(AProtected)),
      Written, nil) or (Written <> DWORD(Length(AProtected))) then
      raise EPortappixRecordAuthError.Create(
        'The staged rollback record key was not written completely.');
    if not FlushFileBuffers(Handle) then
      raise EPortappixRecordAuthError.Create(
        'Unable to flush the staged rollback record key.');
  finally
    CloseHandle(Handle);
  end;
  if not MoveFileEx(PChar(TemporaryFile), PChar(AKeyFile),
    MOVEFILE_REPLACE_EXISTING or MOVEFILE_WRITE_THROUGH) then
  begin
    try
      if TFile.Exists(TemporaryFile) then
        TFile.Delete(TemporaryFile);
    except
    end;
    raise EPortappixRecordAuthError.CreateFmt(
      'Unable to store the rollback record key (replace failed): %s',
      [SysErrorMessage(Integer(GetLastError))]);
  end;
  FlushDirectoryWindows(TPath.GetDirectoryName(TPath.GetFullPath(AKeyFile)));
end;

function AcquireKeyCreateLock(const AKeyFile: string): THandle;
var
  WaitResult: DWORD;
begin
  // Serialize first-time creation across processes (R13). Thread-recursive:
  // safe to nest where callers already hold it.
  Result := CreateMutex(nil, False,
    PChar(MutexNameFor('RecordKey', AKeyFile.ToLower)));
  if Result = 0 then
    raise EPortappixRecordAuthError.Create(
      'Unable to create the rollback-key mutex.');
  WaitResult := WaitForSingleObject(Result, 10000);
  if WaitResult = WAIT_ABANDONED then
  begin
    // The previous creator died; the durable write is an atomic replace so
    // the file is either absent or complete. Proceed and re-check.
  end
  else if WaitResult <> WAIT_OBJECT_0 then
  begin
    CloseHandle(Result);
    Result := 0;
    raise EPortappixRecordAuthError.Create(
      'Another process is creating the rollback record key; try again later.');
  end;
end;

procedure ReleaseKeyCreateLock(var AHandle: THandle);
begin
  if AHandle <> 0 then
  begin
    ReleaseMutex(AHandle);
    CloseHandle(AHandle);
    AHandle := 0;
  end;
end;

function TryGetRollbackKeyFor(const AInstallationRoot: string;
  out AKey: TBytes): Boolean;
var
  ScopedKeyFile: string;
begin  SetLength(AKey, 0);
  ScopedKeyFile := InstallationKeyFilePath(AInstallationRoot);
  if TFile.Exists(ScopedKeyFile) then
  begin
    AKey := ReadKeyFileAt(ScopedKeyFile);
    Exit(True);
  end;
  // R19 bounded migration: a pre-R19 installation has exactly one unscoped
  // key. It is adopted ONLY when the scoped key does not exist yet, and only
  // for verification (this path never creates key material). Adoption copies
  // the blob to the scoped location so the two never diverge; the legacy
  // file is left in place because other installations under the same account
  // may still need to migrate from it.
  if TFile.Exists(LegacyKeyFilePath) then
  begin
    AKey := ReadKeyFileAt(LegacyKeyFilePath);
    try
      ForceDirectories(TPath.GetDirectoryName(TPath.GetFullPath(ScopedKeyFile)));
      if not TFile.Exists(ScopedKeyFile) then
        TFile.Copy(LegacyKeyFilePath, ScopedKeyFile, False);
    except
      // Adopting is an optimization; verification still has the loaded key.
    end;
    Exit(True);
  end;
  Result := False;
end;

function TryGetInstallationRollbackKey(const AInstallationRoot: string;
  out AKey: TBytes): Boolean;
begin
  Result := TryGetRollbackKeyFor(AInstallationRoot, AKey);
end;

function TryGetRollbackKey(out AKey: TBytes): Boolean;
begin
  Result := TryGetRollbackKeyFor(DefaultInstallationRoot, AKey);
end;

function GetRollbackKeyFor(const AInstallationRoot: string): TBytes;
var
  PlainBlob: TDataBlob;
  ProtectedBlob: TDataBlob;
  KeyLock: THandle;
  Plain, ProtectedBytes: TBytes;
  ScopedKeyFile: string;
begin
  ScopedKeyFile := InstallationKeyFilePath(AInstallationRoot);
  if TFile.Exists(ScopedKeyFile) then
    Exit(ReadKeyFileAt(ScopedKeyFile));

  // R19 bounded migration: adopt the pre-R19 unscoped key on first use so an
  // existing installation keeps verifying its records after the upgrade.
  // Only the FIRST installation to run adopts it; the copy is per scope.
  if TFile.Exists(LegacyKeyFilePath) then
  begin
    Plain := ReadKeyFileAt(LegacyKeyFilePath);
    try
      ForceDirectories(TPath.GetDirectoryName(TPath.GetFullPath(ScopedKeyFile)));
      try
        TFile.Copy(LegacyKeyFilePath, ScopedKeyFile, False);
      except
        on E: Exception do
          raise EPortappixRecordAuthError.CreateFmt(
            'Unable to migrate the rollback record key to the per-installation ' +
            'scope: %s', [E.Message]);
      end;
    except
      on E: EPortappixRecordAuthError do
        raise;
    end;
    Exit(Plain);
  end;

  {$IFDEF PORTAPPIX_TESTINJECT}
  if PortappixKeyCreateDelayMs > 0 then
    Sleep(PortappixKeyCreateDelayMs);
  {$ENDIF}

  // First use on this installation: serialize creation across processes,
  // re-check, then generate, protect and store atomically (R13).
  KeyLock := AcquireKeyCreateLock(ScopedKeyFile);
  try
    // Double-check: another process may have created the key while we
    // waited for the mutex — the loser reads the winner's key.
    if TFile.Exists(ScopedKeyFile) then
      Exit(ReadKeyFileAt(ScopedKeyFile));

    Result := RandomBytes(KeySizeBytes);
    Plain := EncodeKeyBlob(Result);
    FillChar(PlainBlob, SizeOf(PlainBlob), 0);
    FillChar(ProtectedBlob, SizeOf(ProtectedBlob), 0);
    PlainBlob.cbData := DWORD(Length(Plain));
    PlainBlob.pbData := @Plain[0];
    if not CryptProtectData(@PlainBlob, 'Portappix rollback record key',
      nil, nil, nil, CRYPTPROTECT_UI_FORBIDDEN, ProtectedBlob) then
      raise EPortappixRecordAuthError.CreateFmt(
        'Unable to protect the rollback record key (error %d).',
        [Integer(GetLastError)]);
    try
      if (ProtectedBlob.cbData = 0) or (ProtectedBlob.pbData = nil) then
        raise EPortappixRecordAuthError.Create(
          'DPAPI returned an empty protected key blob.');
      SetLength(ProtectedBytes, ProtectedBlob.cbData);
      Move(ProtectedBlob.pbData^, ProtectedBytes[0], ProtectedBlob.cbData);
      try
        WriteKeyFileAt(ScopedKeyFile, ProtectedBytes);
      except
        on E: Exception do
          raise EPortappixRecordAuthError.CreateFmt(
            'Unable to store the rollback record key: %s', [E.Message]);
      end;
    finally
      LocalFreeBlob(ProtectedBlob);
    end;
  finally
    ReleaseKeyCreateLock(KeyLock);
  end;
end;

function GetInstallationRollbackKey(
  const AInstallationRoot: string): TBytes;
begin
  Result := GetRollbackKeyFor(AInstallationRoot);
end;

function GetRollbackKey: TBytes;
begin
  Result := GetRollbackKeyFor(DefaultInstallationRoot);
end;

function ComputeRecordHmac(const AKey: TBytes; const ASha256: string;
  ASize: Int64; const AVersion, ARecordedAt: string): string;
const
  HexDigits: array[0..15] of Char = '0123456789abcdef';
var
  Canonical: string;
  Digest: TBytes;
  Index: Integer;
begin
  if Length(AKey) = 0 then
    raise EPortappixRecordAuthError.Create('The rollback record key is empty.');
  // Canonical serialization: fixed field order, explicit separators,
  // length-prefixed variable strings so no field value can be shifted into
  // another field's position.
  Canonical :=
    'portappix-rollback-record-v2' + #10 +
    IntToStr(Length(ASha256)) + ':' + ASha256.ToLower + #10 +
    IntToStr(ASize) + #10 +
    IntToStr(Length(AVersion)) + ':' + AVersion + #10 +
    IntToStr(Length(ARecordedAt)) + ':' + ARecordedAt;
  Digest := THashSHA2.GetHMACAsBytes(TEncoding.UTF8.GetBytes(Canonical), AKey);
  if Length(Digest) <> 32 then
    raise EPortappixRecordAuthError.Create(
      'The HMAC computation returned an unexpected digest length.');
  SetLength(Result, Length(Digest) * 2);
  for Index := 0 to High(Digest) do
  begin
    Result[Index * 2 + 1] := HexDigits[Digest[Index] shr 4];
    Result[Index * 2 + 2] := HexDigits[Digest[Index] and $0F];
  end;
end;

function RecordHmacMatches(const AExpected, AActual: string): Boolean;
var
  Index: Integer;
begin
  Result := Length(AExpected) = Length(AActual);
  if (Length(AExpected) <> 64) or (Length(AActual) <> 64) then
    Exit(False);
  for Index := 1 to Length(AExpected) do
    if UpCase(AExpected[Index]) <> UpCase(AActual[Index]) then
      Result := False;
end;

end.
