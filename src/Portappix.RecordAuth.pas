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

  Mechanism: a 32-byte random per-installation key, DPAPI-protected
  (CryptProtectData, user scope) and stored under %LOCALAPPDATA%\Portappix.
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

/// Returns the per-installation rollback key (32 bytes), creating and
/// DPAPI-protecting it on first use. Raises EPortappixRecordAuthError when
/// the key cannot be created or decrypted (callers must fail closed).
function GetRollbackKey: TBytes;

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
{$ENDIF}

implementation

uses
  System.Classes,
  System.Hash,
  System.IOUtils;

const
  KeyFileDirectory = 'Portappix';
  KeyFileName = 'rollback_key.bin';
  KeySizeBytes = 32;

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

function KeyFilePath: string;
begin
  {$IFDEF PORTAPPIX_TESTCRASH}
  if PortappixRecordKeyPathOverride <> '' then
    Exit(PortappixRecordKeyPathOverride);
  {$ENDIF}
  Result := TPath.Combine(
    TPath.Combine(TPath.GetHomePath, KeyFileDirectory), KeyFileName);
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

function ReadKeyFile: TBytes;
var
  BlobBytes: TBytes;
  InputBlob, OutputBlob: TDataBlob;
  Descr: PWideChar;
begin
  SetLength(Result, 0);
  BlobBytes := TFile.ReadAllBytes(KeyFilePath);
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
      if (OutputBlob.cbData <> KeySizeBytes) or (OutputBlob.pbData = nil) then
        raise EPortappixRecordAuthError.Create(
          'The decrypted rollback record key has an unexpected length.');
      SetLength(Result, OutputBlob.cbData);
      Move(OutputBlob.pbData^, Result[0], OutputBlob.cbData);
    finally
      LocalFreeBlob(OutputBlob);
    end;
  finally
    if Descr <> nil then
      LocalFree(HLOCAL(Descr));
  end;
end;

procedure WriteKeyFile(const AProtected: TDataBlob);
var
  Stream: TFileStream;
begin
  ForceDirectories(TPath.GetDirectoryName(TPath.GetFullPath(KeyFilePath)));
  // The user profile directory already carries a user-only ACL on NTFS; the
  // file is additionally created without wide sharing so a concurrent first
  // use cannot interleave.
  Stream := TFileStream.Create(KeyFilePath, fmCreate or fmShareExclusive);
  try
    if AProtected.cbData > 0 then
      Stream.WriteBuffer(AProtected.pbData^, AProtected.cbData);
  finally
    Stream.Free;
  end;
end;

function GetRollbackKey: TBytes;
var
  PlainBlob, ProtectedBlob: TDataBlob;
begin
  if TFile.Exists(KeyFilePath) then
    Exit(ReadKeyFile);

  // First use on this installation: generate, protect, store.
  Result := RandomBytes(KeySizeBytes);
  FillChar(PlainBlob, SizeOf(PlainBlob), 0);
  FillChar(ProtectedBlob, SizeOf(ProtectedBlob), 0);
  PlainBlob.cbData := DWORD(Length(Result));
  PlainBlob.pbData := @Result[0];
  if not CryptProtectData(@PlainBlob, 'Portappix rollback record key',
    nil, nil, nil, CRYPTPROTECT_UI_FORBIDDEN, ProtectedBlob) then
    raise EPortappixRecordAuthError.CreateFmt(
      'Unable to protect the rollback record key (error %d).',
      [Integer(GetLastError)]);
  try
    if (ProtectedBlob.cbData = 0) or (ProtectedBlob.pbData = nil) then
      raise EPortappixRecordAuthError.Create(
        'DPAPI returned an empty protected key blob.');
    try
      WriteKeyFile(ProtectedBlob);
    except
      on E: Exception do
        raise EPortappixRecordAuthError.CreateFmt(
          'Unable to store the rollback record key: %s', [E.Message]);
    end;
  finally
    LocalFreeBlob(ProtectedBlob);
  end;
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
