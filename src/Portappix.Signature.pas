unit Portappix.Signature;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes,
  Portappix.Common;

type
  EPortappixSignatureError = class(Exception);

const
  // Trusted ECDSA P-256 public key (CNG ECCPUBLICBLOB: magic, 32-byte key
  // length, X, Y). Rotated 2026-11-09 after the previous signing key was
  // found inside a distribution archive (docs/security/SIGNING_KEY_MANAGEMENT.md).
  // The matching public PEM ships as keys/catalog_public.pem; the private key
  // never lives in the repository.
  CatalogPublicKeyHex =
    '4543533120000000DE8A5F92FA779AA955D7B70394B98F03F3E8B8903D40384C9A3A003D' +
    '3AFEC2772B418796C385464E44921354D45520754CA688C1D0C89B6DC25400D40A4D6C56';

{$IFDEF PORTAPPIX_TESTUPDATE}
  PortappixTestUpdateMarker = 'PORTAPPIX-TESTUPDATE-BUILD-2026-11-10';
  {$I PortappixTestKey.inc}
{$ENDIF}

  BCRYPT_ECDSA_PUBLIC_P256_MAGIC = $31534345;
  BCRYPT_ECDSA_P256_ALGORITHM = 'ECDSA_P256';
  BCRYPT_ECCPUBLIC_BLOB = 'ECCPUBLICBLOB';
  BCRYPT_SHA256_ALGORITHM = 'SHA256';

function HexToBytes(const AHex: string): TBytes;
function CatalogPublicKeyBlob: TBytes;
function VerifySignatureWithKey(const AContent, ASignature, APublicKey: TBytes): Boolean;
function VerifySignature(const AContent, ASignature: TBytes): Boolean;
function VerifySignatureForCatalog(const AContent, ASignature: TBytes): Boolean;

implementation

type
  TPortappixNtStatus = LongInt;

function BCryptOpenAlgorithmProvider(out phAlgorithm: THandle; pszAlgId: LPCWSTR;
  pszImplementation: LPCWSTR; dwFlags: ULONG): TPortappixNtStatus; stdcall;
  external 'bcrypt.dll';
function BCryptCloseAlgorithmProvider(hAlgorithm: THandle; dwFlags: ULONG): TPortappixNtStatus;
  stdcall; external 'bcrypt.dll';
function BCryptImportKeyPair(hAlgorithm: THandle; hImportKey: THandle;
  pszBlobType: LPCWSTR; out phKey: THandle; pbInput: PByte; cbInput: ULONG;
  dwFlags: ULONG): TPortappixNtStatus; stdcall; external 'bcrypt.dll';
function BCryptDestroyKey(hKey: THandle): TPortappixNtStatus; stdcall;
  external 'bcrypt.dll';
function BCryptVerifySignature(hKey: THandle; pPaddingInfo: Pointer; pbHash: PByte;
  cbHash: ULONG; pbSignature: PByte; cbSignature: ULONG; dwFlags: ULONG): TPortappixNtStatus;
  stdcall; external 'bcrypt.dll';

function HexToBytes(const AHex: string): TBytes;
var
  Clean: string;
  Value: Integer;
begin
  Clean := AHex.Trim;
  SetLength(Result, Length(Clean) div 2);
  for var Index := 0 to High(Result) do
  begin
    if not TryStrToInt('$' + Copy(Clean, Index * 2 + 1, 2), Value) then
      raise EPortappixSignatureError.Create('Invalid hexadecimal key material.');
    Result[Index] := Byte(Value);
  end;
end;

function CatalogPublicKeyBlob: TBytes;
begin
{$IFDEF PORTAPPIX_TESTUPDATE}
  if Length(Trim(TestPublicKeyHex)) = 144 then
    Exit(HexToBytes(Trim(TestPublicKeyHex)));
{$ENDIF}
  Result := HexToBytes(CatalogPublicKeyHex);
end;

function VerifySignatureWithKey(const AContent, ASignature, APublicKey: TBytes): Boolean;
var
  Algorithm: THandle;
  Key: THandle;
  Status: TPortappixNtStatus;
  Hash: TBytes;
begin
  Result := False;
  if Length(AContent) = 0 then
    Exit;
  if Length(ASignature) <> 64 then
    Exit;
  // Fail closed on any public key that is not a complete 72-byte P-256
  // ECCPUBLICBLOB (magic + key length + X + Y).
  if Length(APublicKey) <> 72 then
    Exit;

  Hash := Sha256Raw(AContent);
  if Length(Hash) <> 32 then
    Exit;

  Algorithm := 0;
  Key := 0;
  Status := BCryptOpenAlgorithmProvider(Algorithm, BCRYPT_ECDSA_P256_ALGORITHM, nil, 0);
  if Status <> 0 then
    Exit;

  try
    Status := BCryptImportKeyPair(Algorithm, 0, BCRYPT_ECCPUBLIC_BLOB, Key,
      PByte(@APublicKey[0]), Length(APublicKey), 0);
    if Status <> 0 then
      Exit(False);

    try
      Status := BCryptVerifySignature(Key, nil, PByte(@Hash[0]), Length(Hash),
        PByte(@ASignature[0]), Length(ASignature), 0);
      Result := Status = 0;
    finally
      BCryptDestroyKey(Key);
    end;
  finally
    BCryptCloseAlgorithmProvider(Algorithm, 0);
  end;
end;

function VerifySignature(const AContent, ASignature: TBytes): Boolean;
var
  PublicKey: TBytes;
begin
  PublicKey := CatalogPublicKeyBlob;
  Result := VerifySignatureWithKey(AContent, ASignature, PublicKey);
end;

function VerifySignatureForCatalog(const AContent, ASignature: TBytes): Boolean;
begin
  Result := VerifySignature(AContent, ASignature);
end;

end.
