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
  CatalogPublicKeyHex =
    '4543533120000000A9ED638DB255D1CEC43A7BCA227247BD2A6A2667C8488C985732CD8A9828E522' +
    'AAF3945B6E71F5CB811E1EF272A4A3775E127A60C87F59916F6E6A10A0609E0F';

  BCRYPT_ECDSA_PUBLIC_P256_MAGIC = $31534345;
  BCRYPT_ECDSA_P256_ALGORITHM = 'ECDSA_P256';
  BCRYPT_ECCPUBLIC_BLOB = 'ECCPUBLICBLOB';
  BCRYPT_SHA256_ALGORITHM = 'SHA256';

function HexToBytes(const AHex: string): TBytes;
function CatalogPublicKeyBlob: TBytes;
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
  Result := HexToBytes(CatalogPublicKeyHex);
end;

function VerifySignature(const AContent, ASignature: TBytes): Boolean;
var
  Algorithm: THandle;
  Key: THandle;
  Status: TPortappixNtStatus;
  PublicKey: TBytes;
  Hash: TBytes;
begin
  Result := False;
  if Length(AContent) = 0 then
    Exit;
  if Length(ASignature) <> 64 then
    Exit;

  PublicKey := CatalogPublicKeyBlob;
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
      PByte(@PublicKey[0]), Length(PublicKey), 0);
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

function VerifySignatureForCatalog(const AContent, ASignature: TBytes): Boolean;
begin
  Result := VerifySignature(AContent, ASignature);
end;

end.
