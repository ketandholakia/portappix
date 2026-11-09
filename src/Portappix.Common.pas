unit Portappix.Common;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.StrUtils,
  System.Classes,
  System.IOUtils,
  System.Hash;

const
  PortappixManifestSchema = 1;

function LauncherDirectory: string;
function IsRelativePath(const APath: string): Boolean;
function ResolveRootPath(const APath: string): string;
function ResolveFromRoot(const ARootPath, APath: string): string;
function TrimTrailingPathDelimiter(const APath: string): string;
function ExpandManifestTokens(const AValue, ARootPath, AAppDir, ADataDir, AAppId: string): string;
function ExpandPercentVariables(const AValue: string): string;
function IsSafeFileComponent(const AValue: string): Boolean;
function IsTransientAppFolder(const AFolderName: string): Boolean;
function TextStartsWith(const AValue, APrefix: string): Boolean;
function TextEndsWith(const AValue, ASuffix: string): Boolean;
function IsPathUnder(const APath, ARootPath: string): Boolean;
function IsZipSlip(const ABaseDir, AEntryName: string): Boolean;
function Sha256File(const AFileName: string): string;
function Sha256Bytes(const AData: TBytes): string;
function Sha256Raw(const AData: TBytes): TBytes;
function Sha256FileBytes(const AFileName: string): TBytes;
function Sha256Text(const AText: string): string;
function BytesToHexString(const AData: TBytes): string;
function MutexNameFor(const APrefix, AValue: string): string;
function LauncherMutexName(const ARootPath: string): string;
function AppMutexName(const ARootPath, AAppId: string): string;
function IsAppRunning(const ARootPath, AAppId: string): Boolean;
function TryAcquireMutex(const AName: string; out AHandle: THandle): Boolean;
procedure ReleaseMutexHandle(var AHandle: THandle);
function WriteTextFileAtomic(const AFileName, AContent: string): Boolean;

type
  TPortappixSingleInstance = class
  private
    FHandle: THandle;
    FName: string;
  public
    constructor Create(const ARootPath: string);
    destructor Destroy; override;
    property Handle: THandle read FHandle;
    property Name: string read FName;
    function IsOwner: Boolean;
  end;

implementation

function LauncherDirectory: string;
begin
  Result := TPath.GetDirectoryName(ParamStr(0));
  if Result = '' then
    Result := GetCurrentDir;
end;

function IsRelativePath(const APath: string): Boolean;
begin
  if APath = '' then
    Exit(True);
  if (Length(APath) >= 2) and (APath[2] = ':') then
    Exit(False);
  if (Length(APath) >= 2) and (APath[1] = '\') and (APath[2] = '\') then
    Exit(False);
  if APath[1] = '\' then
    Exit(False);
  Result := True;
end;

function ResolveRootPath(const APath: string): string;
begin
  if APath = '' then
    Exit(TPath.GetFullPath(LauncherDirectory));
  if IsRelativePath(APath) then
    Result := TPath.GetFullPath(TPath.Combine(LauncherDirectory, APath))
  else
    Result := TPath.GetFullPath(APath);
end;

function ResolveFromRoot(const ARootPath, APath: string): string;
var
  ResolvedRoot: string;
begin
  if APath = '' then
    Exit('');
  ResolvedRoot := ResolveRootPath(ARootPath);
  if IsRelativePath(APath) then
    Result := TPath.GetFullPath(TPath.Combine(ResolvedRoot, APath))
  else
    Result := TPath.GetFullPath(APath);
end;

function TrimTrailingPathDelimiter(const APath: string): string;
begin
  Result := APath;
  if (Length(Result) <= 1) or (Result[Length(Result)] <> '\') then
    Exit;
  if (Length(Result) = 3) and (Result[2] = ':') then
    Exit;
  Result := Copy(Result, 1, Length(Result) - 1);
end;

function ExpandManifestTokens(const AValue, ARootPath, AAppDir, ADataDir,
  AAppId: string): string;
begin
  Result := AValue;
  Result := StringReplace(Result, '{root}', TrimTrailingPathDelimiter(ARootPath),
    [rfReplaceAll, rfIgnoreCase]);
  Result := StringReplace(Result, '{app}', TrimTrailingPathDelimiter(AAppDir),
    [rfReplaceAll, rfIgnoreCase]);
  Result := StringReplace(Result, '{data}', TrimTrailingPathDelimiter(ADataDir),
    [rfReplaceAll, rfIgnoreCase]);
  Result := StringReplace(Result, '{id}', AAppId, [rfReplaceAll, rfIgnoreCase]);
end;

function ExpandPercentVariables(const AValue: string): string;
var
  StartPosition: Integer;
  EndPosition: Integer;
  VariableName: string;
  Replacement: string;
begin
  Result := AValue;
  StartPosition := 1;

  while StartPosition <= Length(Result) do
  begin
    if Result[StartPosition] <> '%' then
    begin
      Inc(StartPosition);
      Continue;
    end;

    EndPosition := PosEx('%', Result, StartPosition + 1);
    if EndPosition = 0 then
      Break;

    VariableName := Copy(Result, StartPosition + 1, EndPosition - StartPosition - 1);
    Replacement := GetEnvironmentVariable(VariableName);
    if (VariableName <> '') and (Replacement <> '') then
    begin
      Result := Copy(Result, 1, StartPosition - 1) + Replacement +
        Copy(Result, EndPosition + 1, MaxInt);
      Inc(StartPosition, Length(Replacement));
    end
    else
      Inc(StartPosition, EndPosition - StartPosition + 1);
  end;
end;

function IsSafeFileComponent(const AValue: string): Boolean;
const
  InvalidCharacters: TSysCharSet = ['\', '/', ':', '*', '?', '"', '<', '>', '|'];
begin
  Result := (AValue <> '') and (AValue <> '.') and (AValue <> '..');
  if not Result then
    Exit;

  for var Character in AValue do
    if (Character < ' ') or CharInSet(Character, InvalidCharacters) then
      Exit(False);
end;

function TextStartsWith(const AValue, APrefix: string): Boolean;
begin
  if APrefix = '' then
    Exit(True);
  if Length(AValue) < Length(APrefix) then
    Exit(False);
  Result := SameText(Copy(AValue, 1, Length(APrefix)), APrefix);
end;

function TextEndsWith(const AValue, ASuffix: string): Boolean;
var
  StartPosition: Integer;
begin
  if ASuffix = '' then
    Exit(True);
  StartPosition := Length(AValue) - Length(ASuffix) + 1;
  Result := (StartPosition > 0) and SameText(Copy(AValue, StartPosition, Length(ASuffix)), ASuffix);
end;

function IsTransientAppFolder(const AFolderName: string): Boolean;
begin
  Result := TextEndsWith(AFolderName, '.new') or
    TextEndsWith(AFolderName, '.old') or
    TextEndsWith(AFolderName, '.prev');
end;

function IsPathUnder(const APath, ARootPath: string): Boolean;
var
  FullPath: string;
  FullRoot: string;
begin
  FullPath := IncludeTrailingPathDelimiter(TPath.GetFullPath(APath));
  FullRoot := IncludeTrailingPathDelimiter(TPath.GetFullPath(ARootPath));
  Result := TextStartsWith(FullPath, FullRoot);
end;

function IsZipSlip(const ABaseDir, AEntryName: string): Boolean;
var
  FullPath: string;
  BasePath: string;
begin
  BasePath := IncludeTrailingPathDelimiter(TPath.GetFullPath(ABaseDir));
  FullPath := TPath.GetFullPath(TPath.Combine(ABaseDir, AEntryName));
  Result := not TextStartsWith(FullPath, BasePath);
end;

function BytesToHexString(const AData: TBytes): string;
const
  HexDigits: array[0..15] of Char = '0123456789abcdef';
begin
  SetLength(Result, Length(AData) * 2);
  for var Index := 0 to High(AData) do
  begin
    Result[Index * 2 + 1] := HexDigits[AData[Index] shr 4];
    Result[Index * 2 + 2] := HexDigits[AData[Index] and $0F];
  end;
end;

function Sha256Raw(const AData: TBytes): TBytes;
var
  Hash: THashSHA2;
begin
  Hash := THashSHA2.Create(THashSHA2.TSHA2Version.SHA256);
  if Length(AData) > 0 then
    Hash.Update(AData);
  Result := Hash.HashAsBytes;
end;

function Sha256Bytes(const AData: TBytes): string;
begin
  Result := BytesToHexString(Sha256Raw(AData));
end;

function Sha256FileBytes(const AFileName: string): TBytes;
var
  Stream: TFileStream;
begin
  Stream := TFileStream.Create(AFileName, fmOpenRead or fmShareDenyWrite);
  try
    SetLength(Result, Stream.Size);
    if Length(Result) > 0 then
      Stream.ReadBuffer(Result[0], Length(Result));
  finally
    Stream.Free;
  end;
end;

function Sha256File(const AFileName: string): string;
begin
  Result := Sha256Bytes(Sha256FileBytes(AFileName));
end;

function Sha256Text(const AText: string): string;
begin
  Result := Sha256Bytes(TEncoding.UTF8.GetBytes(AText));
end;

function MutexNameFor(const APrefix, AValue: string): string;
begin
  Result := 'Local\Portappix.' + APrefix + '.' +
    Copy(Sha256Text(AValue), 1, 24);
end;

function LauncherMutexName(const ARootPath: string): string;
begin
  Result := MutexNameFor('Launcher', ResolveRootPath(ARootPath).ToLower);
end;

function AppMutexName(const ARootPath, AAppId: string): string;
begin
  Result := MutexNameFor('App',
    ResolveRootPath(ARootPath).ToLower + '|' + AAppId.ToLower);
end;

function TryAcquireMutex(const AName: string; out AHandle: THandle): Boolean;
var
  LastError: DWORD;
begin
  AHandle := CreateMutex(nil, True, PChar(AName));
  if AHandle = 0 then
    Exit(False);

  LastError := GetLastError;
  if LastError = ERROR_ALREADY_EXISTS then
  begin
    CloseHandle(AHandle);
    AHandle := 0;
    Exit(False);
  end;

  Result := True;
end;

procedure ReleaseMutexHandle(var AHandle: THandle);
begin
  if AHandle <> 0 then
  begin
    ReleaseMutex(AHandle);
    CloseHandle(AHandle);
    AHandle := 0;
  end;
end;

function IsAppRunning(const ARootPath, AAppId: string): Boolean;
var
  Handle: THandle;
begin
  Handle := OpenMutex(SYNCHRONIZE, False, PChar(AppMutexName(ARootPath, AAppId)));
  Result := Handle <> 0;
  if Result then
    CloseHandle(Handle);
end;

function WriteTextFileAtomic(const AFileName, AContent: string): Boolean;
var
  TemporaryFile: string;
begin
  TemporaryFile := AFileName + '.tmp';
  try
    TFile.WriteAllText(TemporaryFile, AContent, TEncoding.UTF8);
  except
    Exit(False);
  end;

  Result := MoveFileEx(PChar(TemporaryFile), PChar(AFileName),
    MOVEFILE_REPLACE_EXISTING or MOVEFILE_WRITE_THROUGH);
  if not Result then
    try
      TFile.Delete(TemporaryFile);
    except
    end;
end;

constructor TPortappixSingleInstance.Create(const ARootPath: string);
begin
  inherited Create;
  FName := LauncherMutexName(ARootPath);
  if not TryAcquireMutex(FName, FHandle) then
    FHandle := 0;
end;

destructor TPortappixSingleInstance.Destroy;
begin
  ReleaseMutexHandle(FHandle);
  inherited;
end;

function TPortappixSingleInstance.IsOwner: Boolean;
begin
  Result := FHandle <> 0;
end;

end.
