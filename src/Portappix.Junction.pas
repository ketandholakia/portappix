unit Portappix.Junction;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.IOUtils,
  Portappix.Common;

function IsReparsePoint(const APath: string): Boolean;
function CreateJunction(const AJunctionPath, ATargetPath: string): Boolean;
function DeleteJunction(const AJunctionPath: string): Boolean;

implementation

const
  FSCTL_SET_REPARSE_POINT = $000900A4;
  FSCTL_DELETE_REPARSE_POINT = $000900AC;
  IO_REPARSE_TAG_MOUNT_POINT = $A0000003;
  ReparseHeaderSize = SizeOf(ULONG) + SizeOf(USHORT) * 2 + SizeOf(USHORT) * 4;

type
  TReparseDataBuffer = record
    ReparseTag: ULONG;
    ReparseDataLength: USHORT;
    Reserved: USHORT;
    SubstituteNameOffset: USHORT;
    SubstituteNameLength: USHORT;
    PrintNameOffset: USHORT;
    PrintNameLength: USHORT;
    PathBuffer: array[0..0] of WCHAR;
  end;
  PReparseDataBuffer = ^TReparseDataBuffer;

function IsReparsePoint(const APath: string): Boolean;
var
  Attributes: DWORD;
begin
  Attributes := GetFileAttributes(PChar(APath));
  Result := (Attributes <> INVALID_FILE_ATTRIBUTES) and
    ((Attributes and FILE_ATTRIBUTE_REPARSE_POINT) <> 0);
end;

function OpenReparsePoint(const APath: string): THandle;
begin
  Result := CreateFile(PChar(APath), GENERIC_READ or GENERIC_WRITE,
    FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE, nil, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS or FILE_FLAG_OPEN_REPARSE_POINT, 0);
end;

function CreateJunction(const AJunctionPath, ATargetPath: string): Boolean;
var
  Handle: THandle;
  SubstituteName: string;
  PrintName: string;
  Buffer: PByte;
  BufferSize: Cardinal;
  Data: PReparseDataBuffer;
  PathBytes: Cardinal;
  Returned: DWORD;
begin
  Result := False;
  if not CreateDirectory(PChar(AJunctionPath), nil) and
     (GetLastError <> ERROR_ALREADY_EXISTS) then
    Exit;

  Handle := OpenReparsePoint(AJunctionPath);
  if Handle = INVALID_HANDLE_VALUE then
  begin
    RemoveDir(AJunctionPath);
    Exit;
  end;

  try
    SubstituteName := '\??\' + TrimTrailingPathDelimiter(ATargetPath);
    PrintName := TrimTrailingPathDelimiter(ATargetPath);
    PathBytes := Cardinal((Length(SubstituteName) + Length(PrintName)) * SizeOf(WCHAR));
    BufferSize := ReparseHeaderSize + PathBytes + SizeOf(WCHAR);
    GetMem(Buffer, BufferSize);
    try
      FillChar(Buffer^, BufferSize, 0);
      Data := PReparseDataBuffer(Buffer);
      Data.ReparseTag := IO_REPARSE_TAG_MOUNT_POINT;
      Data.ReparseDataLength := USHORT(SizeOf(USHORT) * 4 + PathBytes);
      Data.SubstituteNameOffset := 0;
      Data.SubstituteNameLength := USHORT(Length(SubstituteName) * SizeOf(WCHAR));
      Data.PrintNameOffset := Data.SubstituteNameLength;
      Data.PrintNameLength := USHORT(Length(PrintName) * SizeOf(WCHAR));
      Move(SubstituteName[1], Data.PathBuffer[0], Data.SubstituteNameLength);
      Move(PrintName[1], PByte(@Data.PathBuffer[0])[Data.PrintNameOffset],
        Data.PrintNameLength);

      Result := DeviceIoControl(Handle, FSCTL_SET_REPARSE_POINT, Buffer, BufferSize,
        nil, 0, Returned, nil);
    finally
      FreeMem(Buffer);
    end;
  finally
    CloseHandle(Handle);
  end;

  if not Result then
    RemoveDir(AJunctionPath);
end;

function DeleteJunction(const AJunctionPath: string): Boolean;
var
  Handle: THandle;
  Buffer: array[0..7] of Byte;
  Data: PReparseDataBuffer;
  Returned: DWORD;
begin
  Result := False;
  Handle := OpenReparsePoint(AJunctionPath);
  if Handle <> INVALID_HANDLE_VALUE then
  begin
    try
      FillChar(Buffer, SizeOf(Buffer), 0);
      Data := PReparseDataBuffer(@Buffer[0]);
      Data.ReparseTag := IO_REPARSE_TAG_MOUNT_POINT;
      Data.ReparseDataLength := 0;
      Data.Reserved := 0;
      Result := DeviceIoControl(Handle, FSCTL_DELETE_REPARSE_POINT, @Buffer[0],
        SizeOf(ULONG) + SizeOf(USHORT) * 2, nil, 0, Returned, nil);
    finally
      CloseHandle(Handle);
    end;
  end;

  if Result then
    Result := RemoveDir(AJunctionPath);
end;

end.
