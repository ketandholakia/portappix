unit Portappix.Junction;

{
  NTFS junction support: creation, deletion, and read-only inspection of
  reparse points. Inspection classifies the object (mount-point junction,
  symbolic link, other reparse tag, ordinary directory/file, missing,
  uninspectable) WITHOUT following the reparse point, captures the parsed
  target and the filesystem object identity, and never treats a failed
  inspection as an ordinary directory.

  Junction buffer layout (verified byte-for-byte against junctions created
  by Windows itself, e.g. mklink /J): the generic reparse header is 8 bytes
  (tag, data length, reserved), the mount-point fields are four USHORTs
  after it, the substitute and print names carry no terminators, the print
  name starts one WCHAR after the substitute name ends, and the data length
  covers the fields plus both names plus two trailing pad bytes. Any
  deviation is rejected by the file system with
  ERROR_REPARSE_ATTRIBUTE_MISMATCH (4392).
}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.IOUtils,
  Portappix.Common;

const
  // Public so callers (tests, reconciler) can compare tags without magic
  // numbers. Other tags exist; Portappix only interprets these two.
  IO_REPARSE_TAG_MOUNT_POINT = $A0000003;
  IO_REPARSE_TAG_SYMLINK = $A000000C;
  // The generic reparse-point header: tag + data length + reserved. The
  // mount-point fields (4 x USHORT) live AFTER this header; name offsets
  // are relative to the PathBuffer that follows them.
  ReparseHeaderSize = SizeOf(ULONG) + SizeOf(USHORT) * 2;
  // Minimum bytes needed to read the header plus the tag-specific fields.
  MinReparseBufferSize = ReparseHeaderSize + SizeOf(USHORT) * 4;
  MaxReparseDataSize = 16 * 1024;

type
  // The Microsoft reparse-data layout shared by mount points and symlinks;
  // exposed for callers that feed synthetic buffers to ParseReparseBuffer.
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

  TPortappixReparseKind = (
    rkMissing,          // the path does not exist
    rkFile,             // ordinary file
    rkDirectory,        // ordinary directory (not a reparse point)
    rkJunction,         // mount-point junction (IO_REPARSE_TAG_MOUNT_POINT)
    rkSymlink,          // symbolic link (IO_REPARSE_TAG_SYMLINK)
    rkOtherReparse,     // any other reparse-tagged object
    rkInspectionFailed  // the object exists but could not be inspected
  );

  TPortappixPathInspection = record
    Path: string;
    Kind: TPortappixReparseKind;
    Attributes: DWORD;
    ReparseTag: ULONG;
    // Decoded substitute name (junction/symlink target) with the NT prefix
    // removed; empty when unsupported or not safely parsed.
    Target: string;
    TargetParsed: Boolean;
    // Object identity "volumeSerial:fileIndex" captured from the open
    // handle; empty when unavailable.
    Identity: string;
    ErrorMessage: string;
    function IsMountPoint: Boolean;
  end;

function IsReparsePoint(const APath: string): Boolean;
function GetJunctionTarget(const AJunctionPath: string): string;
function InspectPath(const APath: string): TPortappixPathInspection;
function ParseReparseBuffer(const AData: TBytes; const APath: string;
  var AInspection: TPortappixPathInspection): Boolean;
function CreateJunction(const AJunctionPath, ATargetPath: string): Boolean;
function DeleteJunction(const AJunctionPath: string): Boolean;

implementation

const
  FSCTL_SET_REPARSE_POINT = $000900A4;
  FSCTL_GET_REPARSE_POINT = $000900A8;
  FSCTL_DELETE_REPARSE_POINT = $000900AC;

type
  TReparseDataBufferPriv = record
    ReparseTag: ULONG;
    ReparseDataLength: USHORT;
    Reserved: USHORT;
    SubstituteNameOffset: USHORT;
    SubstituteNameLength: USHORT;
    PrintNameOffset: USHORT;
    PrintNameLength: USHORT;
    PathBuffer: array[0..0] of WCHAR;
  end;
  PReparseDataBufferPriv = ^TReparseDataBufferPriv;

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

function TPortappixPathInspection.IsMountPoint: Boolean;
begin
  Result := (Kind = rkJunction) and (ReparseTag = IO_REPARSE_TAG_MOUNT_POINT);
end;

function OpenReparsePointRead(const APath: string; out AHandle: THandle;
  out AErrorMessage: string): Boolean;
var
  LastError: DWORD;
begin
  // Open WITHOUT following the reparse point so the object's own tag and
  // data are inspected, and read-only so inspection never mutates.
  AHandle := CreateFile(PChar(APath), GENERIC_READ,
    FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE, nil, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS or FILE_FLAG_OPEN_REPARSE_POINT, 0);
  Result := AHandle <> INVALID_HANDLE_VALUE;
  if not Result then
  begin
    LastError := GetLastError;
    AErrorMessage := Format('unable to open the object for inspection (error %u: %s)',
      [LastError, SysErrorMessage(Integer(LastError))]);
  end;
end;

function ReadReparseBuffer(AHandle: THandle; out AData: TBytes;
  out AErrorMessage: string): Boolean;
var
  Returned: DWORD;
begin
  Result := False;
  SetLength(AData, MaxReparseDataSize);
  if not DeviceIoControl(AHandle, FSCTL_GET_REPARSE_POINT, nil, 0,
    @AData[0], Length(AData), Returned, nil) then
  begin
    AErrorMessage := Format('FSCTL_GET_REPARSE_POINT failed (error %u: %s)',
      [GetLastError, SysErrorMessage(Integer(GetLastError))]);
    Exit;
  end;
  if Returned < MinReparseBufferSize then
  begin
    AErrorMessage := Format('the reparse buffer is too small (%u bytes)', [Returned]);
    Exit;
  end;
  SetLength(AData, Returned);
  Result := True;
end;

function ParseReparseBuffer(const AData: TBytes; const APath: string;
  var AInspection: TPortappixPathInspection): Boolean;
var
  Data: PReparseDataBufferPriv;
  BufferEnd: Integer;
  SubstituteName, PrintName: string;

  function ReadName(AOffset, ALength: USHORT): string;
  var
    Text: string;
  begin
    Result := '';
    if ALength = 0 then
      Exit;
    if (16 + Integer(AOffset) + Integer(ALength)) > BufferEnd then
      raise ERangeError.Create('reparse name exceeds the reparse buffer');
    Text := PWChar(PByte(@Data.PathBuffer[0]) + AOffset);
    SetLength(Text, ALength div SizeOf(WCHAR));
    Result := Text;
  end;

begin
  Result := False;
  // AInspection arrives pre-filled (path, kind, identity from the open
  // handle); only the parse-dependent fields are managed here.
  AInspection.Path := APath;
  AInspection.Target := '';
  AInspection.TargetParsed := False;

  if Length(AData) < MinReparseBufferSize then
  begin
    AInspection.ErrorMessage := Format('the reparse buffer is too small (%d bytes)',
      [Length(AData)]);
    Exit;
  end;

  Data := PReparseDataBufferPriv(@AData[0]);
  AInspection.ReparseTag := Data.ReparseTag;

  // Validate the declared data length against the actual buffer before any
  // tag-specific parsing; a lying length is treated as malformed. The names
  // live in the PathBuffer after the 8-byte header and the 8-byte
  // mount-point fields, and must end within the returned buffer.
  if (ReparseHeaderSize + Integer(Data.ReparseDataLength)) > Length(AData) then
  begin
    AInspection.ErrorMessage := Format(
      'the reparse data length (%d) exceeds the buffer size (%d)',
      [Data.ReparseDataLength, Length(AData)]);
    Exit;
  end;
  BufferEnd := Length(AData);

  if Data.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT then
  begin
    try
      SubstituteName := ReadName(Data.SubstituteNameOffset, Data.SubstituteNameLength);
      PrintName := ReadName(Data.PrintNameOffset, Data.PrintNameLength);
    except
      on E: ERangeError do
      begin
        AInspection.ErrorMessage := 'malformed mount-point reparse data: ' + E.Message;
        Exit;
      end;
    end;
    if SubstituteName = '' then
    begin
      AInspection.ErrorMessage := 'the mount point has an empty substitute name';
      Exit;
    end;
    if SubstituteName.StartsWith('\??\', True) then
      Delete(SubstituteName, 1, 4);
    AInspection.Kind := rkJunction;
    AInspection.Target := TrimTrailingPathDelimiter(SubstituteName);
    AInspection.TargetParsed := True;
    Exit(True);
  end;

  if Data.ReparseTag = IO_REPARSE_TAG_SYMLINK then
  begin
    try
      SubstituteName := ReadName(Data.SubstituteNameOffset, Data.SubstituteNameLength);
      PrintName := ReadName(Data.PrintNameOffset, Data.PrintNameLength);
    except
      on E: ERangeError do
      begin
        AInspection.ErrorMessage := 'malformed symbolic-link reparse data: ' + E.Message;
        Exit;
      end;
    end;
    AInspection.Kind := rkSymlink;
    if SubstituteName.StartsWith('\??\', True) then
      Delete(SubstituteName, 1, 4);
    AInspection.Target := SubstituteName;
    AInspection.TargetParsed := True;
    Exit(True);
  end;

  // Any other tag is recognized but never interpreted.
  AInspection.Kind := rkOtherReparse;
  AInspection.ErrorMessage := Format('unsupported reparse tag 0x%.8x', [Data.ReparseTag]);
  Result := True;
end;

function GetJunctionTarget(const AJunctionPath: string): string;
var
  Inspection: TPortappixPathInspection;
begin
  Inspection := InspectPath(AJunctionPath);
  if Inspection.IsMountPoint and Inspection.TargetParsed then
    Result := Inspection.Target
  else
    Result := '';
end;

function InspectPath(const APath: string): TPortappixPathInspection;
var
  Attributes: DWORD;
  Handle: THandle;
  ErrorMessage: string;
  Data: TBytes;
  Info: TByHandleFileInformation;
begin
  Result := Default(TPortappixPathInspection);
  Result.Path := APath;
  Result.TargetParsed := False;

  Attributes := GetFileAttributes(PChar(APath));
  if Attributes = INVALID_FILE_ATTRIBUTES then
  begin
    case GetLastError of
      ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND:
        Result.Kind := rkMissing;
      ERROR_ACCESS_DENIED:
        begin
          Result.Kind := rkInspectionFailed;
          Result.ErrorMessage := 'access denied while inspecting the path';
        end;
    else
      begin
        Result.Kind := rkInspectionFailed;
        Result.ErrorMessage := Format('GetFileAttributes failed (error %u: %s)',
          [GetLastError, SysErrorMessage(Integer(GetLastError))]);
      end;
    end;
    Exit;
  end;

  Result.Attributes := Attributes;
  if (Attributes and FILE_ATTRIBUTE_REPARSE_POINT) = 0 then
  begin
    if (Attributes and FILE_ATTRIBUTE_DIRECTORY) <> 0 then
      Result.Kind := rkDirectory
    else
      Result.Kind := rkFile;
    Exit;
  end;

  // A reparse point: open the object itself (never the target).
  if not OpenReparsePointRead(APath, Handle, ErrorMessage) then
  begin
    Result.Kind := rkInspectionFailed;
    Result.ErrorMessage := ErrorMessage;
    Exit;
  end;
  try
    // Object identity from the same handle: a deleted-and-recreated object
    // gets a new file index, which is how external replacement is detected.
    if GetFileInformationByHandle(Handle, Info) then
      Result.Identity := Format('%.8x:%.8x%.8x', [Info.dwVolumeSerialNumber,
        Info.nFileIndexHigh, Info.nFileIndexLow]);

    if not ReadReparseBuffer(Handle, Data, ErrorMessage) then
    begin
      Result.Kind := rkInspectionFailed;
      Result.ErrorMessage := ErrorMessage;
      Exit;
    end;
    if not ParseReparseBuffer(Data, APath, Result) then
      Result.Kind := rkInspectionFailed;
  finally
    CloseHandle(Handle);
  end;
end;

function CreateJunction(const AJunctionPath, ATargetPath: string): Boolean;
var
  Handle: THandle;
  Buffer: TBytes;
  Data: PReparseDataBufferPriv;
  Sub, Print: string;
  SubBytes, PrintBytes, DataLen: Integer;
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
    // The layout Windows itself produces for junctions (verified against
    // mklink /J): no terminators inside the name lengths, the print name
    // starts one WCHAR after the substitute name ends, and the data length
    // covers the fields, both names, and two trailing pad bytes.
    Sub := '\??\' + TrimTrailingPathDelimiter(ATargetPath);
    Print := TrimTrailingPathDelimiter(ATargetPath);
    SubBytes := Length(Sub) * SizeOf(WCHAR);
    PrintBytes := Length(Print) * SizeOf(WCHAR);
    DataLen := SizeOf(USHORT) * 4 + SubBytes + SizeOf(WCHAR) + PrintBytes +
      SizeOf(WCHAR);
    SetLength(Buffer, ReparseHeaderSize + DataLen);
    FillChar(Buffer[0], Length(Buffer), 0);
    Data := PReparseDataBufferPriv(@Buffer[0]);
    Data.ReparseTag := IO_REPARSE_TAG_MOUNT_POINT;
    Data.ReparseDataLength := USHORT(DataLen);
    Data.SubstituteNameOffset := 0;
    Data.SubstituteNameLength := USHORT(SubBytes);
    Data.PrintNameOffset := USHORT(SubBytes + SizeOf(WCHAR));
    Data.PrintNameLength := USHORT(PrintBytes);
    Move(Sub[1], Data.PathBuffer[0], Length(Sub) * SizeOf(WCHAR));
    Move(Print[1], PByte(@Data.PathBuffer[0])[Data.PrintNameOffset],
      Length(Print) * SizeOf(WCHAR));

    Result := DeviceIoControl(Handle, FSCTL_SET_REPARSE_POINT, @Buffer[0],
      ReparseHeaderSize + DataLen, nil, 0, Returned, nil);
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
  Data: PReparseDataBufferPriv;
  Returned: DWORD;
begin
  Result := False;
  Handle := OpenReparsePoint(AJunctionPath);
  if Handle <> INVALID_HANDLE_VALUE then
  begin
    try
      FillChar(Buffer, SizeOf(Buffer), 0);
      Data := PReparseDataBufferPriv(@Buffer[0]);
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
