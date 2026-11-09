program RegistryWriter;

// Fake app for the Portappix compatibility suite.
// Writes a string, a dword, a binary value and nested subkeys under
// HKCU\Software\PortappixTest\RegistryWriter, reading back the values of the
// previous run first. The previous values are printed to result.txt in the
// executable's own folder so the suite can verify that a second run under the
// launcher sees the first run's redirected registry state.

{$APPTYPE CONSOLE}

uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes,
  System.Win.Registry;

var
  ResultLines: TStringList;

procedure Note(const ALine: string);
begin
  ResultLines.Add(ALine);
end;

function BlobToHex(const ABlob: TBytes): string;
const
  HexDigits: array[0..15] of Char = '0123456789abcdef';
begin
  Result := '';
  for var Index := 0 to High(ABlob) do
  begin
    Result := Result + HexDigits[ABlob[Index] shr 4];
    Result := Result + HexDigits[ABlob[Index] and $0F];
  end;
end;

procedure ReadPreviousValues;
var
  Registry: TRegistry;
  Blob: TBytes;
begin
  Registry := TRegistry.Create(KEY_READ);
  try
    Registry.RootKey := HKEY_CURRENT_USER;
    if not Registry.KeyExists('Software\PortappixTest\RegistryWriter') then
    begin
      Note('previous=none');
      Exit;
    end;
    if not Registry.OpenKey('Software\PortappixTest\RegistryWriter', False) then
    begin
      Note('previous=unreadable');
      Exit;
    end;

    try
      if Registry.ValueExists('Greeting') then
        Note('previous Greeting=' + Registry.ReadString('Greeting'))
      else
        Note('previous Greeting=(missing)');

      if Registry.ValueExists('Counter') then
        Note('previous Counter=' + IntToStr(Registry.ReadInteger('Counter')))
      else
        Note('previous Counter=(missing)');

      if Registry.ValueExists('Blob') then
      begin
        SetLength(Blob, 4);
        Registry.ReadBinaryData('Blob', Blob[0], Length(Blob));
        Note('previous Blob=' + BlobToHex(Blob));
      end
      else
        Note('previous Blob=(missing)');
    finally
      Registry.CloseKey;
    end;

    if Registry.OpenKey('Software\PortappixTest\RegistryWriter\Nested\Deep', False) then
    begin
      try
        if Registry.ValueExists('Marker') then
          Note('previous Nested\Deep\Marker=' + Registry.ReadString('Marker'))
        else
          Note('previous Nested\Deep\Marker=(missing)');
      finally
        Registry.CloseKey;
      end;
    end
    else
      Note('previous Nested\Deep\Marker=(missing subkey)');
  finally
    Registry.Free;
  end;
end;

procedure WriteCurrentValues;
var
  Registry: TRegistry;
  Stamp: string;
  Counter: Integer;
  Blob: TBytes;
begin
  Stamp := FormatDateTime('yyyymmddhhnnsszzz', Now);

  Registry := TRegistry.Create(KEY_READ or KEY_WRITE);
  try
    Registry.RootKey := HKEY_CURRENT_USER;
    if not Registry.OpenKey('Software\PortappixTest\RegistryWriter', True) then
      raise Exception.Create('Cannot open the RegistryWriter key for writing');

    try
      if Registry.ValueExists('Counter') then
        Counter := Registry.ReadInteger('Counter') + 1
      else
        Counter := 1;
      Registry.WriteInteger('Counter', Counter);

      Registry.WriteString('Greeting', 'Hello' + Stamp);

      SetLength(Blob, 4);
      Blob[0] := 1; Blob[1] := 2; Blob[2] := 3; Blob[3] := 4;
      Registry.WriteBinaryData('Blob', Blob[0], Length(Blob));

      Note('wrote Greeting=Hello' + Stamp);
      Note('wrote Counter=' + IntToStr(Counter));
      Note('wrote Blob=' + BlobToHex(Blob));
    finally
      Registry.CloseKey;
    end;

    if not Registry.OpenKey('Software\PortappixTest\RegistryWriter\Nested\Deep', True) then
      raise Exception.Create('Cannot open the nested RegistryWriter subkey for writing');
    try
      Registry.WriteString('Marker', 'M' + Stamp);
      Note('wrote Nested\Deep\Marker=M' + Stamp);
    finally
      Registry.CloseKey;
    end;
  finally
    Registry.Free;
  end;
end;

begin
  ResultLines := TStringList.Create;
  try
    try
      ReadPreviousValues;
      WriteCurrentValues;
      ResultLines.SaveToFile(ChangeFileExt(ParamStr(0), '.txt'), TEncoding.UTF8);
      ExitCode := 0;
    except
      on E: Exception do
      begin
        ResultLines.Insert(0, 'ERROR: ' + E.Message);
        try
          ResultLines.SaveToFile(ChangeFileExt(ParamStr(0), '.txt'), TEncoding.UTF8);
        except
        end;
        ExitCode := 1;
      end;
    end;
  finally
    ResultLines.Free;
  end;
end.
