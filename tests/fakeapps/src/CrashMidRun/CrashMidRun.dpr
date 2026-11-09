program CrashMidRun;

// Fake app for the Portappix compatibility suite.
// Writes registry/AppData/junction state that the Portappix launcher hijacks,
// signals "started" to its own folder, then either kills its parent (the
// launcher) with TerminateProcess or simply sleeps so the test harness can
// kill the launcher. Either path exercises crash recovery on the next start.

{$APPTYPE CONSOLE}

uses
  Winapi.Windows,
  Winapi.TlHelp32,
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  System.Win.Registry;

procedure WriteMarker(const AFileName, AContent: string);
begin
  ForceDirectories(TPath.GetDirectoryName(AFileName));
  TFile.WriteAllText(AFileName, AContent, TEncoding.UTF8);
end;

procedure WriteState;
var
  Registry: TRegistry;
  Stamp: string;
  Blob: TBytes;
begin
  Stamp := FormatDateTime('yyyymmddhhnnsszzz', Now);

  // AppData (redirected through env overrides).
  WriteMarker(TPath.Combine(GetEnvironmentVariable('APPDATA'),
    'FakeApps\CrashMidRun\state.ini'),
    '[CrashMidRun]' + sLineBreak + 'writtenAt=' + Stamp + sLineBreak);

  // LocalAppData (redirected through a junction onto %LOCALAPPDATA%).
  WriteMarker(TPath.Combine(GetEnvironmentVariable('LOCALAPPDATA'),
    'FakeApps\CrashMidRun\crash.txt'),
    'crash state written at ' + Stamp + sLineBreak);

  // Registry (hijacked by the launcher).
  Registry := TRegistry.Create(KEY_READ or KEY_WRITE);
  try
    Registry.RootKey := HKEY_CURRENT_USER;
    if not Registry.OpenKey('Software\PortappixTest\CrashMidRun', True) then
      raise Exception.Create('Cannot open the CrashMidRun registry key');
    try
      Registry.WriteString('Stamp', Stamp);
      Registry.WriteInteger('Crash', 1);
      SetLength(Blob, 2);
      Blob[0] := $CA; Blob[1] := $FE;
      Registry.WriteBinaryData('CrashBlob', Blob[0], Length(Blob));
    finally
      Registry.CloseKey;
    end;
  finally
    Registry.Free;
  end;
end;

function ParentProcessId: DWORD;
var
  Snapshot: THandle;
  Entry: TProcessEntry32;
begin
  Result := 0;
  Snapshot := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if Snapshot = INVALID_HANDLE_VALUE then
    Exit;
  try
    FillChar(Entry, SizeOf(Entry), 0);
    Entry.dwSize := SizeOf(Entry);
    if Process32First(Snapshot, Entry) then
      while True do
      begin
        if Entry.th32ProcessID = GetCurrentProcessId then
        begin
          Result := Entry.th32ParentProcessID;
          Break;
        end;
        if not Process32Next(Snapshot, Entry) then
          Break;
      end;
  finally
    CloseHandle(Snapshot);
  end;
end;

procedure KillParent;
var
  ParentId: DWORD;
  ParentHandle: THandle;
begin
  ParentId := ParentProcessId;
  if ParentId = 0 then
    Exit;
  ParentHandle := OpenProcess(PROCESS_TERMINATE, False, ParentId);
  if ParentHandle = 0 then
    Exit;
  try
    TerminateProcess(ParentHandle, 1);
  finally
    CloseHandle(ParentHandle);
  end;
end;

function HoldMs: Cardinal;
var
  Raw: string;
  Value: Integer;
begin
  Raw := GetEnvironmentVariable('PORTAPPIX_FAKE_HOLD_MS');
  if (Raw <> '') and TryStrToInt(Raw, Value) and (Value >= 0) then
    Result := Cardinal(Value)
  else
    Result := 30000;
end;

begin
  try
    WriteState;
    WriteMarker(ChangeFileExt(ParamStr(0), '.started.txt'),
      'state written at ' + FormatDateTime('yyyy-mm-dd hh:nn:ss.zzz', Now) + sLineBreak);

    if (ParamCount > 0) and SameText(ParamStr(1), '--kill-parent') then
      KillParent
    else
      Sleep(HoldMs); // Let the harness kill the launcher mid-run.

    WriteMarker(ChangeFileExt(ParamStr(0), '.done.txt'), 'done' + sLineBreak);
    ExitCode := 0;
  except
    on E: Exception do
      ExitCode := 1;
  end;
end.
