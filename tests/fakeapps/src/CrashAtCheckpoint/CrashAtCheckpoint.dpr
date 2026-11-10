program CrashAtCheckpoint;

// Fake app for the Portappix compatibility suite (Phase 2 integration).
// Exercises launcher crashes at exact transaction boundaries: the launcher
// is started with PORTAPPIX_CRASH_AT=<checkpoint> (test-only, see
// Portappix.Transactions.CheckCrashPoint); this app simply writes marker
// files so the harness can prove what the app observed before the launcher
// died, then kills its parent (the launcher) to simulate an app that
// outlives a crashed host process.
//
// Markers (next to the executable):
//   crashcheckpoint.started.txt   the app started
//   crashcheckpoint.state.txt     the registry/env state the app saw
//
// Usage in a VM/Sandbox harness:
//   Launcher.exe --run crashatcheckpoint --accept-policy --root <root>
// with PORTAPPIX_CRASH_AT set to a transaction checkpoint, e.g.:
//   state:hostBackupComplete | op:0:pending | op:2:done | ...

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

procedure WriteState;
var
  Registry: TRegistry;
  Stamp: string;
begin
  Stamp := FormatDateTime('yyyymmddhhnnsszzz', Now);

  WriteMarker(TPath.Combine(GetEnvironmentVariable('APPDATA'),
    'FakeApps\CrashAtCheckpoint\state.ini'),
    '[CrashAtCheckpoint]' + sLineBreak + 'writtenAt=' + Stamp + sLineBreak);

  Registry := TRegistry.Create(KEY_READ or KEY_WRITE);
  try
    Registry.RootKey := HKEY_CURRENT_USER;
    if not Registry.OpenKey('Software\PortappixTest\CrashAtCheckpoint', True) then
      raise Exception.Create('Cannot open the CrashAtCheckpoint registry key');
    try
      Registry.WriteString('Stamp', Stamp);
    finally
      Registry.CloseKey;
    end;
  finally
    Registry.Free;
  end;
end;

begin
  try
    WriteMarker(ChangeFileExt(ParamStr(0), '.started.txt'),
      'started at ' + FormatDateTime('yyyy-mm-dd hh:nn:ss.zzz', Now) + sLineBreak);
    WriteState;
    WriteMarker(ChangeFileExt(ParamStr(0), '.state.txt'),
      'state written at ' + FormatDateTime('yyyy-mm-dd hh:nn:ss.zzz', Now) + sLineBreak);

    // Give the harness a deterministic window, then take the launcher down
    // with the app still running (mirrors a real host crash under load).
    Sleep(2000);
    KillParent;

    WriteMarker(ChangeFileExt(ParamStr(0), '.done.txt'), 'done' + sLineBreak);
    ExitCode := 0;
  except
    on E: Exception do
      ExitCode := 1;
  end;
end.
