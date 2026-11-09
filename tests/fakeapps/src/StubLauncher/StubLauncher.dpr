program StubLauncher;

// Fake app for the Portappix compatibility suite.
// Parent mode: starts a second copy of itself with --child and exits
// immediately. Child mode: sleeps (default 5 s), writes a marker file under
// %LOCALAPPDATA%\FakeApps\StubLauncher and exits. A launcher that only waits
// for the main process would return before the marker exists; Portappix must
// wait for the whole job-object process tree.

{$APPTYPE CONSOLE}

uses
  Winapi.Windows,
  Winapi.ShellAPI,
  System.SysUtils,
  System.IOUtils;

const
  DefaultChildDelayMs = 5000;

function ChildDelayMs: Cardinal;
var
  Raw: string;
  Value: Integer;
begin
  Raw := GetEnvironmentVariable('PORTAPPIX_FAKE_CHILD_MS');
  if (Raw <> '') and TryStrToInt(Raw, Value) and (Value >= 0) then
    Result := Cardinal(Value)
  else
    Result := DefaultChildDelayMs;
end;

procedure RunChild;
begin
  Sleep(ChildDelayMs);
  var Marker := TPath.Combine(GetEnvironmentVariable('LOCALAPPDATA'),
    'FakeApps\StubLauncher\child_done.txt');
  ForceDirectories(TPath.GetDirectoryName(Marker));
  TFile.WriteAllText(Marker,
    'child finished at ' + FormatDateTime('yyyy-mm-dd hh:nn:ss.zzz', Now) + sLineBreak,
    TEncoding.UTF8);
end;

procedure StartChildAndExit;
var
  StartupInfo: TStartupInfo;
  ProcessInfo: TProcessInformation;
  CommandLine: string;
  Created: Boolean;
begin
  FillChar(StartupInfo, SizeOf(StartupInfo), 0);
  StartupInfo.cb := SizeOf(StartupInfo);

  CommandLine := '"' + ParamStr(0) + '" --child';
  UniqueString(CommandLine);

  Created := CreateProcess(nil, PChar(CommandLine), nil, nil, False, 0, nil, nil,
    StartupInfo, ProcessInfo);
  if not Created then
  begin
    ExitCode := 1;
    Exit;
  end;

  // Deliberately do NOT wait: the launcher must do the waiting.
  CloseHandle(ProcessInfo.hThread);
  CloseHandle(ProcessInfo.hProcess);
  ExitCode := 0;
end;

begin
  if (ParamCount > 0) and SameText(ParamStr(1), '--child') then
  begin
    RunChild;
    ExitCode := 0;
  end
  else
    StartChildAndExit;
end.
