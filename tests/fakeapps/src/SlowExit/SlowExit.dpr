program SlowExit;

// Fake app for the Portappix compatibility suite.
// Installs a console control handler that swallows close/logoff requests and
// then ignores everything for 8 seconds before exiting on its own. The suite
// uses it to prove the launcher waits patiently for slow exits instead of
// abandoning the process tree.

{$APPTYPE CONSOLE}

uses
  Winapi.Windows,
  System.SysUtils,
  System.IOUtils;

const
  IgnoreWindowMs = 8000;

function CtrlHandler(CtrlType: DWORD): BOOL; stdcall;
begin
  // Swallow every close/logoff request: the app must be left alone for the
  // ignore window and then exit by itself.
  Result := TRUE;
end;

begin
  SetConsoleCtrlHandler(@CtrlHandler, TRUE);

  var StartedAt := GetTickCount64;
  while GetTickCount64 - StartedAt < IgnoreWindowMs do
    Sleep(100);

  try
    TFile.WriteAllText(ChangeFileExt(ParamStr(0), '.done.txt'),
      'slow exit finished after ' + IntToStr(IgnoreWindowMs) + ' ms' + sLineBreak,
      TEncoding.UTF8);
  except
    on E: Exception do
      ExitCode := 1;
  end;
  ExitCode := 0;
end.
