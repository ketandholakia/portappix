program SingleInstance;

// Fake app for the Portappix compatibility suite.
// Refuses to start a second copy while the first is holding a named mutex.
// Used to check the launcher's "already running" path: while the first copy
// holds the app's per-app mutex, a second `--run` must be refused cleanly.

{$APPTYPE CONSOLE}

uses
  Winapi.Windows,
  System.SysUtils,
  System.IOUtils;

const
  TestMutexName = 'Local\PortappixTest.SingleInstance';
  AlreadyRunningExitCode = 3;

procedure WriteMarker(const AName, AContent: string);
begin
  var Path := ChangeFileExt(ParamStr(0), '.' + AName);
  TFile.WriteAllText(Path, AContent + sLineBreak, TEncoding.UTF8);
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
    Result := 10000;
end;

var
  MutexHandle: THandle;

begin
  MutexHandle := CreateMutex(nil, True, TestMutexName);
  if (MutexHandle = 0) or (GetLastError = ERROR_ALREADY_EXISTS) then
  begin
    if MutexHandle <> 0 then
      CloseHandle(MutexHandle);
    WriteMarker('result.txt', 'already running');
    ExitCode := AlreadyRunningExitCode;
    Exit;
  end;

  try
    WriteMarker('started.txt',
      'started at ' + FormatDateTime('yyyy-mm-dd hh:nn:ss.zzz', Now));
    Sleep(HoldMs);
    WriteMarker('done.txt', 'done');
    ExitCode := 0;
  finally
    ReleaseMutex(MutexHandle);
    CloseHandle(MutexHandle);
  end;
end.
