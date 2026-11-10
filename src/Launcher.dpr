program Launcher;

// Application, window and notification-area icons (artwork:
// portappix_icons\). The compiled resource is produced by brcc32 from
// src\PortappixIcons.rc; see scripts\build_launcher.cmd.
{$R PortappixIcons.res}
{$IFDEF PORTAPPIX_VERSION_RES}
{$R LauncherVersion.res}
{$ENDIF}

uses
  Vcl.Forms,
  Winapi.Windows,
  Portappix.Common,
  Portappix.Cli,
  Portappix.Icons,
{$IF defined(PORTAPPIX_TESTCRASH) or defined(PORTAPPIX_TESTUPDATE)}
  System.SysUtils,
{$IFEND}
{$IFDEF PORTAPPIX_TESTCRASH}
  Portappix.Transactions,
{$ENDIF}
  Portappix.Manifest,
  Portappix.Process,
  Portappix.Junction,
  Portappix.Registry,
  Portappix.Policy,
  Portappix.Signature,
  Portappix.Consent,
  Portappix.Runner,
  Portappix.State,
  Portappix.Catalog,
  Portappix.PackageManager,
  Portappix.Importer,
  Portappix.TrayUI,
  MainForm;

var
  SingleInstance: TPortappixSingleInstance;

{$IFDEF PORTAPPIX_TESTCRASH}
// Test-mode only: arms the crash-injection checkpoint from PORTAPPIX_CRASH_AT
// BEFORE any CLI/UI initialization, so the very first transaction boundary can
// crash the launcher deterministically. Production builds (no
// PORTAPPIX_TESTCRASH) compile none of this: they never read the variable,
// contain no crash-hook implementation, and the marker string below is absent
// from the released binary (verified by scripts/make_release.py and
// tests/scripts/test_crash_hook_isolation.py).
procedure ArmTestCrashPoint;
var
  Value: string;

  procedure Message(const AText: string);
  begin
    // A GUI-mode launcher has no console; never fail startup over logging.
    try
      Writeln(AText);
    except
    end;
    OutputDebugString(PChar(AText));
  end;

begin
  Value := GetEnvironmentVariable('PORTAPPIX_CRASH_AT');
  if Value = '' then
    Exit;
  if SetCrashPointFromString(Value) then
    Message('[testcrash] ' + PortappixTestCrashMarker +
      ': checkpoint "' + Value + '" armed; the launcher will terminate itself ' +
      'when that journal boundary is reached.')
  else
    Message('[testcrash] ' + PortappixTestCrashMarker +
      ': unknown checkpoint identifier "' + Value + '" ignored; no checkpoint ' +
      'armed.');
end;
{$ENDIF}

{$IFDEF PORTAPPIX_TESTUPDATE}
function HasRollbackArg: Boolean;
var
  I: Integer;
begin
  for I := 1 to ParamCount do
    if SameText(ParamStr(I), '--rollback') then
      Exit(True);
  Result := False;
end;
{$ENDIF}

begin
{$IFDEF PORTAPPIX_TESTUPDATE}
  {$IFDEF PORTAPPIX_CRASH_STARTUP}
  if not HasRollbackArg then
    Halt(42);
  {$ENDIF}
  if (GetEnvironmentVariable('PORTAPPIX_TEST_CRASH_ON_START') = '1') and not HasRollbackArg then
    Halt(42);
{$ENDIF}
{$IFDEF PORTAPPIX_TESTCRASH}
  ArmTestCrashPoint;
{$ENDIF}
  // Headless mode (--run / --check-manifest / --recover) never creates forms
  // and never touches the single-instance launcher mutex, so the compatibility
  // suite can drive one app while another is already running.
  if HasCliArguments then
    Halt(ExecuteCli);

  SingleInstance := TPortappixSingleInstance.Create('');
  if not SingleInstance.IsOwner then
  begin
    MessageBox(0, 'Portappix is already running.', 'Portappix',
      MB_OK or MB_ICONINFORMATION);
    SingleInstance.Free;
    Halt(0);
  end;

  try
    Application.Initialize;
    // The application icon (taskbar, main window, Alt-Tab). Applied before
    // the form is created so the very first window already shows it.
    TPortappixIcons.ApplyApplicationIcon;
    Application.MainFormOnTaskbar := True;
    Application.ShowMainForm := False;
    Application.CreateForm(TMainLauncherForm, MainLauncherForm);
    Application.Run;
  finally
    SingleInstance.Free;
  end;
end.
