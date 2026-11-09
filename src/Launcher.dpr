program Launcher;

uses
  Vcl.Forms,
  Winapi.Windows,
  Portappix.Common,
  Portappix.Cli,
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

begin
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
    Application.MainFormOnTaskbar := True;
    Application.ShowMainForm := False;
    Application.CreateForm(TMainLauncherForm, MainLauncherForm);
    Application.Run;
  finally
    SingleInstance.Free;
  end;
end.
