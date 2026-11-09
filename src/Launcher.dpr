program Launcher;

uses
  Winapi.Windows,
  Vcl.Forms,
  Portappix.Common in 'Portappix.Common.pas',
  MainForm in 'MainForm.pas' {MainLauncherForm},
  Portappix.Manifest in 'Portappix.Manifest.pas',
  Portappix.Process in 'Portappix.Process.pas',
  Portappix.Junction in 'Portappix.Junction.pas',
  Portappix.Registry in 'Portappix.Registry.pas',
  Portappix.Policy in 'Portappix.Policy.pas',
  Portappix.Signature in 'Portappix.Signature.pas',
  Portappix.Consent in 'Portappix.Consent.pas',
  Portappix.Runner in 'Portappix.Runner.pas',
  Portappix.State in 'Portappix.State.pas',
  Portappix.Catalog in 'Portappix.Catalog.pas',
  Portappix.PackageManager in 'Portappix.PackageManager.pas',
  Portappix.TrayUI in 'Portappix.TrayUI.pas',
  Portappix.Importer in 'Portappix.Importer.pas';

var
  SingleInstance: TPortappixSingleInstance;

begin
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
