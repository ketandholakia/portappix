program Launcher;

uses
  Vcl.Forms,
  MainForm in 'MainForm.pas' {MainLauncherForm},
  Portappix.Manifest in 'Portappix.Manifest.pas',
  Portappix.Runner in 'Portappix.Runner.pas',
  Portappix.State in 'Portappix.State.pas',
  Portappix.Catalog in 'Portappix.Catalog.pas',
  Portappix.PackageManager in 'Portappix.PackageManager.pas',
  Portappix.TrayUI in 'Portappix.TrayUI.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.ShowMainForm := False;
  Application.CreateForm(TMainLauncherForm, MainLauncherForm);
  Application.Run;
end.
