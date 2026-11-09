program ElevationRequired;

// Fake app for the Portappix compatibility suite.
// Embeds an application manifest with requestedExecutionLevel=requireAdministrator.
// When CreateProcess is called without an elevated caller, Portappix must
// report ERROR_ELEVATION_REQUIRED (740) cleanly and leave no host state behind.
// On fully elevated hosts (e.g. some Windows Sandbox sessions) the app simply
// runs and writes its marker.

{$APPTYPE CONSOLE}

{$R ElevationRequired.res}

uses
  System.SysUtils,
  System.IOUtils;

begin
  try
    var Marker := TPath.Combine(GetEnvironmentVariable('TEMP'),
      'fakeapps_elevationrequired.tmp');
    TFile.WriteAllText(Marker,
      'elevation-required app ran at ' +
      FormatDateTime('yyyy-mm-dd hh:nn:ss.zzz', Now) + sLineBreak, TEncoding.UTF8);
    ExitCode := 0;
  except
    on E: Exception do
      ExitCode := 1;
  end;
end.
