program AppDataWriter;

// Fake app for the Portappix compatibility suite.
// Writes marker files into the normal per-user folder locations. When run
// under the Portappix launcher with a manifest that overrides APPDATA /
// LOCALAPPDATA / TEMP / TMP, those files must land inside Data\<id>.

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  System.IOUtils;

procedure WriteMarker(const AFileName, AContent: string);
begin
  ForceDirectories(TPath.GetDirectoryName(AFileName));
  TFile.WriteAllText(AFileName, AContent, TEncoding.UTF8);
end;

begin
  try
    var Tick := FormatDateTime('yyyymmddhhnnsszzz', Now);

    WriteMarker(TPath.Combine(GetEnvironmentVariable('APPDATA'),
      'FakeApps\AppDataWriter\settings.ini'),
      '[AppDataWriter]' + sLineBreak + 'writtenAt=' + Tick + sLineBreak);

    WriteMarker(TPath.Combine(GetEnvironmentVariable('LOCALAPPDATA'),
      'FakeApps\AppDataWriter\local.ini'),
      '[AppDataWriter]' + sLineBreak + 'writtenAt=' + Tick + sLineBreak);

    WriteMarker(TPath.Combine(GetEnvironmentVariable('TEMP'),
      'fakeapps_appdatawriter.tmp'),
      'scratch written at ' + Tick + sLineBreak);

    ExitCode := 0;
  except
    on E: Exception do
    begin
      ExitCode := 1;
    end;
  end;
end.
