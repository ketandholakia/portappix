program ProgramDataWriter;

// Fake app for the Portappix compatibility suite.
// Writes C:\ProgramData\PortappixTest\x.dat. Under the Portappix launcher the
// manifest maps %PROGRAMDATA%\PortappixTest onto Data\<id>\ProgramData with an
// NTFS junction, so the file must land there and must NOT stay on the host.

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  System.IOUtils;

const
  TargetPath = 'C:\ProgramData\PortappixTest\x.dat';

begin
  try
    ForceDirectories(TPath.GetDirectoryName(TargetPath));
    TFile.WriteAllText(TargetPath,
      'portappix programdata test payload ' +
      FormatDateTime('yyyymmddhhnnsszzz', Now) + sLineBreak, TEncoding.UTF8);

    // Read it back so the run fails loudly when the file is not readable.
    if TFile.ReadAllText(TargetPath, TEncoding.UTF8) = '' then
      raise Exception.Create('Read back an empty file');

    ExitCode := 0;
  except
    on E: Exception do
      ExitCode := 1;
  end;
end.
