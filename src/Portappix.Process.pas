unit Portappix.Process;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes;

type
  TJobObjectAccounting = record
    TotalUserTime: Int64;
    TotalKernelTime: Int64;
    ThisPeriodTotalUserTime: Int64;
    ThisPeriodTotalKernelTime: Int64;
    TotalPageFaultCount: DWORD;
    TotalProcesses: DWORD;
    ActiveProcesses: DWORD;
    TotalTerminatedProcesses: DWORD;
  end;

  TPortappixJob = class
  private
    FHandle: THandle;
  public
    constructor Create;
    destructor Destroy; override;
    function IsValid: Boolean;
    function AssignProcess(const AProcessHandle: THandle): Boolean;
    function ActiveProcessCount(out ACount: DWORD): Boolean;
    function WaitForEmpty(const ATimeoutMs: Cardinal = INFINITE;
      const APollMs: Cardinal = 100): Boolean;
    property Handle: THandle read FHandle;
  end;

function QuoteArgument(const AValue: string): string;
function RunHiddenProcess(const ACommandLine: string; out AExitCode: Cardinal;
  const ACurrentDirectory: string = ''): Boolean;

implementation

const
  JobObjectBasicAccountingInfoClass = 1;

function QuoteArgument(const AValue: string): string;
begin
  Result := '"' + StringReplace(AValue, '"', '\"', [rfReplaceAll]) + '"';
end;

function RunHiddenProcess(const ACommandLine: string; out AExitCode: Cardinal;
  const ACurrentDirectory: string): Boolean;
var
  StartupInfo: TStartupInfo;
  ProcessInfo: TProcessInformation;
  CommandLine: string;
  ProcessExitCode: DWORD;
  CurrentDirectoryPointer: PChar;
begin
  AExitCode := Cardinal(-1);
  CurrentDirectoryPointer := nil;
  if ACurrentDirectory <> '' then
    CurrentDirectoryPointer := PChar(ACurrentDirectory);

  FillChar(StartupInfo, SizeOf(StartupInfo), 0);
  StartupInfo.cb := SizeOf(StartupInfo);
  StartupInfo.dwFlags := STARTF_USESHOWWINDOW;
  StartupInfo.wShowWindow := SW_HIDE;

  CommandLine := ACommandLine;
  UniqueString(CommandLine);

  Result := CreateProcess(nil, PChar(CommandLine), nil, nil, False,
    CREATE_NO_WINDOW or CREATE_UNICODE_ENVIRONMENT, nil, CurrentDirectoryPointer,
    StartupInfo, ProcessInfo);
  if not Result then
    Exit;

  try
    if WaitForSingleObject(ProcessInfo.hProcess, INFINITE) <> WAIT_OBJECT_0 then
    begin
      Result := False;
      Exit;
    end;

    if GetExitCodeProcess(ProcessInfo.hProcess, ProcessExitCode) then
      AExitCode := ProcessExitCode
    else
      Result := False;
  finally
    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
  end;
end;

constructor TPortappixJob.Create;
begin
  inherited Create;
  FHandle := CreateJobObject(nil, nil);
end;

destructor TPortappixJob.Destroy;
begin
  if FHandle <> 0 then
    CloseHandle(FHandle);
  inherited;
end;

function TPortappixJob.IsValid: Boolean;
begin
  Result := FHandle <> 0;
end;

function TPortappixJob.AssignProcess(const AProcessHandle: THandle): Boolean;
begin
  Result := IsValid and AssignProcessToJobObject(FHandle, AProcessHandle);
end;

function TPortappixJob.ActiveProcessCount(out ACount: DWORD): Boolean;
var
  Information: TJobObjectAccounting;
begin
  ACount := 0;
  Result := IsValid and QueryInformationJobObject(FHandle,
    JobObjectBasicAccountingInfoClass, @Information, SizeOf(Information), nil);
  if Result then
    ACount := Information.ActiveProcesses;
end;

function TPortappixJob.WaitForEmpty(const ATimeoutMs, APollMs: Cardinal): Boolean;
var
  StartedAt: UInt64;
  Active: DWORD;
begin
  StartedAt := GetTickCount64;
  repeat
    if not ActiveProcessCount(Active) then
      Exit(False);
    if Active = 0 then
      Exit(True);
    if (ATimeoutMs <> INFINITE) and (GetTickCount64 - StartedAt >= ATimeoutMs) then
      Exit(False);
    Sleep(APollMs);
  until False;
end;

end.
