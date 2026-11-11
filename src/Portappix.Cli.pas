unit Portappix.Cli;

{
  Headless command-line mode for the launcher. Used by the compatibility suite
  (tests\suite) and by scripts; it never shows UI and never creates forms.

  Switches:
    --run <app-id|path-to-app.json>   Run an installed app and wait for its
                                      whole process tree (always; --wait is
                                      accepted for readability).
    --trace <app-id|path-to-exe>      Run an app WITHOUT virtualization and
                                      write a "what did it touch" report
                                      (Trace\<id>_<timestamp>\). Use in a VM.
    --check-manifest <path>           Validate app.json against Portappix.Policy
                                      without running anything.
    --recover                         Run the crash journal's pending cleanups.
    --apply-updates                   Apply updates queued while apps ran.
    --check-updates <url>             Download and verify releases.json; report
                                      whether an update is available.
    --self-update <url>               Download, verify and apply the launcher
                                      update from releases.json, then restart.
    --post-update                     First start after a self-update: confirms
                                      the update and records the new version.
    --allow-insecure-release-urls     Test-only: allow http:// release URLs
                                      (signatures stay mandatory).
    --root <path>                     Launcher root (defaults to the exe folder).
    --exit-code-file <path>           Write a JSON result record to this path.
    --log-file <path>                 Append a timestamped run log.
    --wait                            Accepted; --run always waits for the tree.
    --accept-policy                   Test-only: record first-run consent without
                                      a prompt. Never use on a real desktop.

  Process exit codes:
    0     success (for --run this is the app's own exit code)
    2     manifest could not be loaded / policy rejection
    3     usage error
    4     app already running (per-app mutex held)
    5     first-run consent was required but --accept-policy was not passed
    7     other runtime failure
    740   ERROR_ELEVATION_REQUIRED reported by the runner
}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  System.JSON,
  Portappix.Common;

const
  CliExitOk = 0;
  CliExitRejected = 2;
  CliExitUsage = 3;
  CliExitAlreadyRunning = 4;
  CliExitConsentRequired = 5;
  CliExitNeedsReview = 6;
  CliExitGenericFailure = 7;
  CliExitElevationRequired = 740;

  CliUsageText =
    'Usage: Launcher.exe --run <app-id|app.json> [--wait] [--accept-policy]' + sLineBreak +
    '                    [--root <path>] [--exit-code-file <path>] [--log-file <path>]' + sLineBreak +
    '       Launcher.exe --trace <app-id|app.exe> [--accept-policy] [--root <path>]' + sLineBreak +
    '                    [--exit-code-file <path>] [--log-file <path>]' + sLineBreak +
    '       Launcher.exe --check-manifest <app.json> [--exit-code-file <path>]' + sLineBreak +
    '       Launcher.exe --recover [--root <path>] [--log-file <path>]' + sLineBreak +
    '       Launcher.exe --status [--root <path>] [--exit-code-file <path>]' + sLineBreak +
    '       Launcher.exe --clear-review <app-id> [--delete-unowned-junction] [--force] [--root <path>]' + sLineBreak +
    '       Launcher.exe --accept-rollback [--root <path>]' + sLineBreak +
    '       Launcher.exe --apply-updates [--root <path>]' + sLineBreak +
    '       Launcher.exe --check-updates <releases.json-url> [--root <path>]' + sLineBreak +
    '       Launcher.exe --self-update <releases.json-url> [--root <path>]' + sLineBreak +
    sLineBreak +
    'Headless mode never shows UI. --accept-policy records first-run consent' + sLineBreak +
    'without a prompt and must only be used in test environments (VM/Sandbox).' + sLineBreak +
    'Trace mode (--trace) runs the app WITHOUT virtualization to record what it' + sLineBreak +
    'writes on the host; only trace apps you trust, ideally in a VM/Sandbox.';

type
  EPortappixCliError = class(Exception);

  TPortappixCli = class
  private
    FRootPath: string;
    FCommand: string;
    FArgument: string;
    FExitCodeFile: string;
    FLogFilePath: string;
    FAcceptPolicy: Boolean;
    FWait: Boolean;
    FDeleteUnownedJunction: Boolean;
    FForce: Boolean;
    procedure Log(const AMessage: string);
    procedure WriteExitCodeFile(const AExitCode: Integer; const AAppId,
      AMessage: string; const AAlreadyRunning: Boolean = False);
    function ResolveManifestPath(const AReference: string; out AAppId: string): string;
    function ResolveTraceReference(const AReference: string; out AAppId: string): string;
    function ResolveUpdateUrl: string;
    procedure WarnIfUpdateUnconfirmed;
    function ExecuteRun: Integer;
    function ExecuteTrace: Integer;
    function ExecuteCheckManifest: Integer;
    function ExecuteRecover: Integer;
    function ExecuteStatus: Integer;
    function ExecuteClearReview: Integer;
    function ExecuteApplyUpdates: Integer;
    function ExecuteCheckUpdates: Integer;
    function ExecuteSelfUpdate: Integer;
    function ExecutePostUpdate: Integer;
    function ExecuteRollback: Integer;
  public
    constructor Create;
    function Parse(const AArgs: TArray<string>): Boolean;
    function Execute: Integer;
    property Command: string read FCommand;
    property Argument: string read FArgument;
  end;

function HasCliArguments: Boolean;
function ExecuteCli: Integer;

implementation

uses
  Portappix.Manifest,
  Portappix.Policy,
  Portappix.PackageManager,
  Portappix.Runner,
  Portappix.Trace,
  Portappix.State,
  Portappix.Settings,
  Portappix.Update,
  Portappix.Consent;

var
  ConsoleAttached: Boolean = False;

procedure EnsureConsoleAttached;
begin
  if ConsoleAttached then
    Exit;
  ConsoleAttached := True;

  // Rebind the RTL Output file to the parent console when one exists, so
  // diagnostics reach a shell that started the launcher. Headless runs without
  // a console are unaffected; results are written to files instead.
  try
    if AttachConsole(ATTACH_PARENT_PROCESS) then
    begin
      try
        AssignFile(Output, 'CONOUT$');
        Rewrite(Output);
      except
        // No console attached; ignore.
      end;
    end;
  except
    // Ignore.
  end;
end;

procedure CliWrite(const AMessage: string);
begin
  EnsureConsoleAttached;
  try
    Writeln(AMessage);
  except
    // No console attached; ignore output errors.
  end;
end;

constructor TPortappixCli.Create;
begin
  inherited Create;
  FRootPath := ResolveRootPath('');
  FCommand := '';
  FArgument := '';
  FDeleteUnownedJunction := False;
  FForce := False;
end;

procedure TPortappixCli.Log(const AMessage: string);
var
  Line: string;
begin
  Line := Format('%s %s', [FormatDateTime('yyyy-mm-dd hh:nn:ss.zzz', Now), AMessage]);
  CliWrite(Line);
  if FLogFilePath <> '' then
    try
      ForceDirectories(TPath.GetDirectoryName(TPath.GetFullPath(FLogFilePath)));
      TFile.AppendAllText(FLogFilePath, Line + sLineBreak, TEncoding.UTF8);
    except
      // Never fail a run because logging failed.
    end;
end;

procedure TPortappixCli.WriteExitCodeFile(const AExitCode: Integer; const AAppId,
  AMessage: string; const AAlreadyRunning: Boolean);
var
  Record_: TJSONObject;
begin
  if FExitCodeFile = '' then
    Exit;

  Record_ := TJSONObject.Create;
  try
    Record_.AddPair('command', FCommand);
    if AAppId <> '' then
      Record_.AddPair('app', AAppId);
    Record_.AddPair('exitCode', TJSONNumber.Create(AExitCode));
    Record_.AddPair('alreadyRunning', TJSONBool.Create(AAlreadyRunning));
    Record_.AddPair('message', AMessage);
    try
      ForceDirectories(TPath.GetDirectoryName(TPath.GetFullPath(FExitCodeFile)));
      WriteTextFileAtomic(FExitCodeFile, Record_.Format(2));
    except
      on E: Exception do
        Log(Format('Unable to write the exit-code file "%s": %s', [FExitCodeFile, E.Message]));
    end;
  finally
    Record_.Free;
  end;
end;

function TPortappixCli.Parse(const AArgs: TArray<string>): Boolean;
var
  Index: Integer;
  Arg: string;

  function TakeValue(const AName: string; out AValue: string): Boolean;
  begin
    // Consumes the value after AName; the caller increments the index itself.
    if Index + 1 >= Length(AArgs) then
    begin
      Log(Format('Missing value for %s.', [AName]));
      Exit(False);
    end;
    AValue := AArgs[Index + 1];
    Result := True;
  end;

begin
  Result := False;
  FCommand := '';
  FArgument := '';

  Index := 0;
  while Index < Length(AArgs) do
  begin
    Arg := AArgs[Index];

    if SameText(Arg, '--accept-policy') then
      FAcceptPolicy := True
{$IFDEF PORTAPPIX_TESTUPDATE}
    else if SameText(Arg, '--allow-insecure-release-urls') then
      AllowInsecureReleaseUrls := True
{$ENDIF}
    else if SameText(Arg, '--wait') then
      FWait := True
    else if SameText(Arg, '--recover') then
      FCommand := 'recover'
    else if SameText(Arg, '--apply-updates') then
      FCommand := 'apply-updates'
    else if SameText(Arg, '--post-update') then
      FCommand := 'post-update'
    else if SameText(Arg, '--rollback') or SameText(Arg, '--accept-rollback') then
      FCommand := 'rollback'
    else if SameText(Arg, '--status') then
      FCommand := 'status'
    else if SameText(Arg, '--delete-unowned-junction') then
      FDeleteUnownedJunction := True
    else if SameText(Arg, '--force') then
      FForce := True
    else if SameText(Arg, '--clear-review') then
    begin
      if not TakeValue(Arg, FArgument) then
        Exit;
      FCommand := 'clear-review';
      Inc(Index);
    end
    else if SameText(Arg, '--check-updates') or SameText(Arg, '--check-update') then
    begin
      if not TakeValue(Arg, FArgument) then
        Exit;
      FCommand := 'check-updates';
      Inc(Index);
    end
    else if SameText(Arg, '--self-update') then
    begin
      if not TakeValue(Arg, FArgument) then
        Exit;
      FCommand := 'self-update';
      Inc(Index);
    end
    else if SameText(Arg, '--run') then
    begin
      if not TakeValue(Arg, FArgument) then
        Exit;
      FCommand := 'run';
      Inc(Index);
    end
    else if SameText(Arg, '--trace') then
    begin
      if not TakeValue(Arg, FArgument) then
        Exit;
      FCommand := 'trace';
      Inc(Index);
    end
    else if SameText(Arg, '--check-manifest') then
    begin
      if not TakeValue(Arg, FArgument) then
        Exit;
      FCommand := 'check-manifest';
      Inc(Index);
    end
    else if SameText(Arg, '--root') then
    begin
      if not TakeValue(Arg, FRootPath) then
        Exit;
      Inc(Index);
      FRootPath := ResolveRootPath(FRootPath);
    end
    else if SameText(Arg, '--exit-code-file') then
    begin
      if not TakeValue(Arg, FExitCodeFile) then
        Exit;
      Inc(Index);
    end
    else if SameText(Arg, '--log-file') then
    begin
      if not TakeValue(Arg, FLogFilePath) then
        Exit;
      Inc(Index);
    end
    else
    begin
      Log(Format('Unknown argument: "%s".', [Arg]));
      Exit;
    end;

    Inc(Index);
  end;

  Result := (FCommand = 'run') or (FCommand = 'trace') or
    (FCommand = 'check-manifest') or (FCommand = 'recover') or
    (FCommand = 'status') or (FCommand = 'clear-review') or
    (FCommand = 'apply-updates') or (FCommand = 'check-updates') or
    (FCommand = 'self-update') or (FCommand = 'post-update') or
    (FCommand = 'rollback');
  if not Result then
    Log('No command switch found (--run, --trace, --check-manifest, --recover, ' +
      '--status, --clear-review, --apply-updates, --check-updates, --self-update, ' +
      '--post-update, --rollback or --accept-rollback).');
end;

function TPortappixCli.ResolveManifestPath(const AReference: string;
  out AAppId: string): string;
var
  Candidate: string;
begin
  Result := '';
  AAppId := '';

  if AReference = '' then
    raise EPortappixCliError.Create('Missing app id or manifest path.');

  if TFile.Exists(AReference) then
    Result := TPath.GetFullPath(AReference)
  else if IsSafeFileComponent(AReference) then
  begin
    Candidate := TPath.Combine(TPath.Combine(FRootPath, 'Apps'),
      AReference + '\app.json');
    if TFile.Exists(Candidate) then
      Result := TPath.GetFullPath(Candidate);
  end;

  if Result = '' then
    raise EPortappixCliError.CreateFmt(
      'App "%s" was not found: no manifest exists at Apps\%s\app.json and "%s" is not a file.',
      [AReference, AReference, AReference]);
end;

function TPortappixCli.ExecuteRun: Integer;
var
  AppReference: string;
  ManifestPath: string;
  AppId: string;
  Manifest: TPortappixManifest;
  Journal: IPortappixJournal;
  Consent: TPortappixConsent;
  Runner: TPortableAppRunner;
  LockHandle: THandle;
  FinalCode: Integer;
  FinalMessage: string;
begin
  AppReference := FArgument;
  FinalMessage := '';
  LockHandle := 0;
  Manifest := nil;

  try
    try
      WarnIfUpdateUnconfirmed;
      ManifestPath := ResolveManifestPath(AppReference, AppId);
      Manifest := TPortappixManifest.LoadFromFile(ManifestPath);
      AppId := Manifest.Id;

      if not SameText(AppId, TPath.GetFileName(ExcludeTrailingPathDelimiter(
        TPath.GetDirectoryName(ManifestPath)))) then
        raise EPortappixCliError.CreateFmt(
          'Manifest id "%s" does not match its folder name "%s".',
          [AppId, TPath.GetFileName(TPath.GetDirectoryName(ManifestPath))]);

      if not TryAcquireMutex(AppMutexName(FRootPath, AppId), LockHandle) then
      begin
        Log(Format('%s is already running.', [AppId]));
        WriteExitCodeFile(CliExitAlreadyRunning, AppId,
          'App is already running (per-app mutex is held).', True);
        Exit(CliExitAlreadyRunning);
      end;

      Journal := TPortappixJournal.Create(FRootPath);
      Journal.OnLog :=
        procedure(AMsg: string)
        begin
          Log(AMsg);
        end;

      var ReviewItem: TPortappixReviewItem;
      try
        if Journal.HasReviewItem(AppId, ReviewItem) then
        begin
          var ReviewMsg := Format(
            'Application "%s" requires manual review before it can run.' + sLineBreak +
            'Unowned junction: "%s" -> "%s"' + sLineBreak +
            'Recorded at: %s' + sLineBreak +
            'Reason: %s' + sLineBreak +
            'Action required: Verify the folder, delete it by hand, or run:' + sLineBreak +
            '  Launcher.exe --clear-review %s [--delete-unowned-junction] [--force]',
            [AppId, ReviewItem.JunctionPath, ReviewItem.Target, ReviewItem.Time,
             ReviewItem.Reason, AppId]);
          Log(ReviewMsg);
          WriteExitCodeFile(CliExitNeedsReview, AppId, ReviewMsg);
          Exit(CliExitNeedsReview);
        end;
      except
        // Fail closed: an unreadable review state must refuse the run with
        // the needs-review contract instead of crashing or running blind.
        on E: EPortappixStateError do
        begin
          var UnreadableMsg := Format(
            'Application "%s" cannot be started: the review state is unreadable. %s',
            [AppId, E.Message]);
          Log(UnreadableMsg);
          WriteExitCodeFile(CliExitNeedsReview, AppId, UnreadableMsg);
          Exit(CliExitNeedsReview);
        end;
      end;

      Consent := TPortappixConsent.Create(FRootPath);
      try
        if Consent.NeedsConsent(Manifest) then
        begin
          if not FAcceptPolicy then
          begin
            Log(Format('First-run consent is required for "%s"; pass --accept-policy ' +
              'in test environments only.', [AppId]));
            WriteExitCodeFile(CliExitConsentRequired, AppId,
              'First-run consent was required but --accept-policy was not passed.');
            Exit(CliExitConsentRequired);
          end;
          Consent.Approve(Manifest);
          Log(Format('First-run consent recorded for "%s" (--accept-policy).', [AppId]));
        end;
      finally
        Consent.Free;
      end;

      Runner := TPortableAppRunner.Create(ManifestPath, Journal, FRootPath);
      try
        Runner.OnLog :=
          procedure(AMsg: string)
          begin
            Log(AMsg);
          end;
        if FWait then
          Log('Waiting for the whole process tree (default behaviour).');
        FinalCode := Integer(Runner.Run);
        Log(Format('Run finished with exit code %d.', [FinalCode]));
      finally
        Runner.Free;
      end;
    except
      on E: EPortappixElevationRequired do
      begin
        FinalCode := CliExitElevationRequired;
        FinalMessage := E.Message;
        Log('Elevation required: ' + E.Message);
      end;
      on E: EPortappixPolicyError do
      begin
        FinalCode := CliExitRejected;
        FinalMessage := E.Message;
        Log('Policy rejection: ' + E.Message);
      end;
      on E: EPortappixCliError do
      begin
        FinalCode := CliExitUsage;
        FinalMessage := E.Message;
        Log(E.Message);
      end;
      on E: EPortappixManifestError do
      begin
        FinalCode := CliExitRejected;
        FinalMessage := E.Message;
        Log('Manifest error: ' + E.Message);
      end;
      on E: Exception do
      begin
        FinalCode := CliExitGenericFailure;
        FinalMessage := E.Message;
        Log('Run failed: ' + E.Message);
      end;
    end;
  finally
    ReleaseMutexHandle(LockHandle);
    Manifest.Free;
  end;

  WriteExitCodeFile(FinalCode, AppId, FinalMessage);
  Result := FinalCode;
end;

function TPortappixCli.ResolveTraceReference(const AReference: string;
  out AAppId: string): string;
var
  Candidate: string;
begin
  if TFile.Exists(AReference) and
     SameText(TPath.GetExtension(AReference), '.exe') then
  begin
    // Tracing a loose executable: its app.json must sit next to it.
    Candidate := TPath.Combine(
      TPath.GetDirectoryName(TPath.GetFullPath(AReference)), 'app.json');
    if not TFile.Exists(Candidate) then
      raise EPortappixCliError.CreateFmt(
        'No app.json found next to "%s"; place the executable in an Apps\<id> ' +
        'folder first (Import App creates one).', [AReference]);
    Result := TPath.GetFullPath(Candidate);
  end
  else
    Result := ResolveManifestPath(AReference, AAppId);
end;

function TPortappixCli.ExecuteTrace: Integer;
var
  AppReference: string;
  ManifestPath: string;
  AppId: string;
  Manifest: TPortappixManifest;
  Consent: TPortappixConsent;
  Runner: TPortappixTraceRunner;
  LockHandle: THandle;
  FinalCode: Integer;
  FinalMessage: string;
  TraceResult: TPortappixTraceResult;
begin
  AppReference := FArgument;
  FinalMessage := '';
  LockHandle := 0;
  Manifest := nil;

  try
    try
      WarnIfUpdateUnconfirmed;
      ManifestPath := ResolveTraceReference(AppReference, AppId);
      Manifest := TPortappixManifest.LoadFromFile(ManifestPath);
      AppId := Manifest.Id;

      if not SameText(AppId, TPath.GetFileName(ExcludeTrailingPathDelimiter(
        TPath.GetDirectoryName(ManifestPath)))) then
        raise EPortappixCliError.CreateFmt(
          'Manifest id "%s" does not match its folder name "%s".',
          [AppId, TPath.GetFileName(TPath.GetDirectoryName(ManifestPath))]);

      if not TryAcquireMutex(AppMutexName(FRootPath, AppId), LockHandle) then
      begin
        Log(Format('%s is already running.', [AppId]));
        WriteExitCodeFile(CliExitAlreadyRunning, AppId,
          'App is already running (per-app mutex is held).', True);
        Exit(CliExitAlreadyRunning);
      end;

      Consent := TPortappixConsent.Create(FRootPath);
      try
        if Consent.NeedsConsent(Manifest) then
        begin
          if not FAcceptPolicy then
          begin
            Log(Format('First-run consent is required for "%s"; pass --accept-policy ' +
              'in test environments only. Trace mode is more dangerous than a ' +
              'normal run because the app is not sandboxed.', [AppId]));
            WriteExitCodeFile(CliExitConsentRequired, AppId,
              'First-run consent was required but --accept-policy was not passed.');
            Exit(CliExitConsentRequired);
          end;
          Consent.Approve(Manifest);
          Log(Format('First-run consent recorded for "%s" (--accept-policy).', [AppId]));
        end;
      finally
        Consent.Free;
      end;

      Log('WARNING: trace mode runs the app WITHOUT virtualization so Portappix ' +
        'can record what it writes on this PC. Only trace apps you trust, ' +
        'ideally in a VM or Windows Sandbox.');

      Runner := TPortappixTraceRunner.Create(FRootPath, ManifestPath);
      try
        Runner.OnLog :=
          procedure(AMsg: string)
          begin
            Log(AMsg);
          end;
        TraceResult := Runner.Execute;
        FinalCode := CliExitOk;
        FinalMessage := Format('Trace report written to "%s" (app exit code %d).',
          [TraceResult.ReportDirectory, TraceResult.AppExitCode]);
        Log(FinalMessage);
      finally
        Runner.Free;
      end;
    except
      on E: EPortappixTraceElevationRequired do
      begin
        FinalCode := CliExitElevationRequired;
        FinalMessage := E.Message;
        Log('Elevation required: ' + E.Message);
      end;
      on E: EPortappixTracePolicyError do
      begin
        FinalCode := CliExitRejected;
        FinalMessage := E.Message;
        Log('Policy rejection: ' + E.Message);
      end;
      on E: EPortappixManifestError do
      begin
        FinalCode := CliExitRejected;
        FinalMessage := E.Message;
        Log('Manifest error: ' + E.Message);
      end;
      on E: EPortappixCliError do
      begin
        FinalCode := CliExitUsage;
        FinalMessage := E.Message;
        Log(E.Message);
      end;
      on E: EPortappixTraceError do
      begin
        FinalCode := CliExitGenericFailure;
        FinalMessage := E.Message;
        Log('Trace failed: ' + E.Message);
      end;
      on E: Exception do
      begin
        FinalCode := CliExitGenericFailure;
        FinalMessage := E.Message;
        Log('Trace failed: ' + E.Message);
      end;
    end;
  finally
    ReleaseMutexHandle(LockHandle);
    Manifest.Free;
  end;

  WriteExitCodeFile(FinalCode, AppId, FinalMessage);
  Result := FinalCode;
end;

function TPortappixCli.ResolveUpdateUrl: string;
begin
  Result := FArgument.Trim;
  if Result <> '' then
    Exit;
  var Settings := TPortappixSettings.Create(FRootPath);
  try
    Settings.Load;
    Result := Settings.UpdateUrl;
  finally
    Settings.Free;
  end;
end;

procedure TPortappixCli.WarnIfUpdateUnconfirmed;
var
  Manager: TPortappixUpdateManager;
begin
  Manager := TPortappixUpdateManager.Create(FRootPath);
  try
    if Manager.NeedsRollbackOffer then
      Log('WARNING: a launcher update was applied but never confirmed ' +
        '(Launcher.exe.old exists without the update_ok marker). Start the ' +
        'launcher UI to get the option to restore the previous version, or ' +
        'delete Launcher.exe.old to dismiss the rollback offer.');
  finally
    Manager.Free;
  end;
end;

function TPortappixCli.ExecuteApplyUpdates: Integer;
var
  Manager: TPortappixPackageManager;
begin
  Manager := TPortappixPackageManager.Create(FRootPath);
  try
    Manager.OnLog :=
      procedure(AMsg: string)
      begin
        Log(AMsg);
      end;
    try
      Manager.ApplyPendingUpdates;
      Log('Finished applying queued updates.');
      WriteExitCodeFile(CliExitOk, '', '');
      Result := CliExitOk;
    except
      on E: Exception do
      begin
        Log('Applying queued updates failed: ' + E.Message);
        WriteExitCodeFile(CliExitGenericFailure, '', E.Message);
        Result := CliExitGenericFailure;
      end;
    end;
  finally
    Manager.Free;
  end;
end;

function TPortappixCli.ExecuteCheckUpdates: Integer;
var
  Url: string;
  Manager: TPortappixUpdateManager;
  Release: TPortappixRelease;
  Available: Boolean;
begin
  Url := ResolveUpdateUrl;
  if Url = '' then
  begin
    Log('No release URL given; pass it to --check-updates or set updateUrl in ' +
      'Cache\settings.json.');
    WriteExitCodeFile(CliExitUsage, '', 'No release URL given.');
    Exit(CliExitUsage);
  end;

  Manager := TPortappixUpdateManager.Create(FRootPath);
  try
    Manager.OnLog :=
      procedure(AMsg: string)
      begin
        Log(AMsg);
      end;
    try
      Release := DownloadReleases(Url);
      try
        Available := Manager.IsUpdateAvailable(Release);
        if Available then
          Log(Format('Update available: %s -> %s (%s).',
            [Manager.InstalledVersion, Release.Version, Release.Url]))
        else
          Log(Format('Up to date: installed %s, latest release %s.',
            [Manager.InstalledVersion, Release.Version]));
        WriteExitCodeFile(CliExitOk, '', Format(
          'updateAvailable=%s; installed=%s; available=%s; url=%s',
          [BoolToStr(Available, True), Manager.InstalledVersion, Release.Version,
           Release.Url]));
        Result := CliExitOk;
      finally
        Release.Free;
      end;
    except
      on E: EPortappixUpdateError do
      begin
        Log('Update check failed: ' + E.Message);
        WriteExitCodeFile(CliExitGenericFailure, '', E.Message);
        Result := CliExitGenericFailure;
      end;
      on E: Exception do
      begin
        Log('Update check failed: ' + E.Message);
        WriteExitCodeFile(CliExitGenericFailure, '', E.Message);
        Result := CliExitGenericFailure;
      end;
    end;
  finally
    Manager.Free;
  end;
end;

function TPortappixCli.ExecuteSelfUpdate: Integer;
var
  Url: string;
  Manager: TPortappixUpdateManager;
begin
  Url := ResolveUpdateUrl;
  if Url = '' then
  begin
    Log('No release URL given; pass it to --self-update or set updateUrl in ' +
      'Cache\settings.json.');
    WriteExitCodeFile(CliExitUsage, '', 'No release URL given.');
    Exit(CliExitUsage);
  end;

  Manager := TPortappixUpdateManager.Create(FRootPath);
  try
    Manager.OnLog :=
      procedure(AMsg: string)
      begin
        Log(AMsg);
      end;
    try
      Manager.ApplyUpdateFromUrl(Url);
      // The new launcher was started with --post-update; this process exits.
      WriteExitCodeFile(CliExitOk, '', 'Update applied; the launcher is restarting.');
      Result := CliExitOk;
    except
      on E: EPortappixUpdateError do
      begin
        Log('Self-update failed: ' + E.Message);
        WriteExitCodeFile(CliExitGenericFailure, '', E.Message);
        Result := CliExitGenericFailure;
      end;
      on E: Exception do
      begin
        Log('Self-update failed: ' + E.Message);
        WriteExitCodeFile(CliExitGenericFailure, '', E.Message);
        Result := CliExitGenericFailure;
      end;
    end;
  finally
    Manager.Free;
  end;
end;

function TPortappixCli.ExecutePostUpdate: Integer;
var
  Manager: TPortappixUpdateManager;
begin
  Manager := TPortappixUpdateManager.Create(FRootPath);
  try
    Manager.OnLog :=
      procedure(AMsg: string)
      begin
        Log(AMsg);
      end;
    try
      Manager.ConfirmUpdate;
      WriteExitCodeFile(CliExitOk, '', Format(
        'Update confirmed; installed version is %s.', [Manager.InstalledVersion]));
      Result := CliExitOk;
    except
      on E: Exception do
      begin
        Log('Post-update confirmation failed: ' + E.Message);
        WriteExitCodeFile(CliExitGenericFailure, '', E.Message);
        Result := CliExitGenericFailure;
      end;
    end;
  finally
    Manager.Free;
  end;
end;

function TPortappixCli.ExecuteCheckManifest: Integer;
var
  ManifestPath: string;
  Manifest: TPortappixManifest;
  Policy: TPolicyResult;
  FinalCode: Integer;
begin
  Manifest := nil;
  Policy := nil;

  if (FArgument = '') or not TFile.Exists(FArgument) then
  begin
    Log(Format('Manifest not found: "%s".', [FArgument]));
    WriteExitCodeFile(CliExitRejected, '', Format('Manifest not found: "%s".', [FArgument]));
    Exit(CliExitRejected);
  end;

  ManifestPath := TPath.GetFullPath(FArgument);
  try
    Manifest := TPortappixManifest.LoadFromFile(ManifestPath);
    Policy := TPortappixPolicy.ValidateManifest(Manifest);
    if Policy.Allowed then
    begin
      Log(Format('Manifest "%s" passes policy validation.', [ManifestPath]));
      FinalCode := CliExitOk;
    end
    else
    begin
      Log(Format('Manifest "%s" failed policy validation: %s', [ManifestPath, Policy.Summary]));
      FinalCode := CliExitRejected;
    end;
  except
    on E: Exception do
    begin
      Log('Manifest validation failed: ' + E.Message);
      FinalCode := CliExitRejected;
      if Policy = nil then
        Policy := TPolicyResult.Create;
      Policy.AddError(E.Message);
    end;
  end;

  if FExitCodeFile <> '' then
  begin
    var Record_ := TJSONObject.Create;
    try
      Record_.AddPair('command', 'check-manifest');
      Record_.AddPair('manifest', ManifestPath);
      Record_.AddPair('allowed', TJSONBool.Create(Policy.Allowed));
      var Messages := TJSONArray.Create;
      for var Line in Policy.Messages do
        Messages.Add(Line);
      Record_.AddPair('messages', Messages);
      try
        ForceDirectories(TPath.GetDirectoryName(TPath.GetFullPath(FExitCodeFile)));
        WriteTextFileAtomic(FExitCodeFile, Record_.Format(2));
      except
        on E: Exception do
          Log(Format('Unable to write the exit-code file "%s": %s', [FExitCodeFile, E.Message]));
      end;
    finally
      Record_.Free;
    end;
  end;

  Policy.Free;
  Manifest.Free;
  Result := FinalCode;
end;

function TPortappixCli.ExecuteRecover: Integer;
var
  Journal: IPortappixJournal;
begin
  Journal := TPortappixJournal.Create(FRootPath);
  Journal.OnLog :=
    procedure(AMsg: string)
    begin
      Log(AMsg);
    end;
  try
    Journal.RecoverPendingCleanups;
    Log('Recovery finished.');
    WriteExitCodeFile(CliExitOk, '', '');
    Result := CliExitOk;
  except
    on E: Exception do
    begin
      Log('Recovery failed: ' + E.Message);
      WriteExitCodeFile(CliExitGenericFailure, '', E.Message);
      Result := CliExitGenericFailure;
    end;
  end;
end;

function TPortappixCli.ExecuteStatus: Integer;
var
  Journal: TPortappixJournal;
  Items: TArray<TPortappixReviewItem>;
  Msg: string;
begin
  Journal := TPortappixJournal.Create(FRootPath);
  try
    // Fail closed: an unreadable or corrupt review state must never be
    // reported as "Clean".
    try
      Items := Journal.ListReviewItems;
    except
      on E: EPortappixStateError do
      begin
        Msg := 'Status: REVIEW STATE UNREADABLE. ' + E.Message;
        Log(Msg);
        WriteExitCodeFile(CliExitNeedsReview, '', Msg);
        Exit(CliExitNeedsReview);
      end;
    end;
    if Length(Items) = 0 then
    begin
      Msg := 'Status: Clean. No unowned junctions require review.';
      Log(Msg);
      WriteExitCodeFile(CliExitOk, '', Msg);
      Exit(CliExitOk);
    end;

    Msg := Format('Status: %d unowned junction(s) require manual review:' + sLineBreak, [Length(Items)]);
    for var Item in Items do
    begin
      Msg := Msg + Format('  App: %s' + sLineBreak +
                          '  Junction: %s' + sLineBreak +
                          '  Target: %s' + sLineBreak +
                          '  Recorded: %s' + sLineBreak +
                          '  Reason: %s' + sLineBreak,
                          [Item.AppId, Item.JunctionPath, Item.Target, Item.Time, Item.Reason]);
    end;
    Log(Msg);
    WriteExitCodeFile(CliExitNeedsReview, '', Msg);
    Result := CliExitNeedsReview;
  finally
    Journal.Free;
  end;
end;

function TPortappixCli.ExecuteClearReview: Integer;
var
  Journal: TPortappixJournal;
  ErrorMsg: string;
begin
  if FArgument = '' then
  begin
    Log('Missing app id for --clear-review.');
    WriteExitCodeFile(CliExitUsage, '', 'Missing app id for --clear-review.');
    Exit(CliExitUsage);
  end;

  Journal := TPortappixJournal.Create(FRootPath);
  try
    Journal.OnLog :=
      procedure(AMsg: string)
      begin
        Log(AMsg);
      end;

    if Journal.ClearReview(FArgument, FForce, FDeleteUnownedJunction, ErrorMsg) then
    begin
      Log(Format('Review cleared for app "%s".', [FArgument]));
      WriteExitCodeFile(CliExitOk, FArgument, Format('Review cleared for app "%s".', [FArgument]));
      Result := CliExitOk;
    end
    else
    begin
      Log(Format('Failed to clear review for app "%s": %s', [FArgument, ErrorMsg]));
      WriteExitCodeFile(CliExitGenericFailure, FArgument, ErrorMsg);
      Result := CliExitGenericFailure;
    end;
  finally
    Journal.Free;
  end;
end;

function TPortappixCli.ExecuteRollback: Integer;
var
  Manager: TPortappixUpdateManager;
begin
  Manager := TPortappixUpdateManager.Create(FRootPath);
  try
    Manager.OnLog :=
      procedure(AMsg: string)
      begin
        Log(AMsg);
      end;
    if not Manager.NeedsRollbackOffer then
    begin
      Log('No rollback needed or offered.');
      WriteExitCodeFile(CliExitGenericFailure, '', 'No rollback needed.');
      Exit(CliExitGenericFailure);
    end;
    try
      Manager.RollbackToOldLauncher(False);
      Log('Rollback to old launcher succeeded.');
      WriteExitCodeFile(CliExitOk, '', 'Rollback succeeded.');
      Result := CliExitOk;
    except
      on E: Exception do
      begin
        Log('Rollback failed: ' + E.Message);
        WriteExitCodeFile(CliExitGenericFailure, '', E.Message);
        Result := CliExitGenericFailure;
      end;
    end;
  finally
    Manager.Free;
  end;
end;

function TPortappixCli.Execute: Integer;
begin
  if FCommand = 'run' then
    Result := ExecuteRun
  else if FCommand = 'trace' then
    Result := ExecuteTrace
  else if FCommand = 'check-manifest' then
    Result := ExecuteCheckManifest
  else if FCommand = 'recover' then
    Result := ExecuteRecover
  else if FCommand = 'status' then
    Result := ExecuteStatus
  else if FCommand = 'clear-review' then
    Result := ExecuteClearReview
  else if FCommand = 'apply-updates' then
    Result := ExecuteApplyUpdates
  else if FCommand = 'check-updates' then
    Result := ExecuteCheckUpdates
  else if FCommand = 'self-update' then
    Result := ExecuteSelfUpdate
  else if FCommand = 'post-update' then
    Result := ExecutePostUpdate
  else if FCommand = 'rollback' then
    Result := ExecuteRollback
  else
  begin
    CliWrite(CliUsageText);
    Result := CliExitUsage;
  end;
end;

function HasCliArguments: Boolean;
begin
  Result := (ParamCount > 0) and TextStartsWith(ParamStr(1), '--');
end;

function ExecuteCli: Integer;
var
  Cli: TPortappixCli;
  Args: TArray<string>;
begin
  SetLength(Args, ParamCount);
  for var Index := 1 to ParamCount do
    Args[Index - 1] := ParamStr(Index);

  Cli := TPortappixCli.Create;
  try
    if not Cli.Parse(Args) then
    begin
      CliWrite(CliUsageText);
      Result := CliExitUsage;
    end
    else
      Result := Cli.Execute;
  finally
    Cli.Free;
  end;
end;

end.
