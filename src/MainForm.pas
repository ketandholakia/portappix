unit MainForm;

interface

uses
  Winapi.Windows,
  Winapi.Messages,
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  System.StrUtils,
  System.UITypes,
  System.Generics.Collections,
  System.Generics.Defaults,
  Vcl.Graphics,
  Vcl.Controls,
  Vcl.Forms,
  Vcl.Dialogs,
  Vcl.ComCtrls,
  Vcl.StdCtrls,
  Vcl.ExtCtrls,
  Vcl.Menus,
  Portappix.Common,
  Portappix.Icons,
  Portappix.Manifest,
  Portappix.Catalog,
  Portappix.PackageManager,
  Portappix.Settings,
  Portappix.State,
  Portappix.Runner,
  Portappix.TrayUI,
  Portappix.Importer;

type
  TMainLauncherForm = class(TForm)
    PageControl: TPageControl;
    InstalledTab: TTabSheet;
    StoreTab: TTabSheet;
    InstalledListView: TListView;
    StoreListView: TListView;
    InstalledButtonsPanel: TPanel;
    StoreTopPanel: TPanel;
    StoreBottomPanel: TPanel;
    LaunchButton: TButton;
    UninstallButton: TButton;
    RefreshInstalledButton: TButton;
    ImportAppButton: TButton;
    TraceButton: TButton;
    SearchEdit: TEdit;
    SearchLabel: TLabel;
    RefreshCatalogButton: TButton;
    UpdateButton: TButton;
    InstallButton: TButton;
    ProgressBar: TProgressBar;
    StatusLabel: TLabel;
    TrayIcon: TTrayIcon;
    dlgImportExe: TOpenDialog;
    procedure FormCreate(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: Boolean);
    procedure FormDestroy(Sender: TObject);
    procedure RefreshInstalledButtonClick(Sender: TObject);
    procedure LaunchButtonClick(Sender: TObject);
    procedure UninstallButtonClick(Sender: TObject);
    procedure RefreshCatalogButtonClick(Sender: TObject);
    procedure InstallButtonClick(Sender: TObject);
    procedure UpdateButtonClick(Sender: TObject);
    procedure SearchEditChange(Sender: TObject);
    procedure TrayIconDblClick(Sender: TObject);
    procedure btnImportAppClick(Sender: TObject);
    procedure TraceButtonClick(Sender: TObject);
  private
    FRootPath: string;
    FAppsDir: string;
    FCatalogCacheFile: string;
    FCatalogUrlFile: string;
    FCatalogUrl: string;
{$IFDEF PORTAPPIX_TESTUPDATE}
    FAllowUnsignedCatalog: Boolean;
{$ENDIF}
    FJournal: IPortappixJournal;
    FTrayUI: TPortappixTrayUI;
    FCatalog: TPortappixCatalog;
    FSettings: TPortappixSettings;
    FPackageManager: TPortappixPackageManager;
    FInstalledPaths: TStringList;
    FInstalledVersions: TDictionary<string, string>;
    FInstallInProgress: Boolean;
    FTraceInProgress: Boolean;
    FAllowClose: Boolean;
    FWaitingForApps: Boolean;
    // True while the last user-visible operation failed; drives the
    // notification-area icon into its error state.
    FLastOperationFailed: Boolean;
    procedure InitializePaths;
    procedure LoadCatalogUrl;
    procedure SaveCatalogUrl;
    procedure InitializeRuntime;
    procedure InitializeTray;
    procedure LoadInstalledApps;
    procedure LoadCatalogFromCache;
    procedure RefreshCatalogInBackground;
    procedure PopulateStoreList(const AFilter: string);
    function SelectedInstalledManifestPath: string;
    function SelectedCatalogApp: TCatalogApp;
    procedure ShowMainForm;
    procedure HideToTray;
    procedure RequestExit;
    procedure SetStatus(const AMessage: string);
    procedure QueueStatus(const AMessage: string);
    // Notification-area icon state (idle / running / paused / error /
    // inactive), derived from the real launcher state.
    procedure UpdateTrayState;
    procedure MarkOperationFailed;
    procedure MarkOperationSucceeded;
    procedure SetInstallProgress(const AAppId: string; ASent, ATotal: Int64);
    procedure InstallSelectedAppInBackground;
    procedure ApplyPendingUpdatesInBackground;
    procedure CheckLauncherUpdateWatchdog;
    procedure TraceSelectedAppInBackground(const AManifestPath: string);
    function AskConsent(const AAppId, ADescription, AManifestHash: string): Boolean;
    function WaitForRunningApps(const ATimeoutMs: Cardinal): Boolean;
{$IFDEF PORTAPPIX_TESTUPDATE}
    procedure SetAllowUnsignedCatalog(const AValue: Boolean);
{$ENDIF}
    procedure WMQueryEndSession(var Message: TWMQueryEndSession); message WM_QUERYENDSESSION;
    procedure WMEndSession(var Message: TWMEndSession); message WM_ENDSESSION;
  public
    property CatalogUrl: string read FCatalogUrl write FCatalogUrl;
{$IFDEF PORTAPPIX_TESTUPDATE}
    property AllowUnsignedCatalog: Boolean read FAllowUnsignedCatalog
      write SetAllowUnsignedCatalog;
{$ENDIF}
  end;

var
  MainLauncherForm: TMainLauncherForm;

implementation

uses
  Portappix.Trace,
  Portappix.Update;

{$R *.dfm}

procedure TMainLauncherForm.FormCreate(Sender: TObject);
begin
  FInstallInProgress := False;
  FTraceInProgress := False;
  FAllowClose := False;
  FWaitingForApps := False;
{$IFDEF PORTAPPIX_TESTUPDATE}
  FAllowUnsignedCatalog := False;
{$ENDIF}
  FInstalledPaths := TStringList.Create;
  FInstalledVersions := TDictionary<string, string>.Create(TIStringComparer.Ordinal);
  InitializePaths;
  CheckLauncherUpdateWatchdog;
  LoadCatalogUrl;
  InitializeRuntime;      // includes TPortappixJournal.RecoverPendingCleanups (boot)
  if FJournal <> nil then
  begin
    var ReviewItems := FJournal.ListReviewItems;
    if Length(ReviewItems) > 0 then
      QueueStatus(Format('WARNING: %d unowned junction(s) require manual review (see --status).',
        [Length(ReviewItems)]));
  end;
  InitializeTray;
  LoadInstalledApps;
  LoadCatalogFromCache;   // instant local cache
  RefreshCatalogInBackground; // fetch latest catalog in background thread
  ApplyPendingUpdatesInBackground; // install updates queued while apps ran
end;

procedure TMainLauncherForm.InitializePaths;
begin
  FRootPath := TPath.GetFullPath(LauncherDirectory);
  FAppsDir := TPath.Combine(FRootPath, 'Apps');
  FCatalogCacheFile := TPath.Combine(TPath.Combine(FRootPath, 'Cache'), 'catalog.json');
  FCatalogUrlFile := TPath.Combine(TPath.Combine(FRootPath, 'Cache'), 'catalog_url.txt');
  FSettings := TPortappixSettings.Create(FRootPath);
  FSettings.Load;
end;

procedure TMainLauncherForm.LoadCatalogUrl;
begin
  FCatalogUrl := GetEnvironmentVariable('PORTAPPIX_CATALOG_URL').Trim;
  if (FCatalogUrl = '') and TFile.Exists(FCatalogUrlFile) then
    try
      FCatalogUrl := TFile.ReadAllText(FCatalogUrlFile, TEncoding.UTF8).Trim;
    except
    end;
end;

procedure TMainLauncherForm.SaveCatalogUrl;
begin
  try
    ForceDirectories(TPath.GetDirectoryName(FCatalogUrlFile));
    TFile.WriteAllText(FCatalogUrlFile, FCatalogUrl, TEncoding.UTF8);
  except
  end;
end;

{$IFDEF PORTAPPIX_TESTUPDATE}
procedure TMainLauncherForm.SetAllowUnsignedCatalog(const AValue: Boolean);
begin
  FAllowUnsignedCatalog := AValue;
  AllowUnsignedCatalogs := AValue;
end;
{$ENDIF}

procedure TMainLauncherForm.InitializeRuntime;
begin
  ForceDirectories(FAppsDir);
  ForceDirectories(TPath.GetDirectoryName(FCatalogCacheFile));

  FJournal := TPortappixJournal.Create(FRootPath);
  FJournal.OnLog :=
    procedure(AMsg: string)
    begin
      QueueStatus(AMsg);
    end;
  try
    FJournal.RecoverPendingCleanups;
  except
    on E: Exception do
      QueueStatus('Startup recovery reported an error: ' + E.Message);
  end;

  FCatalog := TPortappixCatalog.Create;
  FPackageManager := TPortappixPackageManager.Create(FRootPath);
  FPackageManager.OnLog :=
    procedure(AMsg: string)
    begin
      QueueStatus(AMsg);
    end;
end;

procedure TMainLauncherForm.InitializeTray;
begin
  TrayIcon.Visible := True;
  FTrayUI := TPortappixTrayUI.Create(TrayIcon, FRootPath, FJournal);
  FTrayUI.OnShowForm :=
    procedure
    begin
      TThread.Queue(nil, ShowMainForm);
    end;
  FTrayUI.OnRefreshForm :=
    procedure
    begin
      TThread.Queue(nil, LoadInstalledApps);
    end;
  FTrayUI.OnExitRequested :=
    procedure
    begin
      TThread.Queue(nil, RequestExit);
    end;
  FTrayUI.OnConsentRequired :=
    function(const AAppId, ADescription, AManifestHash: string): Boolean
    begin
      Result := AskConsent(AAppId, ADescription, AManifestHash);
    end;
  FTrayUI.OnLog :=
    procedure(AMsg: string)
    begin
      QueueStatus(AMsg);
    end;
end;

procedure TMainLauncherForm.FormCloseQuery(Sender: TObject; var CanClose: Boolean);
var
  Running: Integer;
begin
  if FAllowClose then
  begin
    CanClose := True;
    Exit;
  end;

  CanClose := False;
  if FWaitingForApps then
    Exit;

  Running := 0;
  if Assigned(FTrayUI) then
    Running := FTrayUI.RunningCount;

  if Running > 0 then
  begin
    if MessageDlg(Format('%d app(s) are still running. Wait for them to finish and exit?',
      [Running]), mtWarning, [mbYes, mbNo], 0) = mrYes then
    begin
      FWaitingForApps := True;
      try
        if WaitForRunningApps(30000) then
        begin
          FAllowClose := True;
          CanClose := True;
        end
        else
          ShowMessage('Apps are still running; exit cancelled. Close them and try again.');
      finally
        FWaitingForApps := False;
      end;
    end;
  end
  else
    HideToTray;
end;

procedure TMainLauncherForm.FormDestroy(Sender: TObject);
begin
  FInstalledPaths.Free;
  FInstalledVersions.Free;
  FTrayUI.Free;
  FPackageManager.Free;
  FCatalog.Free;
  FSettings.Free;
  FJournal := nil;
end;

procedure TMainLauncherForm.WMQueryEndSession(var Message: TWMQueryEndSession);
begin
  // Never block Windows logoff/shutdown; the crash journal recovers leftover state.
  FAllowClose := True;
  Message.Result := 1;
end;

procedure TMainLauncherForm.WMEndSession(var Message: TWMEndSession);
begin
  if Message.EndSession then
    FAllowClose := True;
  inherited;
end;

procedure TMainLauncherForm.RequestExit;
var
  Running: Integer;
begin
  Running := 0;
  if Assigned(FTrayUI) then
    Running := FTrayUI.RunningCount;

  if Running > 0 then
  begin
    if MessageDlg(Format('%d app(s) are still running. Wait for them to finish and exit?',
      [Running]), mtWarning, [mbYes, mbNo], 0) <> mrYes then
      Exit;
    if not WaitForRunningApps(30000) then
    begin
      ShowMessage('Apps are still running; exit cancelled.');
      Exit;
    end;
  end;

  FAllowClose := True;
  Close;
end;

function TMainLauncherForm.WaitForRunningApps(const ATimeoutMs: Cardinal): Boolean;
var
  StartedAt: UInt64;
begin
  if not Assigned(FTrayUI) then
    Exit(True);

  StartedAt := GetTickCount64;
  while FTrayUI.RunningCount > 0 do
  begin
    if GetTickCount64 - StartedAt >= ATimeoutMs then
      Exit(False);
    Application.ProcessMessages;
    Sleep(50);
  end;
  Result := True;
end;

procedure TMainLauncherForm.ShowMainForm;
begin
  Visible := True;
  WindowState := wsNormal;
  Show;
  Application.BringToFront;
end;

procedure TMainLauncherForm.HideToTray;
begin
  Hide;
end;

procedure TMainLauncherForm.SetStatus(const AMessage: string);
begin
  if StatusLabel <> nil then
    StatusLabel.Caption := AMessage;
end;

procedure TMainLauncherForm.QueueStatus(const AMessage: string);
var
  StatusMsg: string;
begin
  StatusMsg := AMessage;
  TThread.Queue(nil,
    procedure
    begin
      SetStatus(StatusMsg);
    end);
end;

procedure TMainLauncherForm.UpdateTrayState;
var
  State: TPortappixTrayIconState;
  Pending: Boolean;
begin
  if not Assigned(FTrayUI) then
    Exit;

  Pending := False;
  if Assigned(FPackageManager) then
    try
      Pending := Length(FPackageManager.PendingUpdateIds) > 0;
    except
      Pending := False;
    end;

  if FLastOperationFailed then
    State := tisError
  else if Pending then
    State := tisPaused
  else if FInstalledPaths.Count = 0 then
    State := tisInactive
  else
    State := tisNormal;
  FTrayUI.SetTrayState(State);
end;

procedure TMainLauncherForm.MarkOperationFailed;
begin
  FLastOperationFailed := True;
  UpdateTrayState;
end;

procedure TMainLauncherForm.MarkOperationSucceeded;
begin
  if not FLastOperationFailed then
    Exit;
  FLastOperationFailed := False;
  UpdateTrayState;
end;

procedure TMainLauncherForm.LoadInstalledApps;
var
  Item: TListItem;
  Manifest: TPortappixManifest;
  FolderName: string;
begin
  FInstalledPaths.Clear;
  FInstalledVersions.Clear;

  InstalledListView.Items.BeginUpdate;
  try
    InstalledListView.Clear;
    if not TDirectory.Exists(FAppsDir) then
      Exit;

    for var AppDir in TDirectory.GetDirectories(FAppsDir) do
    begin
      FolderName := TPath.GetFileName(AppDir);
      if IsTransientAppFolder(FolderName) then
        Continue;

      var ManifestPath := TPath.Combine(AppDir, 'app.json');
      if not TFile.Exists(ManifestPath) then
        Continue;
      try
        Manifest := TPortappixManifest.LoadFromFile(ManifestPath);
        try
          if not SameText(Manifest.Id, FolderName) then
          begin
            QueueStatus(Format('Skipping "%s": manifest id "%s" does not match its folder.',
              [ManifestPath, Manifest.Id]));
            Continue;
          end;

          Item := InstalledListView.Items.Add;
          Item.Caption := Manifest.Name;
          Item.SubItems.Add(Manifest.Id);
          Item.SubItems.Add(AppDir);
          FInstalledPaths.Add(ManifestPath);
          FInstalledVersions.AddOrSetValue(Manifest.Id, Manifest.Version);
        finally
          Manifest.Free;
        end;
      except
        on E: Exception do
        begin
          MarkOperationFailed;
          QueueStatus(Format('Unable to read "%s": %s', [ManifestPath, E.Message]));
        end;
      end;
    end;
  finally
    InstalledListView.Items.EndUpdate;
  end;

  PopulateStoreList(SearchEdit.Text);
  if Assigned(FTrayUI) then
    FTrayUI.RebuildMenu;
  UpdateTrayState;
end;

function TMainLauncherForm.SelectedInstalledManifestPath: string;
var
  Item: TListItem;
begin
  Result := '';
  Item := InstalledListView.Selected;
  if (Item = nil) or (Item.Index < 0) or (Item.Index >= FInstalledPaths.Count) then
    Exit;
  Result := FInstalledPaths[Item.Index];
end;

function TMainLauncherForm.SelectedCatalogApp: TCatalogApp;
var
  Item: TListItem;
begin
  Result := nil;
  Item := StoreListView.Selected;
  if (Item = nil) or (Item.SubItems.Count < 1) then
    Exit;
  Result := FCatalog.FindById(Item.SubItems[0]);
end;

procedure TMainLauncherForm.LaunchButtonClick(Sender: TObject);
var
  ManifestPath: string;
begin
  ManifestPath := SelectedInstalledManifestPath;
  if ManifestPath = '' then
  begin
    MessageDlg('Select an installed app first.', mtInformation, [mbOK], 0);
    Exit;
  end;
  if Assigned(FTrayUI) then
    FTrayUI.LaunchApp(ManifestPath)
  else
    QueueStatus('Tray UI is not available.');
end;

procedure TMainLauncherForm.UninstallButtonClick(Sender: TObject);
var
  Item: TListItem;
  AppDir: string;
  PrevDir: string;
  AppId: string;
begin
  Item := InstalledListView.Selected;
  if (Item = nil) or (Item.SubItems.Count < 2) then
  begin
    MessageDlg('Select an installed app to uninstall.', mtInformation, [mbOK], 0);
    Exit;
  end;

  AppId := Item.SubItems[0];
  AppDir := Item.SubItems[1];
  if not TDirectory.Exists(AppDir) then
  begin
    QueueStatus('App directory does not exist: ' + AppDir);
    Exit;
  end;

  if MessageDlg('Uninstall "' + Item.Caption + '"? This removes Apps\<id> (and its rollback copy) but leaves Data\<id> intact.',
    mtConfirmation, [mbYes, mbNo], 0) <> mrYes then
    Exit;

  try
    TDirectory.Delete(AppDir, True);
    PrevDir := AppDir + '.prev';
    if TDirectory.Exists(PrevDir) then
      TDirectory.Delete(PrevDir, True);
    if Assigned(FPackageManager) then
      FPackageManager.RemovePendingUpdate(AppId);
    QueueStatus('Uninstalled ' + Item.Caption + '. Data was preserved.');
    LoadInstalledApps;
    MarkOperationSucceeded;
  except
    on E: Exception do
    begin
      MarkOperationFailed;
      MessageDlg('Unable to uninstall app: ' + E.Message, mtError, [mbOK], 0);
    end;
  end;
end;

procedure TMainLauncherForm.RefreshInstalledButtonClick(Sender: TObject);
begin
  LoadInstalledApps;
end;

procedure TMainLauncherForm.LoadCatalogFromCache;
var
  LocalCatalog: string;
begin
  try
    if not TFile.Exists(FCatalogCacheFile) then
    begin
      LocalCatalog := TPath.Combine(FRootPath, 'catalog.json');
      if TFile.Exists(LocalCatalog) then
      begin
        ForceDirectories(TPath.GetDirectoryName(FCatalogCacheFile));
        TFile.Copy(LocalCatalog, FCatalogCacheFile, True);
        if TFile.Exists(LocalCatalog + '.sig') then
          TFile.Copy(LocalCatalog + '.sig', FCatalogCacheFile + '.sig', True);
      end;
    end;

    if TFile.Exists(FCatalogCacheFile) then
    begin
      FCatalog.LoadFromFile(FCatalogCacheFile);
      PopulateStoreList(SearchEdit.Text);
      SetStatus('Loaded catalog cache.');
      MarkOperationSucceeded;
    end
    else
      SetStatus('No catalog cache found.');
  except
    on E: Exception do
    begin
      MarkOperationFailed;
      SetStatus('Unable to load catalog cache: ' + E.Message);
    end;
  end;
end;

procedure TMainLauncherForm.PopulateStoreList(const AFilter: string);
var
  FilterText: string;
  Item: TListItem;
  Status: string;
  InstalledVersion: string;
begin
  FilterText := AFilter.Trim.ToLower;
  StoreListView.Items.BeginUpdate;
  try
    StoreListView.Clear;
    for var App in FCatalog.Apps do
    begin
      if (FilterText <> '') and
         not ContainsStr(App.Name.ToLower, FilterText) and
         not ContainsStr(App.Id.ToLower, FilterText) and
         not ContainsStr(App.Category.ToLower, FilterText) then
        Continue;

      if FInstalledVersions.TryGetValue(App.Id, InstalledVersion) then
      begin
        if FPackageManager.HasPendingUpdate(App.Id) then
          Status := 'Update pending'
        else if SameText(InstalledVersion, App.Version) then
          Status := 'Installed'
        else
          Status := 'Update available';
      end
      else
        Status := '';

      Item := StoreListView.Items.Add;
      Item.Caption := App.Name;
      Item.SubItems.Add(App.Id);
      Item.SubItems.Add(App.Version);
      Item.SubItems.Add(Status);
      Item.SubItems.Add(App.Category);
      Item.SubItems.Add(IntToStr(App.Size));
    end;
  finally
    StoreListView.Items.EndUpdate;
  end;
end;

procedure TMainLauncherForm.SearchEditChange(Sender: TObject);
begin
  PopulateStoreList(SearchEdit.Text);
end;

procedure TMainLauncherForm.RefreshCatalogInBackground;
var
  CatalogUrl: string;
  CacheFile: string;
begin
  CatalogUrl := FCatalogUrl.Trim;
  if CatalogUrl = '' then
    Exit;

  CacheFile := FCatalogCacheFile;
  QueueStatus('Refreshing catalog...');

  TThread.CreateAnonymousThread(
    procedure
    var
      Catalog: TPortappixCatalog;
      Json: string;
      ErrorMsg: string;
    begin
      Catalog := TPortappixCatalog.Create;
      try
        try
          Catalog.LoadFromUrl(CatalogUrl, CacheFile);
          Json := TFile.ReadAllText(CacheFile, TEncoding.UTF8);
          TThread.Queue(nil,
            procedure
            begin
              try
                FCatalog.LoadFromJson(Json);
                PopulateStoreList(SearchEdit.Text);
                SetStatus('Catalog updated.');
                MarkOperationSucceeded;
              except
                on E: Exception do
                begin
                  MarkOperationFailed;
                  SetStatus('Unable to apply catalog update: ' + E.Message);
                end;
              end;
            end);
        except
          on E: Exception do
          begin
            ErrorMsg := E.Message;
            TThread.Queue(nil,
              procedure
              begin
                MarkOperationFailed;
                SetStatus('Unable to refresh catalog: ' + ErrorMsg);
              end);
          end;
        end;
      finally
        Catalog.Free;
      end;
    end).Start;
end;

procedure TMainLauncherForm.RefreshCatalogButtonClick(Sender: TObject);
var
  PromptUrl: string;
begin
  if (FCatalogUrl.Trim = '') or (GetKeyState(VK_SHIFT) < 0) then
  begin
    PromptUrl := InputBox('Store Catalog URL',
      'Enter the hosted catalog.json URL (must start with https://):', FCatalogUrl).Trim;
    if PromptUrl = '' then
      Exit;
    if not IsHttpsUrl(PromptUrl) then
    begin
      MessageDlg('Catalog URL must start with https://', mtError, [mbOK], 0);
      Exit;
    end;
    FCatalogUrl := PromptUrl;
    SaveCatalogUrl;
  end;

  RefreshCatalogInBackground;
end;

procedure TMainLauncherForm.SetInstallProgress(const AAppId: string; ASent, ATotal: Int64);
begin
  if ATotal > 0 then
  begin
    ProgressBar.Max := 1000;
    ProgressBar.Position := Round((ASent / ATotal) * 1000);
    StatusLabel.Caption := Format('Downloading %s: %d%%', [AAppId, Round((ASent / ATotal) * 100)]);
  end
  else
  begin
    ProgressBar.Style := pbstMarquee;
    StatusLabel.Caption := Format('Downloading %s: %d bytes', [AAppId, ASent]);
  end;
end;

procedure TMainLauncherForm.InstallButtonClick(Sender: TObject);
begin
  InstallSelectedAppInBackground;
end;

procedure TMainLauncherForm.UpdateButtonClick(Sender: TObject);
var
  App: TCatalogApp;
  InstalledVersion: string;
begin
  App := SelectedCatalogApp;
  if App = nil then
  begin
    MessageDlg('Select an app from the Store tab first.', mtInformation, [mbOK], 0);
    Exit;
  end;

  if not FInstalledVersions.TryGetValue(App.Id, InstalledVersion) then
  begin
    MessageDlg('That app is not installed; use Install instead.', mtInformation, [mbOK], 0);
    Exit;
  end;

  if SameText(InstalledVersion, App.Version) then
  begin
    MessageDlg('That app is already up to date.', mtInformation, [mbOK], 0);
    Exit;
  end;

  if TPortappixPackageManager.IsAppRunning(FRootPath, App.Id) then
  begin
    // Safe update: queue it; it installs once the app has fully exited.
    try
      FPackageManager.QueueUpdate(App);
      MessageDlg(Format('"%s" is running. The update to %s is queued and installs ' +
        'automatically after the app closes (or at the next launcher start). ' +
        'Data\<%s> is never touched.', [App.Id, App.Version, App.Id]),
        mtInformation, [mbOK], 0);
      LoadInstalledApps;
      UpdateTrayState;
    except
      on E: Exception do
      begin
        MarkOperationFailed;
        MessageDlg('Unable to queue the update: ' + E.Message, mtError, [mbOK], 0);
      end;
    end;
    Exit;
  end;

  InstallSelectedAppInBackground;
end;

procedure TMainLauncherForm.InstallSelectedAppInBackground;
var
  Selected: TCatalogApp;
  AppCopy: TCatalogApp;
  RootPath: string;
begin
  if FInstallInProgress then
  begin
    MessageDlg('An installation is already in progress.', mtInformation, [mbOK], 0);
    Exit;
  end;

  Selected := SelectedCatalogApp;
  if Selected = nil then
  begin
    MessageDlg('Select an app from the Store tab first.', mtInformation, [mbOK], 0);
    Exit;
  end;

  AppCopy := TCatalogApp.Create;
  AppCopy.Id := Selected.Id;
  AppCopy.Name := Selected.Name;
  AppCopy.Version := Selected.Version;
  AppCopy.Category := Selected.Category;
  AppCopy.Url := Selected.Url;
  AppCopy.Sha256 := Selected.Sha256;
  AppCopy.Size := Selected.Size;

  RootPath := FRootPath;
  FInstallInProgress := True;
  InstallButton.Enabled := False;
  UpdateButton.Enabled := False;
  ProgressBar.Style := pbstNormal;
  ProgressBar.Position := 0;
  SetStatus('Installing ' + AppCopy.Name + '...');

  TThread.CreateAnonymousThread(
    procedure
    var
      PackageManager: TPortappixPackageManager;
      LastQueuedAt: UInt64;
      ErrorMsg: string;
    begin
      LastQueuedAt := 0;
      PackageManager := TPortappixPackageManager.Create(RootPath);
      try
        try
          PackageManager.OnLog :=
            procedure(AMsg: string)
            begin
              QueueStatus(AMsg);
            end;
          PackageManager.InstallApp(AppCopy,
            procedure(const AAppId: string; ASent, ATotal: Int64; var AAbort: Boolean)
            var
              Now: UInt64;
            begin
              Now := GetTickCount64;
              if Now - LastQueuedAt < 100 then
                Exit;
              LastQueuedAt := Now;
              TThread.Queue(nil,
                procedure
                begin
                  SetInstallProgress(AAppId, ASent, ATotal);
                end);
            end);

          TThread.Queue(nil,
            procedure
            begin
              ProgressBar.Style := pbstNormal;
              ProgressBar.Position := ProgressBar.Max;
              SetStatus('Installed ' + AppCopy.Name + '.');
              LoadInstalledApps;
              MarkOperationSucceeded;
            end);
        except
          on E: Exception do
          begin
            ErrorMsg := E.Message;
            TThread.Queue(nil,
              procedure
              begin
                ProgressBar.Style := pbstNormal;
                ProgressBar.Position := 0;
                MarkOperationFailed;
                SetStatus('Install failed: ' + ErrorMsg);
                MessageDlg('Install failed: ' + ErrorMsg, mtError, [mbOK], 0);
              end);
          end;
        end;
      finally
        PackageManager.Free;
        TThread.Queue(nil,
          procedure
          begin
            FInstallInProgress := False;
            InstallButton.Enabled := True;
            UpdateButton.Enabled := True;
            ProgressBar.Style := pbstNormal;
            AppCopy.Free;
          end);
      end;
    end).Start;
end;

function TMainLauncherForm.AskConsent(const AAppId, ADescription,
  AManifestHash: string): Boolean;
begin
  Result := MessageDlg(
    'The app "' + AAppId + '" wants to make the following host changes:' + sLineBreak +
    sLineBreak + ADescription + sLineBreak + sLineBreak +
    'Allow this app to run? (Approval is remembered for this exact app.json.)',
    mtConfirmation, [mbYes, mbNo], 0) = mrYes;
end;

procedure TMainLauncherForm.btnImportAppClick(Sender: TObject);
var
  SourceFolder: string;
  AppsRoot: string;
  Importer: TPortappixImporter;
  Analysis: TPortappixSourceAnalysis;
begin
  if not dlgImportExe.Execute then
    Exit;

  SourceFolder := TPath.GetDirectoryName(dlgImportExe.FileName);
  AppsRoot := TPath.Combine(FRootPath, 'Apps');

  try
    Importer := TPortappixImporter.Create(FRootPath);
    try
      Importer.OnLog :=
        procedure(AMsg: string)
        begin
          QueueStatus(AMsg);
        end;
      Analysis := Importer.AnalyzeSource(SourceFolder);
      if Analysis.RequiresConfirmation then
        if MessageDlg(Format(
          'This folder contains %d file(s), %d byte(s)%s. Importing a drive root or a very ' +
          'large folder can take a long time and use a lot of disk space. Continue?',
          [Analysis.FileCount, Analysis.TotalBytes,
           IfThen(Analysis.IsDriveRoot, ' and is a drive root', '')]),
          mtWarning, [mbYes, mbNo], 0) <> mrYes then
          Exit;

      Importer.ImportToApps(SourceFolder, dlgImportExe.FileName, '', AppsRoot);
    finally
      Importer.Free;
    end;

    ShowMessage('App imported successfully! You can configure its Level 2 sandboxing in the new Apps folder if needed.');
    LoadInstalledApps;
    MarkOperationSucceeded;
  except
    on E: Exception do
    begin
      MarkOperationFailed;
      ShowMessage('Import failed: ' + E.Message);
    end;
  end;
end;

procedure TMainLauncherForm.CheckLauncherUpdateWatchdog;
var
  Manager: TPortappixUpdateManager;
  PendingVersion: string;
begin
  Manager := TPortappixUpdateManager.Create(FRootPath);
  try
    Manager.OnLog :=
      procedure(AMsg: string)
      begin
        QueueStatus(AMsg);
      end;
    if not Manager.NeedsRollbackOffer then
      Exit;

    PendingVersion := Manager.PendingUpdateVersion;
    if not FindCmdLineSwitch('accept-rollback') and not FindCmdLineSwitch('auto-rollback') then
    begin
      if MessageDlg(
        Format('A launcher update to %s was applied but the new version never ' +
          'confirmed that it started (no update_ok marker).' + sLineBreak + sLineBreak +
          'Restore the previous version from Launcher.exe.old now?',
          [PendingVersion]),
        mtWarning, [mbYes, mbNo], 0) <> mrYes then
      begin
        QueueStatus('Rollback declined; the offer reappears on the next start ' +
          'until the update is confirmed or Launcher.exe.old is deleted.');
        Exit;
      end;
    end;

    try
      Manager.RollbackToOldLauncher;
      // The previous launcher was started; this (failing) process exits.
      Halt(0);
    except
      on E: Exception do
      begin
        QueueStatus('Rollback failed: ' + E.Message);
      end;
    end;
  finally
    Manager.Free;
  end;
end;

procedure TMainLauncherForm.ApplyPendingUpdatesInBackground;
var
  RootPath: string;
begin
  if (FSettings = nil) or not FSettings.AutoApplyPendingUpdates then
    Exit;
  if FPackageManager = nil then
    Exit;
  if Length(FPackageManager.PendingUpdateIds) = 0 then
    Exit;

  RootPath := FRootPath;
  FInstallInProgress := True;
  InstallButton.Enabled := False;
  UpdateButton.Enabled := False;
  ProgressBar.Style := pbstMarquee;
  SetStatus('Applying queued updates...');

  TThread.CreateAnonymousThread(
    procedure
    var
      Manager: TPortappixPackageManager;
    begin
      Manager := TPortappixPackageManager.Create(RootPath);
      try
        Manager.OnLog :=
          procedure(AMsg: string)
          begin
            QueueStatus(AMsg);
          end;
        try
          Manager.ApplyPendingUpdates;
        except
          on E: Exception do
          begin
            TThread.Queue(nil,
              procedure
              begin
                MarkOperationFailed;
              end);
            QueueStatus('Applying queued updates failed: ' + E.Message);
          end;
        end;
      finally
        Manager.Free;
        TThread.Queue(nil,
          procedure
          begin
            FInstallInProgress := False;
            InstallButton.Enabled := True;
            UpdateButton.Enabled := True;
            ProgressBar.Style := pbstNormal;
            SetStatus('Queued updates processed.');
            LoadInstalledApps;
            UpdateTrayState;
          end);
      end;
    end).Start;
end;

procedure TMainLauncherForm.TraceButtonClick(Sender: TObject);
var
  ManifestPath: string;
begin
  ManifestPath := SelectedInstalledManifestPath;
  if ManifestPath = '' then
  begin
    MessageDlg('Select an installed app first.', mtInformation, [mbOK], 0);
    Exit;
  end;
  if FTraceInProgress then
  begin
    MessageDlg('A trace is already in progress.', mtInformation, [mbOK], 0);
    Exit;
  end;

  if MessageDlg(
    'Trace runs the selected app WITHOUT sandboxing so Portappix can record ' +
    'what it writes on this PC.' + sLineBreak + sLineBreak +
    'Only trace apps you trust, ideally inside a virtual machine or ' +
    'Windows Sandbox. Run the trace now?',
    mtWarning, [mbYes, mbNo], 0) <> mrYes then
    Exit;

  TraceSelectedAppInBackground(ManifestPath);
end;

procedure TMainLauncherForm.TraceSelectedAppInBackground(const AManifestPath: string);
var
  RootPath: string;
begin
  RootPath := FRootPath;
  FTraceInProgress := True;
  TraceButton.Enabled := False;
  ProgressBar.Style := pbstMarquee;
  SetStatus('Tracing (no sandbox; the app can write to this PC)...');

  TThread.CreateAnonymousThread(
    procedure
    var
      Runner: TPortappixTraceRunner;
      TraceResult: TPortappixTraceResult;
    begin
      try
        try
          Runner := TPortappixTraceRunner.Create(RootPath, AManifestPath);
          try
            Runner.OnLog :=
              procedure(AMsg: string)
              begin
                QueueStatus(AMsg);
              end;
            TraceResult := Runner.Execute;
            TThread.Queue(nil,
              procedure
              begin
                SetStatus(Format('Trace finished (app exit code %d). Report: %s',
                  [TraceResult.AppExitCode, TraceResult.ReportDirectory]));
                MarkOperationSucceeded;
              end);
          finally
            Runner.Free;
          end;
        except
          on E: Exception do
          begin
            var ErrorMsg := E.Message;
            TThread.Queue(nil,
              procedure
              begin
                MarkOperationFailed;
                SetStatus('Trace failed: ' + ErrorMsg);
                MessageDlg('Trace failed: ' + ErrorMsg, mtError, [mbOK], 0);
              end);
          end;
        end;
      finally
        TThread.Queue(nil,
          procedure
          begin
            FTraceInProgress := False;
            TraceButton.Enabled := True;
            ProgressBar.Style := pbstNormal;
          end);
      end;
    end).Start;
end;

procedure TMainLauncherForm.TrayIconDblClick(Sender: TObject);
begin
  ShowMainForm;
end;

end.
