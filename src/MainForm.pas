unit MainForm;

interface

uses
  Winapi.Windows,
  Winapi.Messages,
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  System.UITypes,
  Vcl.Graphics,
  Vcl.Controls,
  Vcl.Forms,
  Vcl.Dialogs,
  Vcl.ComCtrls,
  Vcl.StdCtrls,
  Vcl.ExtCtrls,
  Vcl.Menus,
  Portappix.Manifest,
  Portappix.Catalog,
  Portappix.PackageManager,
  Portappix.State,
  Portappix.TrayUI;

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
    SearchEdit: TEdit;
    SearchLabel: TLabel;
    RefreshCatalogButton: TButton;
    InstallButton: TButton;
    ProgressBar: TProgressBar;
    StatusLabel: TLabel;
    TrayIcon: TTrayIcon;
    procedure FormCreate(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: Boolean);
    procedure FormDestroy(Sender: TObject);
    procedure RefreshInstalledButtonClick(Sender: TObject);
    procedure LaunchButtonClick(Sender: TObject);
    procedure UninstallButtonClick(Sender: TObject);
    procedure RefreshCatalogButtonClick(Sender: TObject);
    procedure InstallButtonClick(Sender: TObject);
    procedure SearchEditChange(Sender: TObject);
    procedure TrayIconDblClick(Sender: TObject);
  private
    FRootPath: string;
    FAppsDir: string;
    FCatalogCacheFile: string;
    FCatalogUrl: string;
    FJournal: TPortappixJournal;
    FTrayUI: TPortappixTrayUI;
    FCatalog: TPortappixCatalog;
    FPackageManager: TPortappixPackageManager;
    FInstallInProgress: Boolean;
    FAllowClose: Boolean;
    procedure InitializePaths;
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
    procedure SetStatus(const AMessage: string);
    procedure QueueStatus(const AMessage: string);
    procedure SetInstallProgress(const AAppId: string; ASent, ATotal: Int64);
    procedure InstallSelectedAppInBackground;
  public
    property CatalogUrl: string read FCatalogUrl write FCatalogUrl;
  end;

var
  MainLauncherForm: TMainLauncherForm;

implementation

{$R *.dfm}

function LauncherDirectory: string;
begin
  Result := TPath.GetDirectoryName(ParamStr(0));
  if Result = '' then
    Result := GetCurrentDir;
end;

procedure TMainLauncherForm.FormCreate(Sender: TObject);
begin
  FInstallInProgress := False;
  FAllowClose := False;
  // Set CatalogUrl to your hosted catalog.json URL (or leave empty to use local cache only).
  FCatalogUrl := '';
  InitializePaths;
  InitializeRuntime;      // includes TPortappixJournal.RecoverPendingCleanups (boot)
  InitializeTray;
  LoadInstalledApps;
  LoadCatalogFromCache;   // instant local cache
  RefreshCatalogInBackground; // fetch latest catalog in background thread
end;

procedure TMainLauncherForm.InitializePaths;
begin
  FRootPath := TPath.GetFullPath(LauncherDirectory);
  FAppsDir := TPath.Combine(FRootPath, 'Apps');
  FCatalogCacheFile := TPath.Combine(TPath.Combine(FRootPath, 'Cache'), 'catalog.json');
end;

procedure TMainLauncherForm.InitializeRuntime;
begin
  ForceDirectories(FAppsDir);
  ForceDirectories(TPath.GetDirectoryName(FCatalogCacheFile));

  FJournal := TPortappixJournal.Create(FRootPath);
  FJournal.OnLog := procedure(const Message: string) begin QueueStatus(Message); end;
  try
    FJournal.RecoverPendingCleanups;
  except
    on E: Exception do
      QueueStatus('Startup recovery reported an error: ' + E.Message);
  end;

  FCatalog := TPortappixCatalog.Create;
  FPackageManager := TPortappixPackageManager.Create(FRootPath);
  FPackageManager.OnLog := procedure(const Message: string) begin QueueStatus(Message); end;
end;

procedure TMainLauncherForm.InitializeTray;
begin
  TrayIcon.Visible := True;
  FTrayUI := TPortappixTrayUI.Create(TrayIcon, FRootPath, FJournal);
  FTrayUI.OnShowForm := procedure begin TThread.Queue(nil, procedure begin ShowMainForm; end); end;
  FTrayUI.OnRefreshForm := procedure begin TThread.Queue(nil, procedure begin LoadInstalledApps; end); end;
  FTrayUI.OnLog := procedure(const Message: string) begin QueueStatus(Message); end;
end;

procedure TMainLauncherForm.FormCloseQuery(Sender: TObject; var CanClose: Boolean);
begin
  CanClose := FAllowClose;
  if not FAllowClose then
    HideToTray;
end;

procedure TMainLauncherForm.FormDestroy(Sender: TObject);
begin
  for var Index := 0 to InstalledListView.Items.Count - 1 do
    if InstalledListView.Items[Index].Data <> nil then
      StrDispose(PChar(InstalledListView.Items[Index].Data));

  FTrayUI.Free;
  FPackageManager.Free;
  FCatalog.Free;
  FJournal.Free;
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
begin
  TThread.Queue(nil, procedure begin SetStatus(AMessage); end);
end;


procedure TMainLauncherForm.LoadInstalledApps;
var
  Item: TListItem;
  Manifest: TPortappixManifest;
begin
  for var Index := 0 to InstalledListView.Items.Count - 1 do
    if InstalledListView.Items[Index].Data <> nil then
      StrDispose(PChar(InstalledListView.Items[Index].Data));

  InstalledListView.Items.BeginUpdate;
  try
    InstalledListView.Clear;
    if not TDirectory.Exists(FAppsDir) then
      Exit;

    for var AppDir in TDirectory.GetDirectories(FAppsDir) do
    begin
      var ManifestPath := TPath.Combine(AppDir, 'app.json');
      if not TFile.Exists(ManifestPath) then
        Continue;
      try
        Manifest := TPortappixManifest.LoadFromFile(ManifestPath);
        try
          Item := InstalledListView.Items.Add;
          Item.Caption := Manifest.Name;
          Item.SubItems.Add(Manifest.Id);
          Item.SubItems.Add(AppDir);
          Item.Data := Pointer(StrNew(PChar(ManifestPath)));
        finally
          Manifest.Free;
        end;
      except
        on E: Exception do
          QueueStatus(Format('Unable to read "%s": %s', [ManifestPath, E.Message]));
      end;
    end;
  finally
    InstalledListView.Items.EndUpdate;
  end;

  if Assigned(FTrayUI) then
    FTrayUI.RebuildMenu;
end;

function TMainLauncherForm.SelectedInstalledManifestPath: string;
var
  Item: TListItem;
begin
  Result := '';
  Item := InstalledListView.Selected;
  if (Item = nil) or (Item.Data = nil) then
    Exit;
  Result := string(PChar(Item.Data));
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
begin
  Item := InstalledListView.Selected;
  if (Item = nil) or (Item.SubItems.Count < 2) then
  begin
    MessageDlg('Select an installed app to uninstall.', mtInformation, [mbOK], 0);
    Exit;
  end;

  AppDir := Item.SubItems[1];
  if not TDirectory.Exists(AppDir) then
  begin
    QueueStatus('App directory does not exist: ' + AppDir);
    Exit;
  end;

  if MessageDlg('Uninstall "' + Item.Caption + '"? This removes Apps\<id> but leaves Data\<id> intact.',
    mtConfirmation, [mbYes, mbNo], 0) <> mrYes then
    Exit;

  try
    TDirectory.Delete(AppDir, True);
    QueueStatus('Uninstalled ' + Item.Caption + '. Data was preserved.');
    LoadInstalledApps;
  except
    on E: Exception do
      MessageDlg('Unable to uninstall app: ' + E.Message, mtError, [mbOK], 0);
  end;
end;

procedure TMainLauncherForm.RefreshInstalledButtonClick(Sender: TObject);
begin
  LoadInstalledApps;
end;

procedure TMainLauncherForm.LoadCatalogFromCache;
begin
  try
    if TFile.Exists(FCatalogCacheFile) then
    begin
      FCatalog.LoadFromFile(FCatalogCacheFile);
      PopulateStoreList(SearchEdit.Text);
      SetStatus('Loaded catalog cache.');
    end
    else
      SetStatus('No catalog cache found.');
  except
    on E: Exception do
      SetStatus('Unable to load catalog cache: ' + E.Message);
  end;
end;

procedure TMainLauncherForm.PopulateStoreList(const AFilter: string);
var
  FilterText: string;
  Item: TListItem;
begin
  FilterText := AFilter.Trim.ToLower;
  StoreListView.Items.BeginUpdate;
  try
    StoreListView.Clear;
    for var App in FCatalog.Apps do
    begin
      if (FilterText <> '') and
         not App.Name.ToLower.Contains(FilterText) and
         not App.Id.ToLower.Contains(FilterText) and
         not App.Category.ToLower.Contains(FilterText) then
        Continue;

      Item := StoreListView.Items.Add;
      Item.Caption := App.Name;
      Item.SubItems.Add(App.Id);
      Item.SubItems.Add(App.Version);
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
  RootPath: string;
  CacheFile: string;
begin
  CatalogUrl := FCatalogUrl.Trim;
  if CatalogUrl = '' then
    Exit;

  RootPath := FRootPath;
  CacheFile := FCatalogCacheFile;
  QueueStatus('Refreshing catalog...');

  TThread.CreateAnonymousThread(
    procedure
    var
      Catalog: TPortappixCatalog;
      Json: string;
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
              except
                on E: Exception do
                  SetStatus('Unable to apply catalog update: ' + E.Message);
              end;
            end);
        except
          on E: Exception do
            TThread.Queue(nil,
              procedure
              begin
                SetStatus('Unable to refresh catalog: ' + E.Message);
              end);
        end;
      finally
        Catalog.Free;
      end;
    end).Start;
end;

procedure TMainLauncherForm.RefreshCatalogButtonClick(Sender: TObject);
begin
  if FCatalogUrl.Trim = '' then
  begin
    MessageDlg('Set CatalogUrl before refreshing the store catalog.', mtInformation, [mbOK], 0);
    Exit;
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
  ProgressBar.Style := pbstNormal;
  ProgressBar.Position := 0;
  SetStatus('Installing ' + AppCopy.Name + '...');

  TThread.CreateAnonymousThread(
    procedure
    var
      PackageManager: TPortappixPackageManager;
    begin
      PackageManager := TPortappixPackageManager.Create(RootPath);
      try
        try
          PackageManager.OnLog := procedure(const Message: string) begin QueueStatus(Message); end;
          PackageManager.InstallApp(AppCopy,
            procedure(const AAppId: string; ASent, ATotal: Int64; var AAbort: Boolean)
            begin
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
            end);
        except
          on E: Exception do
            TThread.Queue(nil,
              procedure
              begin
                ProgressBar.Style := pbstNormal;
                ProgressBar.Position := 0;
                SetStatus('Install failed: ' + E.Message);
                MessageDlg('Install failed: ' + E.Message, mtError, [mbOK], 0);
              end);
        end;
      finally
        PackageManager.Free;
        TThread.Queue(nil,
          procedure
          begin
            FInstallInProgress := False;
            InstallButton.Enabled := True;
            ProgressBar.Style := pbstNormal;
            AppCopy.Free;
          end);
      end;
    end).Start;
end;

procedure TMainLauncherForm.TrayIconDblClick(Sender: TObject);
begin
  ShowMainForm;
end;

end.
