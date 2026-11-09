unit Portappix.TrayUI;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  System.UITypes,
  System.Generics.Collections,
  System.Generics.Defaults,
  Vcl.Forms,
  Vcl.Menus,
  Vcl.ExtCtrls,
  Vcl.Dialogs,
  Portappix.Common,
  Portappix.Consent,
  Portappix.Manifest,
  Portappix.Runner,
  Portappix.State;

type
  TConsentRequest = reference to function(const AAppId, ADescription,
    AManifestHash: string): Boolean;

  TPortappixTrayUI = class
  private
    FTrayIcon: TTrayIcon;
    FPopupMenu: TPopupMenu;
    FRootPath: string;
    FAppsDir: string;
    FJournal: IPortappixJournal;
    FShowForm: TProc;
    FRefreshForm: TProc;
    FExitRequested: TProc;
    FConsentRequest: TConsentRequest;
    FLog: TProc<string>;
    FRunning: Integer;
    procedure Log(const AMessage: string);
    procedure EnsurePopupMenu;
    procedure ClearMenuItems;
    procedure BuildStaticItems;
    procedure BuildCategoryMenus;
    procedure AppMenuClick(Sender: TObject);
    procedure OpenMenuClick(Sender: TObject);
    procedure RefreshMenuClick(Sender: TObject);
    procedure ExitMenuClick(Sender: TObject);
    procedure RunAppInBackground(const AManifestPath: string);
    procedure NotifyRefresh;
    function CreateCategoryMenu(const AMenu: TPopupMenu; const ACategory: string;
      const ACategories: TDictionary<string, TMenuItem>): TMenuItem;
  public
    constructor Create(ATrayIcon: TTrayIcon; const ARootPath: string = '';
      const AJournal: IPortappixJournal = nil);
    destructor Destroy; override;
    procedure RebuildMenu;
    procedure LaunchApp(const AManifestPath: string);
    property RootPath: string read FRootPath;
    property AppsDirectory: string read FAppsDir;
    property RunningCount: Integer read FRunning;
    property OnShowForm: TProc read FShowForm write FShowForm;
    property OnRefreshForm: TProc read FRefreshForm write FRefreshForm;
    property OnExitRequested: TProc read FExitRequested write FExitRequested;
    property OnConsentRequired: TConsentRequest read FConsentRequest write FConsentRequest;
    property OnLog: TProc<string> read FLog write FLog;
  end;

implementation

type
  TInstalledAppEntry = class
  public
    ManifestPath: string;
    Name: string;
    Category: string;
  end;

constructor TPortappixTrayUI.Create(ATrayIcon: TTrayIcon; const ARootPath: string;
  const AJournal: IPortappixJournal);
begin
  inherited Create;
  FTrayIcon := ATrayIcon;
  FJournal := AJournal;
  FRootPath := ResolveRootPath(ARootPath);
  FAppsDir := TPath.Combine(FRootPath, 'Apps');
  EnsurePopupMenu;
  RebuildMenu;
end;

destructor TPortappixTrayUI.Destroy;
begin
  if FTrayIcon <> nil then
    FTrayIcon.PopupMenu := nil;
  FPopupMenu.Free;
  FJournal := nil;
  inherited;
end;

procedure TPortappixTrayUI.Log(const AMessage: string);
begin
  if Assigned(FLog) then
    FLog(AMessage);
end;

procedure TPortappixTrayUI.EnsurePopupMenu;
begin
  FPopupMenu := TPopupMenu.Create(nil);
  if FTrayIcon <> nil then
    FTrayIcon.PopupMenu := FPopupMenu;
end;

procedure TPortappixTrayUI.ClearMenuItems;
begin
  for var Index := FPopupMenu.Items.Count - 1 downto 0 do
    FPopupMenu.Items[Index].Free;
  FPopupMenu.Items.Clear;
end;

procedure TPortappixTrayUI.BuildStaticItems;
var
  Item: TMenuItem;
begin
  Item := TMenuItem.Create(FPopupMenu);
  Item.Caption := 'Open Portappix';
  Item.OnClick := OpenMenuClick;
  FPopupMenu.Items.Add(Item);

  Item := TMenuItem.Create(FPopupMenu);
  Item.Caption := 'Refresh Apps';
  Item.OnClick := RefreshMenuClick;
  FPopupMenu.Items.Add(Item);

  Item := TMenuItem.Create(FPopupMenu);
  Item.Caption := '-';
  FPopupMenu.Items.Add(Item);
end;

function TPortappixTrayUI.CreateCategoryMenu(const AMenu: TPopupMenu;
  const ACategory: string; const ACategories: TDictionary<string, TMenuItem>): TMenuItem;
begin
  if ACategories.TryGetValue(ACategory, Result) then
    Exit;

  Result := TMenuItem.Create(AMenu);
  Result.Caption := ACategory;
  AMenu.Items.Add(Result);
  ACategories.Add(ACategory, Result);
end;

procedure TPortappixTrayUI.BuildCategoryMenus;
var
  Categories: TDictionary<string, TMenuItem>;
  Entries: TObjectList<TInstalledAppEntry>;
  CategoryItem: TMenuItem;
  AppItem: TMenuItem;
  Manifest: TPortappixManifest;
  Separator: TMenuItem;
begin
  Categories := TDictionary<string, TMenuItem>.Create(TIStringComparer.OrdinalIgnoreCase);
  Entries := TObjectList<TInstalledAppEntry>.Create(True);
  try
    if TDirectory.Exists(FAppsDir) then
      for var AppDir in TDirectory.GetDirectories(FAppsDir) do
      begin
        if IsTransientAppFolder(TPath.GetFileName(AppDir)) then
          Continue;

        var ManifestPath := TPath.Combine(AppDir, 'app.json');
        if not TFile.Exists(ManifestPath) then
          Continue;

        try
          Manifest := TPortappixManifest.LoadFromFile(ManifestPath);
          try
            if not SameText(Manifest.Id, TPath.GetFileName(AppDir)) then
            begin
              Log(Format('Skipping "%s": manifest id "%s" does not match its folder name.',
                [ManifestPath, Manifest.Id]));
              Continue;
            end;

            var Entry := TInstalledAppEntry.Create;
            Entry.ManifestPath := ManifestPath;
            Entry.Name := Manifest.Name;
            Entry.Category := Manifest.Category;
            Entries.Add(Entry);
          finally
            Manifest.Free;
          end;
        except
          on E: Exception do
            Log(Format('Unable to load "%s": %s', [ManifestPath, E.Message]));
        end;
      end;

    Entries.Sort(TComparer<TInstalledAppEntry>.Construct(
      function(const Left, Right: TInstalledAppEntry): Integer
      begin
        Result := CompareText(Left.Category, Right.Category);
        if Result = 0 then
          Result := CompareText(Left.Name, Right.Name);
      end));

    for var Entry in Entries do
    begin
      CategoryItem := CreateCategoryMenu(FPopupMenu, Entry.Category, Categories);
      AppItem := TMenuItem.Create(FPopupMenu);
      AppItem.Caption := Entry.Name;
      AppItem.Hint := Entry.ManifestPath;
      AppItem.OnClick := AppMenuClick;
      CategoryItem.Add(AppItem);
    end;

    if Entries.Count = 0 then
    begin
      AppItem := TMenuItem.Create(FPopupMenu);
      AppItem.Caption := '(No installed apps)';
      AppItem.Enabled := False;
      FPopupMenu.Items.Add(AppItem);
    end;

    Separator := TMenuItem.Create(FPopupMenu);
    Separator.Caption := '-';
    FPopupMenu.Items.Add(Separator);
  finally
    Entries.Free;
    Categories.Free;
  end;
end;

procedure TPortappixTrayUI.RebuildMenu;
var
  ExitItem: TMenuItem;
begin
  if FPopupMenu = nil then
    Exit;

  FPopupMenu.Items.BeginUpdate;
  try
    ClearMenuItems;
    BuildStaticItems;
    BuildCategoryMenus;

    ExitItem := TMenuItem.Create(FPopupMenu);
    ExitItem.Caption := 'Exit';
    ExitItem.OnClick := ExitMenuClick;
    FPopupMenu.Items.Add(ExitItem);
  finally
    FPopupMenu.Items.EndUpdate;
  end;
end;

procedure TPortappixTrayUI.NotifyRefresh;
begin
  if Assigned(FRefreshForm) then
    TThread.Queue(nil, procedure begin FRefreshForm(); end);
end;

procedure TPortappixTrayUI.AppMenuClick(Sender: TObject);
var
  Item: TMenuItem;
begin
  if not (Sender is TMenuItem) then
    Exit;
  Item := TMenuItem(Sender);
  if Item.Hint = '' then
    Exit;
  LaunchApp(Item.Hint);
end;

procedure TPortappixTrayUI.OpenMenuClick(Sender: TObject);
begin
  if Assigned(FShowForm) then
    FShowForm();
end;

procedure TPortappixTrayUI.RefreshMenuClick(Sender: TObject);
begin
  RebuildMenu;
  NotifyRefresh;
end;

procedure TPortappixTrayUI.ExitMenuClick(Sender: TObject);
begin
  if Assigned(FExitRequested) then
    FExitRequested()
  else
    Application.Terminate;
end;

procedure TPortappixTrayUI.LaunchApp(const AManifestPath: string);
begin
  RunAppInBackground(AManifestPath);
end;

procedure TPortappixTrayUI.RunAppInBackground(const AManifestPath: string);
var
  ManifestPath: string;
  RootPath: string;
  Journal: IPortappixJournal;
begin
  ManifestPath := AManifestPath;
  RootPath := FRootPath;
  Journal := FJournal;

  InterlockedIncrement(FRunning);
  TThread.CreateAnonymousThread(
    procedure
    var
      Manifest: TPortappixManifest;
      Consent: TPortappixConsent;
      Runner: TPortableAppRunner;
      LockHandle: THandle;
      Description: string;
      ManifestHash: string;
      Approved: Boolean;
    begin
      LockHandle := 0;
      try
        try
          Manifest := TPortappixManifest.LoadFromFile(ManifestPath);
          try
            if not SameText(Manifest.Id,
              TPath.GetFileName(TPath.GetDirectoryName(ManifestPath))) then
            begin
              TThread.Synchronize(nil,
                procedure
                begin
                  MessageDlg(Format('Cannot run "%s": manifest id "%s" does not match its folder.',
                    [Manifest.Name, Manifest.Id]), mtError, [mbOK], 0);
                end);
              Exit;
            end;

            if not TryAcquireMutex(AppMutexName(RootPath, Manifest.Id), LockHandle) then
            begin
              TThread.Synchronize(nil,
                procedure
                begin
                  MessageDlg(Format('%s is already running.', [Manifest.Name]),
                    mtInformation, [mbOK], 0);
                end);
              Exit;
            end;

            Consent := TPortappixConsent.Create(RootPath);
            try
              if Consent.NeedsConsent(Manifest) then
              begin
                Description := Consent.ApprovalDescription(Manifest);
                ManifestHash := Consent.ManifestHash(Manifest);
                Approved := False;
                TThread.Synchronize(nil,
                  procedure
                  begin
                    if Assigned(FConsentRequest) then
                      Approved := FConsentRequest(Manifest.Id, Description, ManifestHash);
                  end);
                if not Approved then
                begin
                  TThread.Synchronize(nil,
                    procedure begin Log('Launch cancelled: consent was not granted.'); end);
                  Exit;
                end;
                Consent.Approve(Manifest);
              end;
            finally
              Consent.Free;
            end;

            Runner := TPortableAppRunner.Create(ManifestPath, Journal, RootPath);
            try
              Runner.OnLog :=
                procedure(const Message: string)
                begin
                  TThread.Queue(nil, procedure begin Log(Message); end);
                end;
              Runner.Run;
            finally
              Runner.Free;
            end;
          finally
            Manifest.Free;
          end;
        except
          on E: Exception do
            TThread.Synchronize(nil,
              procedure
              begin
                Log('Unable to launch app: ' + E.Message);
                MessageDlg('Unable to launch app: ' + E.Message, mtError, [mbOK], 0);
              end);
        end;
      finally
        ReleaseMutexHandle(LockHandle);
        InterlockedDecrement(FRunning);
      end;
    end).Start;
end;

end.
