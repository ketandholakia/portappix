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
  Portappix.Manifest,
  Portappix.Runner,
  Portappix.State;

type
  TPortappixTrayUI = class
  private
    FTrayIcon: TTrayIcon;
    FPopupMenu: TPopupMenu;
    FRootPath: string;
    FAppsDir: string;
    FJournal: TPortappixJournal;
    FShowForm: TProc;
    FRefreshForm: TProc;
    FLog: TProc<string>;
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
      const AJournal: TPortappixJournal = nil);
    destructor Destroy; override;
    procedure RebuildMenu;
    procedure LaunchApp(const AManifestPath: string);
    property RootPath: string read FRootPath;
    property AppsDirectory: string read FAppsDir;
    property OnShowForm: TProc read FShowForm write FShowForm;
    property OnRefreshForm: TProc read FRefreshForm write FRefreshForm;
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

function LauncherDirectory: string;
begin
  Result := TPath.GetDirectoryName(ParamStr(0));
  if Result = '' then
    Result := GetCurrentDir;
end;

function IsRelativePath(const APath: string): Boolean;
begin
  if APath = '' then
    Exit(True);
  if (Length(APath) >= 2) and (APath[2] = ':') then
    Exit(False);
  if (Length(APath) >= 2) and (APath[1] = '\') and (APath[2] = '\') then
    Exit(False);
  if APath[1] = '\' then
    Exit(False);
  Result := True;
end;

function ResolveRootPath(const APath: string): string;
begin
  if APath = '' then
    Exit(TPath.GetFullPath(LauncherDirectory));
  if IsRelativePath(APath) then
    Result := TPath.GetFullPath(TPath.Combine(LauncherDirectory, APath))
  else
    Result := TPath.GetFullPath(APath);
end;

constructor TPortappixTrayUI.Create(ATrayIcon: TTrayIcon; const ARootPath: string;
  const AJournal: TPortappixJournal);
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
        var ManifestPath := TPath.Combine(AppDir, 'app.json');
        if not TFile.Exists(ManifestPath) then
          Continue;

        try
          Manifest := TPortappixManifest.LoadFromFile(ManifestPath);
          try
            var Entry := TInstalledAppEntry.Create;
            Entry.ManifestPath := ManifestPath;
            Entry.Name := Manifest.Name;
            Entry.Category := 'Apps';
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
  Journal: TPortappixJournal;
begin
  ManifestPath := AManifestPath;
  RootPath := FRootPath;
  Journal := FJournal;

  TThread.CreateAnonymousThread(
    procedure
    var
      Runner: TPortableAppRunner;
    begin
      try
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
      except
        on E: Exception do
          TThread.Queue(nil,
            procedure
            begin
              Log('Unable to launch app: ' + E.Message);
              MessageDlg('Unable to launch app: ' + E.Message, mtError, [mbOK], 0);
            end);
      end;
    end).Start;
end;

end.
