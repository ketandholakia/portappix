unit Portappix.Icons;

{
  Application and notification-area icons for Portappix.

  The artwork lives in the repository folder "portappix_icons" and is
  embedded into the executable by src\PortappixIcons.rc (compiled to
  src\PortappixIcons.res and referenced from Launcher.dpr). The resources
  are:

    1  ICON    portappix.ico                application / launcher icon
    2  ICON    portappix-tray-normal.ico    tray: idle, apps installed
    3  ICON    portappix-tray-running.ico   tray: an app is running
    4  ICON    portappix-tray-paused.ico    tray: an update is pending
    5  ICON    portappix-tray-error.ico     tray: the last operation failed
    6  ICON    portappix-tray-inactive.ico  tray: no apps installed
    10 RCDATA  portappix-app.png            application artwork (high resolution)

  Everything here degrades gracefully: when a resource is missing (for
  example in a build made without the icon resource) the loaders return
  nil and the caller simply keeps the VCL default icon. The launcher must
  never fail to start because of a missing icon.
}

interface

uses
  Winapi.Windows,
  System.Classes,
  Vcl.Graphics;

type
  /// Visual state of the notification-area icon.
  TPortappixTrayIconState = (
    tisInactive,  // no apps installed
    tisNormal,    // apps installed, launcher idle
    tisRunning,   // at least one app is running
    tisPaused,    // an update is pending and held back
    tisError      // the last operation failed
  );

  TPortappixIcons = class
  public
    /// The application icon (32x32), or nil when the resource is missing.
    class function ApplicationIcon: TIcon;
    /// The notification-area icon for a state, or nil.
    class function TrayIcon(const AState: TPortappixTrayIconState): TIcon;
    /// The high-resolution application artwork as a bitmap, or nil.
    class function AppImage: TBitmap;
    /// True when the icon resources are present in this build.
    class function HasIcons: Boolean;
    /// Copies the application icon into Application.Icon (taskbar, window
    /// and Alt-Tab entries). Safe to call when the resource is missing.
    class procedure ApplyApplicationIcon;
  end;

implementation

uses
  Vcl.Forms;

const
  PortappixIconResourceApp          = 1;
  PortappixIconResourceTrayNormal   = 2;
  PortappixIconResourceTrayRunning  = 3;
  PortappixIconResourceTrayPaused   = 4;
  PortappixIconResourceTrayError    = 5;
  PortappixIconResourceTrayInactive = 6;
  PortappixAppImageResourceId       = 10;

/// Loads one icon resource at the requested pixel size. The caller owns
/// the returned TIcon (and the HICON it owns).
function LoadResourceIcon(const AResourceId: Integer;
  const ASize: Integer): TIcon;
var
  IconHandle: HICON;
begin
  Result := nil;
  IconHandle := LoadImage(hInstance, MakeIntResource(AResourceId), IMAGE_ICON,
    ASize, ASize, LR_DEFAULTSIZE);
  if IconHandle = 0 then
    Exit;
  try
    Result := TIcon.Create;
    // TIcon.Handle takes ownership of the HICON.
    Result.Handle := IconHandle;
  except
    DeleteObject(IconHandle);
    Result.Free;
    Result := nil;
  end;
end;

class function TPortappixIcons.ApplicationIcon: TIcon;
begin
  Result := LoadResourceIcon(PortappixIconResourceApp, 32);
end;

class function TPortappixIcons.TrayIcon(
  const AState: TPortappixTrayIconState): TIcon;
var
  ResourceId: Integer;
  Size: Integer;
begin
  case AState of
    tisNormal:   ResourceId := PortappixIconResourceTrayNormal;
    tisRunning:  ResourceId := PortappixIconResourceTrayRunning;
    tisPaused:   ResourceId := PortappixIconResourceTrayPaused;
    tisError:    ResourceId := PortappixIconResourceTrayError;
    tisInactive: ResourceId := PortappixIconResourceTrayInactive;
  else
    ResourceId := PortappixIconResourceTrayNormal;
  end;
  // The notification area is 16 logical pixels at 100% scaling; pick the
  // matching artwork for the display so the icon stays crisp.
  Size := 16;
  case Screen.PixelsPerInch of
    120: Size := 20;
    144: Size := 24;
    192: Size := 32;
  end;
  Result := LoadResourceIcon(ResourceId, Size);
end;

class function TPortappixIcons.AppImage: TBitmap;
var
  ResHandle: HRSRC;
  GlobalHandle: HGLOBAL;
  DataPtr: PByte;
  DataSize: DWORD;
  Stream: TMemoryStream;
  WicImage: TWICImage;
begin
  Result := nil;
  Stream := nil;
  WicImage := nil;
  try
    // RT_RCDATA is the predefined ORDINAL type 10: the type must be passed
    // as MAKEINTRESOURCE(RT_RCDATA), not as the string 'RCDATA' (a string
    // would look for a user-defined type and never match).
    ResHandle := FindResource(hInstance,
      MakeIntResource(PortappixAppImageResourceId), MakeIntResource(RT_RCDATA));
    if ResHandle = 0 then
      Exit;
    GlobalHandle := LoadResource(hInstance, ResHandle);
    if GlobalHandle = 0 then
      Exit;
    DataSize := SizeofResource(hInstance, ResHandle);
    DataPtr := PByte(LockResource(GlobalHandle));
    if (DataPtr = nil) or (DataSize = 0) then
      Exit;
    Stream := TMemoryStream.Create;
    Stream.WriteBuffer(DataPtr^, DataSize);
    Stream.Position := 0;
    // The artwork is a PNG: the VCL decodes it through its WIC support
    // (the same route the VCL uses for PNG-compressed icon entries).
    WicImage := TWICImage.Create;
    WicImage.LoadFromStream(Stream);
    Result := TBitmap.Create;
    Result.Assign(WicImage);
    if (Result.Width <= 0) or (Result.Height <= 0) then
    begin
      Result.Free;
      Result := nil;
    end;
  except
    Result.Free;
    Result := nil;
  end;
  WicImage.Free;
  Stream.Free;
end;

class function TPortappixIcons.HasIcons: Boolean;
var
  Icon: TIcon;
begin
  Icon := ApplicationIcon;
  Result := Icon <> nil;
  Icon.Free;
end;

class procedure TPortappixIcons.ApplyApplicationIcon;
var
  Icon: TIcon;
begin
  Icon := ApplicationIcon;
  if Icon = nil then
    Exit;
  try
    // Application.Icon copies the image; the temporary icon is ours.
    Application.Icon.Assign(Icon);
  finally
    Icon.Free;
  end;
end;

end.
