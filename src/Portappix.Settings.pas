unit Portappix.Settings;

{
  Launcher settings persisted as Cache\settings.json inside the launcher root.
  Loading is tolerant: a missing or corrupt file yields defaults, and saving
  is atomic. UI code owns when to show dialogs; this class only stores values.
}

interface

uses
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  System.JSON,
  Portappix.Common;

type
  TPortappixSettings = class
  private
    FRootPath: string;
    FUpdateUrl: string;
    FAutoCheckUpdates: Boolean;
    FAutoApplyPendingUpdates: Boolean;
    function SettingsFile: string;
  public
    constructor Create(const ARootPath: string = '');
    procedure Load;
    procedure Save;
    function SaveOrUpdate: Boolean;
    property UpdateUrl: string read FUpdateUrl write FUpdateUrl;
    property AutoCheckUpdates: Boolean read FAutoCheckUpdates write FAutoCheckUpdates;
    property AutoApplyPendingUpdates: Boolean
      read FAutoApplyPendingUpdates write FAutoApplyPendingUpdates;
  end;

implementation

constructor TPortappixSettings.Create(const ARootPath: string);
begin
  inherited Create;
  FRootPath := ResolveRootPath(ARootPath);
  FUpdateUrl := '';
  FAutoCheckUpdates := False;
  FAutoApplyPendingUpdates := True;
end;

function TPortappixSettings.SettingsFile: string;
begin
  Result := TPath.Combine(TPath.Combine(FRootPath, 'Cache'), 'settings.json');
end;

procedure TPortappixSettings.Load;
var
  JsonValue: TJSONValue;
  UrlValue: TJSONValue;
  CheckValue: TJSONValue;
  PendingValue: TJSONValue;
begin
  // Defaults; everything below only overrides what is actually present.
  FUpdateUrl := '';
  FAutoCheckUpdates := False;
  FAutoApplyPendingUpdates := True;

  if not TFile.Exists(SettingsFile) then
    Exit;

  try
    JsonValue := TJSONObject.ParseJSONValue(
      TFile.ReadAllText(SettingsFile, TEncoding.UTF8));
    try
      if JsonValue = nil then
        Exit;

      UrlValue := JsonValue.FindValue('updateUrl');
      if UrlValue is TJSONString then
        FUpdateUrl := TJSONString(UrlValue).Value.Trim;

      CheckValue := JsonValue.FindValue('autoCheckUpdates');
      if CheckValue is TJSONBool then
        FAutoCheckUpdates := TJSONBool(CheckValue).AsBoolean;

      PendingValue := JsonValue.FindValue('autoApplyPendingUpdates');
      if PendingValue is TJSONBool then
        FAutoApplyPendingUpdates := TJSONBool(PendingValue).AsBoolean;
    finally
      JsonValue.Free;
    end;
  except
    // A corrupt settings file behaves like a missing one.
  end;
end;

procedure TPortappixSettings.Save;
var
  Json: TJSONObject;
begin
  Json := TJSONObject.Create;
  try
    Json.AddPair('schema', TJSONNumber.Create(1));
    Json.AddPair('updateUrl', FUpdateUrl);
    Json.AddPair('autoCheckUpdates', TJSONBool.Create(FAutoCheckUpdates));
    Json.AddPair('autoApplyPendingUpdates', TJSONBool.Create(FAutoApplyPendingUpdates));
    ForceDirectories(TPath.GetDirectoryName(SettingsFile));
    if not WriteTextFileAtomic(SettingsFile, Json.Format(2)) then
      raise Exception.Create('Unable to write settings.json.');
  finally
    Json.Free;
  end;
end;

function TPortappixSettings.SaveOrUpdate: Boolean;
begin
  try
    Save;
    Result := True;
  except
    Result := False;
  end;
end;

end.
