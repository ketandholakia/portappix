object MainLauncherForm: TMainLauncherForm
  Left = 0
  Top = 0
  Caption = 'Portappix'
  ClientHeight = 520
  ClientWidth = 860
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  Position = poScreenCenter
  OnCloseQuery = FormCloseQuery
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  TextHeight = 15
  object PageControl: TPageControl
    Left = 0
    Top = 0
    Width = 860
    Height = 495
    ActivePage = InstalledTab
    Align = alClient
    TabOrder = 0
    object InstalledTab: TTabSheet
      Caption = 'Installed Apps'
      object InstalledListView: TListView
        Left = 0
        Top = 0
        Width = 852
        Height = 424
        Align = alClient
        Columns = <
          item
            Caption = 'Name'
            Width = 220
          end
          item
            Caption = 'Id'
            Width = 180
          end
          item
            Caption = 'Path'
            Width = 430
          end>
        ReadOnly = True
        RowSelect = True
        TabOrder = 0
        ViewStyle = vsReport
      end
      object InstalledButtonsPanel: TPanel
        Left = 0
        Top = 424
        Width = 852
        Height = 41
        Align = alBottom
        BevelOuter = bvNone
        TabOrder = 1
        object RefreshInstalledButton: TButton
          Left = 8
          Top = 8
          Width = 120
          Height = 25
          Caption = 'Refresh'
          TabOrder = 0
          OnClick = RefreshInstalledButtonClick
        end
        object LaunchButton: TButton
          Left = 134
          Top = 8
          Width = 120
          Height = 25
          Caption = 'Launch'
          TabOrder = 1
          OnClick = LaunchButtonClick
        end
        object UninstallButton: TButton
          Left = 260
          Top = 8
          Width = 120
          Height = 25
          Caption = 'Uninstall'
          TabOrder = 2
          OnClick = UninstallButtonClick
        end
      end
    end
    object StoreTab: TTabSheet
      Caption = 'Store'
      ImageIndex = 1
      object StoreTopPanel: TPanel
        Left = 0
        Top = 0
        Width = 852
        Height = 41
        Align = alTop
        BevelOuter = bvNone
        TabOrder = 0
        object SearchLabel: TLabel
          Left = 8
          Top = 12
          Width = 36
          Height = 15
          Caption = 'Search'
        end
        object SearchEdit: TEdit
          Left = 56
          Top = 8
          Width = 321
          Height = 23
          TabOrder = 0
          OnChange = SearchEditChange
        end
        object RefreshCatalogButton: TButton
          Left = 383
          Top = 8
          Width = 120
          Height = 25
          Caption = 'Refresh Catalog'
          TabOrder = 1
          OnClick = RefreshCatalogButtonClick
        end
      end
      object StoreListView: TListView
        Left = 0
        Top = 41
        Width = 852
        Height = 383
        Align = alClient
        Columns = <
          item
            Caption = 'Name'
            Width = 220
          end
          item
            Caption = 'Id'
            Width = 140
          end
          item
            Caption = 'Version'
            Width = 100
          end
          item
            Caption = 'Category'
            Width = 140
          end
          item
            Caption = 'Size'
            Width = 120
          end>
        ReadOnly = True
        RowSelect = True
        TabOrder = 1
        ViewStyle = vsReport
      end
      object StoreBottomPanel: TPanel
        Left = 0
        Top = 424
        Width = 852
        Height = 41
        Align = alBottom
        BevelOuter = bvNone
        TabOrder = 2
        object InstallButton: TButton
          Left = 8
          Top = 8
          Width = 120
          Height = 25
          Caption = 'Install'
          TabOrder = 0
          OnClick = InstallButtonClick
        end
        object ProgressBar: TProgressBar
          Left = 134
          Top = 10
          Width = 710
          Height = 21
          TabOrder = 1
        end
      end
    end
  end
  object StatusLabel: TLabel
    Left = 0
    Top = 495
    Width = 860
    Height = 25
    Align = alBottom
    AutoSize = False
    Caption = 'Ready'
    Layout = tlCenter
  end
  object TrayIcon: TTrayIcon
    Hint = 'Portappix'
    Visible = True
    OnDblClick = TrayIconDblClick
    Left = 808
    Top = 8
  end
end
