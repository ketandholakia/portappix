unit Portappix.Version;

{
  Minimal semantic-versioning helper used for update decisions.

  Supported forms: "1", "1.2", "1.2.3", with an optional "-pre.release"
  suffix and an ignored "+build" suffix. Missing core numbers default to 0.
  Comparison follows semver 2.0.0 ordering: core numbers first, then
  pre-release versions sort BEFORE the stable release, numeric identifiers
  compare numerically, alphanumeric identifiers lexically, numeric before
  alphanumeric, and a shorter identifier list sorts before a longer one.
}

interface

uses
  System.SysUtils,
  System.Math;

type
  EPortappixVersionError = class(Exception);

  TPortappixSemVer = record
  private
    FMajor: Integer;
    FMinor: Integer;
    FPatch: Integer;
    FPreRelease: string;   // dot-separated identifiers after '-'; '' when stable
    FRaw: string;
    function GetIsValid: Boolean;
  public
    class function Parse(const AValue: string): TPortappixSemVer; static;
    class function TryParse(const AValue: string;
      out AVersion: TPortappixSemVer): Boolean; static;
    class function Compare(const ALeft, ARight: TPortappixSemVer): Integer; static;
    class function CompareText(const ALeft, ARight: string): Integer; static;
    function IsNewerThan(const AOther: TPortappixSemVer): Boolean;
    property Major: Integer read FMajor;
    property Minor: Integer read FMinor;
    property Patch: Integer read FPatch;
    property PreRelease: string read FPreRelease;
    property Raw: string read FRaw;
    property IsValid: Boolean read GetIsValid;
  end;

implementation

function IsNumericIdentifier(const AValue: string): Boolean;
begin
  if AValue = '' then
    Exit(False);
  for var Character in AValue do
    if not CharInSet(Character, ['0'..'9']) then
      Exit(False);
  Result := True;
end;

{ TPortappixSemVer }

class function TPortappixSemVer.Parse(const AValue: string): TPortappixSemVer;
var
  Core: string;
  CoreParts: TArray<string>;
begin
  Result := Default(TPortappixSemVer);
  Result.FRaw := AValue.Trim;
  Core := Result.FRaw;

  // Build metadata is ignored for ordering.
  var PlusAt := Core.IndexOf('+');
  if PlusAt >= 0 then
    Core := Core.Substring(0, PlusAt);

  var DashAt := Core.IndexOf('-');
  if DashAt >= 0 then
  begin
    Result.FPreRelease := Core.Substring(DashAt + 1);
    Core := Core.Substring(0, DashAt);
  end;

  if Core = '' then
    raise EPortappixVersionError.CreateFmt('Version "%s" has no numbers.', [AValue]);
  for var Character in Core do
    if not CharInSet(Character, ['0'..'9', '.']) then
      raise EPortappixVersionError.CreateFmt(
        'Version "%s" is not a semantic version.', [AValue]);

  CoreParts := Core.Split(['.']);
  if (Length(CoreParts) = 0) or (Length(CoreParts) > 3) then
    raise EPortappixVersionError.CreateFmt(
      'Version "%s" must have one to three dot-separated numbers.', [AValue]);
  for var Index := 0 to High(CoreParts) do
    if (CoreParts[Index] = '') or not IsNumericIdentifier(CoreParts[Index]) then
      raise EPortappixVersionError.CreateFmt(
        'Version "%s" contains an invalid number: "%s".', [AValue, CoreParts[Index]]);

  Result.FMajor := StrToIntDef(CoreParts[0], 0);
  if Length(CoreParts) > 1 then
    Result.FMinor := StrToIntDef(CoreParts[1], 0);
  if Length(CoreParts) > 2 then
    Result.FPatch := StrToIntDef(CoreParts[2], 0);
end;

class function TPortappixSemVer.TryParse(const AValue: string;
  out AVersion: TPortappixSemVer): Boolean;
begin
  try
    AVersion := TPortappixSemVer.Parse(AValue);
    Result := True;
  except
    AVersion := Default(TPortappixSemVer);
    Result := False;
  end;
end;

class function TPortappixSemVer.Compare(const ALeft,
  ARight: TPortappixSemVer): Integer;
begin
  // Core numbers.
  if ALeft.Major <> ARight.Major then
    Exit(CompareValue(ALeft.Major, ARight.Major));
  if ALeft.Minor <> ARight.Minor then
    Exit(CompareValue(ALeft.Minor, ARight.Minor));
  if ALeft.Patch <> ARight.Patch then
    Exit(CompareValue(ALeft.Patch, ARight.Patch));

  // A pre-release sorts before the stable release.
  if (ALeft.PreRelease = '') and (ARight.PreRelease = '') then
    Exit(0);
  if ALeft.PreRelease = '' then
    Exit(1);
  if ARight.PreRelease = '' then
    Exit(-1);

  // Both pre-release: compare dot-separated identifiers pairwise.
  var LeftParts := ALeft.PreRelease.Split(['.']);
  var RightParts := ARight.PreRelease.Split(['.']);
  var CommonCount := Min(Length(LeftParts), Length(RightParts));
  for var Index := 0 to CommonCount - 1 do
  begin
    var LeftNumeric := IsNumericIdentifier(LeftParts[Index]);
    var RightNumeric := IsNumericIdentifier(RightParts[Index]);
    if LeftNumeric and RightNumeric then
    begin
      var LeftValue := StrToInt64Def(LeftParts[Index], 0);
      var RightValue := StrToInt64Def(RightParts[Index], 0);
      if LeftValue <> RightValue then
        Exit(CompareValue(LeftValue, RightValue));
    end
    else if LeftNumeric then
      Exit(-1)   // numeric identifiers sort before alphanumeric
    else if RightNumeric then
      Exit(1)
    else if LeftParts[Index] <> RightParts[Index] then
      Exit(CompareStr(LeftParts[Index], RightParts[Index]));
  end;

  // Every shared identifier is equal: the shorter list sorts first.
  Result := CompareValue(Length(LeftParts), Length(RightParts));
end;

class function TPortappixSemVer.CompareText(const ALeft, ARight: string): Integer;
var
  LeftVersion: TPortappixSemVer;
  RightVersion: TPortappixSemVer;
begin
  LeftVersion := TPortappixSemVer.Parse(ALeft);
  RightVersion := TPortappixSemVer.Parse(ARight);
  Result := TPortappixSemVer.Compare(LeftVersion, RightVersion);
end;

function TPortappixSemVer.IsNewerThan(const AOther: TPortappixSemVer): Boolean;
begin
  Result := TPortappixSemVer.Compare(Self, AOther) > 0;
end;

function TPortappixSemVer.GetIsValid: Boolean;
begin
  Result := FRaw <> '';
end;

end.
