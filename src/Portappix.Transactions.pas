unit Portappix.Transactions;

{
  Transactional journal model for Portappix (Phase 2).

  A host-state transaction is one portable-app run: it persists a durable,
  per-operation write-ahead record BEFORE every host mutation so a crash at
  any point leaves enough information to restore the original host state.

  Storage layout (all inside the launcher root):
    Transactions\<txid>\transaction.json        durable journal (schema 2)
    Transactions\<txid>\transaction.json.prev   previous good journal copy
    Transactions\<txid>\registry_backup_<n>.reg host registry exports

  State machine (see docs/security/JOURNAL_TRANSACTION_AND_RECOVERY.md):
    preparing -> prepared -> hostBackupComplete -> hostStateChanging ->
    hostStateChanged -> running -> cleaning -> completed
  with prepared/hostBackupComplete/hostStateChanging -> cleaning on
  pre-launch failure, and any non-completed state -> recoveryRequired when
  the recovery engine hits an ambiguity it refuses to guess about.

  Integrity / threat model: transaction.json lives in a user-writable
  directory. A process running as the same user can rewrite the journal AND
  every backup file, so no integrity mechanism available here (DPAPI is
  per-user too) can defend against that attacker; instead every loaded
  journal is strictly validated (schema, state, tx id, app id, paths,
  backup-file ownership) and anything inconsistent FAILS CLOSED into
  recoveryRequired/manual review. The journal is not tamper-proof and must
  not be claimed to be.
}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  System.StrUtils,
  System.JSON,
  System.DateUtils,
  System.RegularExpressions,
  System.Generics.Collections,
  Portappix.Common,
  Portappix.Junction,
  Portappix.Registry;

const
  PortappixJournalSchemaVersion = 2;
  // Optional top-level schema-2 journal field recording TRANSACTION
  // PROVENANCE for junction ownership (Phase 3 remediation). Every journal
  // written by a Phase 3 build carries "junctionOwnership": "identity"
  // durably BEFORE any junction operation, so a Phase 3 journal can never
  // be mistaken for a Phase 2 journal because a field is missing. A journal
  // WITHOUT the field is therefore positively identified as a Phase 2 (or
  // migrated legacy) transaction and keeps the documented target+tag
  // compatibility behavior; a journal with an UNKNOWN value is ambiguous
  // by definition and fails closed (it can never be classified as legacy).
  // The field is a provenance marker only: it is not an integrity
  // mechanism, and the journal itself remains user-writable and
  // non-tamper-proof (the same-user attacker model is unchanged).
  PortappixOwnershipField = 'junctionOwnership';
  PortappixOwnershipFieldIdentity = 'identity';

type
  EPortappixTransactionError = class(Exception);
  EPortappixSimulatedCrash = class(Exception);

  TPortappixTxState = (
    txPreparing,
    txPrepared,
    txHostBackupComplete,
    txHostStateChanging,
    txHostStateChanged,
    txRunning,
    txCleaning,
    txCompleted,
    txRecoveryRequired
  );

  TPortappixTxOpStatus = (opPending, opDone, opAbsent, opFailed, opRestored);

  TPortappixTxOpKind = (
    okJunctionRemoveOld,   // remove a pre-existing reparse point (old target recorded)
    okHostDirBackup,       // rename an existing host directory to <path>_host_backup
    okJunctionCreate,      // create a Portappix junction
    okRegistryBackup,      // export a host registry key into the transaction dir
    okRegistryDelete,      // delete a host registry key
    okJunctionRemove,      // remove a Portappix-owned junction
    okHostDirRestore,      // rename <path>_host_backup back
    okRegistryRestore      // re-import a host registry backup
  );

  TPortappixTxOperation = record
    Kind: TPortappixTxOpKind;
    Status: TPortappixTxOpStatus;
    HostPath: string;
    TargetPath: string;
    BackupPath: string;
    RegistryKey: string;
    // Phase 3 junction-ownership metadata (optional; empty for legacy
    // records): what the host path was before the run ('absent',
    // 'directory', 'junction', 'file', 'other'), the reparse tag of the
    // created junction (hex), and the created object's identity
    // ('volumeSerial:fileIndex') captured at creation time.
    ExpectedOriginal: string;
    ReparseTag: string;
    Identity: string;
  end;

  /// Persistence seam: writes the transaction JSON durably and loads it back.
  /// Test overrides simulate temp-file creation failure, partial writes,
  /// flush failure and replace failure. On any failure the previous journal
  /// remains intact and no partial file is ever swapped into place.
  TPortappixJournalStore = class
  public
    type
      TTestFailMode = (tfmNone, tfmTempCreate, tfmPartialWrite, tfmFlush, tfmReplace);
  private
    FTestFailMode: TTestFailMode;
    FTestFailRemaining: Integer;
  protected
    function ShouldFailNow: Boolean;
  public
    constructor Create;
    function Persist(const AFileName, AContent: string): Boolean; virtual;
    function ReadText(const AFileName: string; out AContent: string): Boolean; virtual;
    property TestFailMode: TTestFailMode read FTestFailMode write FTestFailMode;
    // -1 = fail on every persist while armed; 0/n = fail on the next n persists.
    property TestFailRemaining: Integer read FTestFailRemaining write FTestFailRemaining;
  end;

  /// Interface handed to the runner: records intents and state transitions;
  /// every call is durably persisted before the runner performs the mutation.
  IPortappixTransaction = interface
    ['{7C0F6D9A-2E44-4B06-9A11-3D5C0A81B7F2}']
    function GetTxId: string;
    function GetState: TPortappixTxState;
    function GetDirectory: string;
    function GetDataDir: string;
    procedure SetState(const ATarget: TPortappixTxState);
    function RecordOperation(const AOperation: TPortappixTxOperation): Integer;
    procedure MarkOperation(const AIndex: Integer; const AStatus: TPortappixTxOpStatus);
    function OperationCount: Integer;
    function GetOperation(const AIndex: Integer): TPortappixTxOperation;
    function RegistryBackupFileName(const AIndex: Integer): string;
    procedure SetError(const AMessage: string);
    procedure CompleteAndRemove;
    function AllOperationsResolved: Boolean;
    // Phase 3: persist a created junction's ownership metadata together
    // with its done status (tag + object identity captured at creation).
    procedure MarkJunctionCreated(const AIndex: Integer;
      const ATag, AIdentity: string);
  end;

  TPortappixTransaction = class(TInterfacedObject, IPortappixTransaction)
  private
    FStore: TPortappixJournalStore;
    FOwnsStore: Boolean;
    FDirectory: string;
    FTxId: string;
    FAppId: string;
    FCreatedAt: TDateTime;
    FState: TPortappixTxState;
    FLegacy: Boolean;
    FLastError: string;
    FDataDir: string;
    // Transaction provenance (Phase 3): 'identity' when the journal
    // positively carries the Phase 3 junction-ownership provenance; empty
    // for Phase 2/legacy journals (junction removals may then fall back to
    // the documented strict target+tag match).
    FJunctionOwnership: string;
    FOnLog: TProc<string>;
    FOperations: TList<TPortappixTxOperation>;
    // Legacy schema-1 payload (only when FLegacy = True); recovery applies
    // the proven legacy cleanup semantics to these values verbatim.
    FLegacyKeys: TArray<string>;
    FLegacyJunctions: TArray<string>;
    procedure Log(const AMessage: string);
    procedure CheckTransition(const ATarget: TPortappixTxState);
    function TransactionFileName: string;
    procedure ParseJsonInto(const AJson: string);
    // IPortappixTransaction (explicit method resolution below)
    function GetTxId: string;
    function GetState: TPortappixTxState;
    function GetDirectory: string;
    function GetDataDir: string;
    procedure IPortappixTransaction_SetState(const ATarget: TPortappixTxState);
    function RecordOperationInternal(
      const AOperation: TPortappixTxOperation): Integer;
    procedure SetErrorInternal(const AMessage: string);
    procedure MarkJunctionCreatedInternal(const AIndex: Integer;
      const ATag, AIdentity: string);
  public
    procedure IPortappixTransaction.SetState = IPortappixTransaction_SetState;
    function IPortappixTransaction.RecordOperation = RecordOperationInternal;
    procedure IPortappixTransaction.SetError = SetErrorInternal;
    procedure IPortappixTransaction.MarkJunctionCreated = MarkJunctionCreatedInternal;
    procedure IPortappixTransaction.MarkOperation = ApplyOperationStatus;
    function IPortappixTransaction.OperationCount = GetOperationCount;
    function IPortappixTransaction.GetOperation = OperationAt;

    // Recovery / cleanup API (validated + durably persisted like the rest).
    // True when this journal positively identifies itself as a Phase 3
    // transaction ("junctionOwnership": "identity"): a junction-create or
    // junction-remove record MUST then carry the filesystem identity
    // captured at creation time before the reconciler may treat the
    // on-disk object as Portappix-owned. Phase 2 journals (field absent)
    // are positively identified as legacy and keep the documented strict
    // target+tag compatibility behavior; unknown field values are rejected
    // at parse time, so this can never silently degrade to legacy.
    function IdentityOwnershipRequired: Boolean;
    function ToJson: string;
    procedure Persist;
    procedure ApplyState(const ATarget: TPortappixTxState);
    procedure ApplyOperationStatus(const AIndex: Integer; const AStatus: TPortappixTxOpStatus);
    procedure SetErrorPersisted(const AMessage: string);
    procedure CompleteAndRemove;
    function GetOperationCount: Integer;
    function OperationAt(const AIndex: Integer): TPortappixTxOperation;
    function AllOperationsResolved: Boolean;
    constructor Create(const AStore: TPortappixJournalStore; const ADirectory,
      ATxId, AAppId: string; const ACreatedAt: TDateTime;
      const AState: TPortappixTxState; const ADataDir: string;
      const ALegacy: Boolean = False;
      // AJunctionOwnership records the transaction provenance in the
      // journal. The default empty value is intentionally LEGACY (Phase 2
      // semantics) so journal loads that find no provenance field classify
      // as Phase 2; production transaction creation passes
      // PortappixOwnershipFieldIdentity.
      const AJunctionOwnership: string = '');
    destructor Destroy; override;

    class function NewTxId(const AAppId: string): string;
    class function ValidTxAppId(const AAppId: string): Boolean;
    class function ValidateTxId(const AValue: string): Boolean;
    class function TxIdAppId(const AValue: string): string;
    class function StateToString(const AState: TPortappixTxState): string;
    class function StringToState(const AValue: string): TPortappixTxState;
    class function OpKindToString(const AKind: TPortappixTxOpKind): string;
    class function StringToOpKind(const AValue: string): TPortappixTxOpKind;
    class function OpStatusToString(const AStatus: TPortappixTxOpStatus): string;
    class function StringToOpStatus(const AValue: string): TPortappixTxOpStatus;
    class function TransitionAllowed(AFrom, ATo: TPortappixTxState): Boolean;
    class function MakeOperation(AKind: TPortappixTxOpKind; const AHostPath,
      ATargetPath, ABackupPath, ARegistryKey: string): TPortappixTxOperation; static;
    class function MakeJunctionOperation(AKind: TPortappixTxOpKind;
      const AHostPath, ATargetPath, AExpectedOriginal: string): TPortappixTxOperation; static;
    class function ParseOperation(const AValue: TJSONObject): TPortappixTxOperation; static;
    class function ParseTransaction(const ADirectory, AJson, AExpectedTxId: string;
      const AStore: TPortappixJournalStore): TPortappixTransaction; static;

    // Path-safety validation (component-wise, separator-boundary aware).
    class function SameCanonicalPath(const APath, AOther: string): Boolean; static;
    class function IsCanonicalPathUnder(const APath, ARoot: string): Boolean; static;
    class function ValidateOwnedFilePath(const APath, AExpectedDirectory,
      AExpectedName: string): Boolean; static;
    class function ValidateDataDir(const APath, ARoot, AAppId: string): Boolean; static;
    class function ValidateHostPath(const APath: string): Boolean; static;

    function Load: Boolean;
    procedure RemoveTransactionDirectory;
    function RegistryBackupFileName(const AIndex: Integer): string;
    procedure SetLegacyPayload(const AKeys, AJunctions: TArray<string>);
    procedure SetDataDir(const ADataDir: string);

    property Store: TPortappixJournalStore read FStore;
    property TxId: string read FTxId;
    property AppId: string read FAppId;
    property CreatedAt: TDateTime read FCreatedAt;
    property State: TPortappixTxState read FState;
    property DataDir: string read FDataDir;
    property Legacy: Boolean read FLegacy;
    // Provenance of this journal ('identity' = Phase 3; '' = Phase 2/
    // migrated legacy). Parsed from the journal and persisted as-is.
    property JunctionOwnership: string read FJunctionOwnership;
    property LegacyKeys: TArray<string> read FLegacyKeys;
    property LegacyJunctions: TArray<string> read FLegacyJunctions;
    property LastError: string read FLastError;
    property Directory: string read FDirectory;
    property OnLog: TProc<string> read FOnLog write FOnLog;
    property Operations: TList<TPortappixTxOperation> read FOperations;
  end;

{$IFDEF PORTAPPIX_TESTCRASH}
var
  // Test-only crash points (compiled ONLY when PORTAPPIX_TESTCRASH is
  // defined, i.e. in test-mode launcher and unit-test builds). Production
  // builds compile an empty no-op CheckCrashPoint and declare neither
  // variable, so no crash-injection mechanism exists in the shipped launcher.
  // The checkpoint identifier normally comes from PORTAPPIX_CRASH_AT via
  // Launcher.dpr (test-mode only) and names a durable-persist boundary
  // ('state:<state>' or 'op:<index>:<status>'); when it matches, the launcher
  // terminates itself abruptly to simulate a hard crash at that exact
  // transaction boundary. Never used outside test environments.
  PortappixCrashPoint: string = '';
  PortappixCrashHook: TProc<string> = nil;

// Embedded test-mode build marker. Referenced by the arming log line in
// Launcher.dpr so the linker retains it; a byte-scan for this string (and for
// 'PORTAPPIX_CRASH_AT') reliably identifies test-mode executables, and a
// release build must contain NEITHER string (see scripts/make_release.py and
// tests/scripts/test_crash_hook_isolation.py).
const
  PortappixTestCrashMarker = 'PORTAPPIX-TESTCRASH-BUILD-2026-11-10';

// Test-mode only: parse a crash checkpoint identifier and, when it is one of
// the documented forms, arm it (case-sensitive; the identifiers are emitted
// with exactly these names). Accepted:
//   state:<one canonical TPortappixTxState name>    e.g. state:hostBackupComplete
//   op:<non-negative digits>:<one canonical status> e.g. op:2:done
// Anything else returns False and never touches the armed checkpoint.
function SetCrashPointFromString(const AValue: string): Boolean;
{$ENDIF}

type
  /// Host-path operation seam (junctions, reparse-point inspection, safe
  /// renames). The default implementation wraps Portappix.Junction; tests
  /// inject fakes for fault injection and reconciliation checks.
  IPortappixHostPathOps = interface
    ['{E4D2A9C1-6B3F-4D8E-9C7A-1F0B5E2D8A34}']
    function PathExists(const APath: string): Boolean;
    function IsDirectory(const APath: string): Boolean;
    function IsReparsePoint(const APath: string): Boolean;
    function GetJunctionTarget(const APath: string): string;
    // Full reparse-point classification (tag, target, identity, errors);
    // never follows the inspected object's reparse point.
    function InspectPath(const APath: string): TPortappixPathInspection;
    function CreateJunction(const APath, ATarget: string): Boolean;
    function DeleteJunction(const APath: string): Boolean;
    function RenamePath(const AFrom, ATo: string): Boolean;
  end;

  TPortappixHostPathOps = class(TInterfacedObject, IPortappixHostPathOps)
  public
    function PathExists(const APath: string): Boolean;
    function IsDirectory(const APath: string): Boolean;
    function IsReparsePoint(const APath: string): Boolean;
    function GetJunctionTarget(const APath: string): string;
    function InspectPath(const APath: string): TPortappixPathInspection;
    function CreateJunction(const APath, ATarget: string): Boolean;
    function DeleteJunction(const APath: string): Boolean;
    function RenamePath(const AFrom, ATo: string): Boolean;
  end;

  TUndoOutcome = (uoRestored, uoRetry, uoManual);

  /// Idempotent undo/reconciliation of transaction operations. Shared by the
  /// runner's cleanup path and the recovery engine: walks operations in
  /// reverse order, verifies recorded intent against actual host state, and
  /// restores the original state — marking each operation restored (durably)
  /// only after the restore is confirmed. Never deletes a backup file; the
  /// whole transaction directory is removed only at completion.
  TPortappixTransactionReconciler = class
  private
    FRegistryOps: IPortappixRegistryOps;
    FHostPathOps: IPortappixHostPathOps;
    FOnLog: TProc<string>;
    FLastError: string;
    FManualFailure: Boolean;
    procedure Log(const AMessage: string);
    function Manual(const ATx: TPortappixTransaction;
      const AMessage: string): TUndoOutcome;
    function Retry(const AMessage: string): TUndoOutcome;
  public
    class function ValidateRegistryKey(const AKey: string): Boolean; static;
  private
    function ValidateOwnedBackup(const ATx: TPortappixTransaction;
      const ABackupPath: string): Boolean;
    function ValidateJunctionHost(const ATx: TPortappixTransaction;
      const APath: string): Boolean;
    function ValidateJunctionTarget(const ATx: TPortappixTransaction;
      const APath: string): Boolean;
    function UndoJunctionRemoveOld(const ATx: TPortappixTransaction;
      const AOp: TPortappixTxOperation): TUndoOutcome;
    function UndoHostDirBackup(const ATx: TPortappixTransaction;
      const AOp: TPortappixTxOperation): TUndoOutcome;
    function UndoJunctionCreate(const ATx: TPortappixTransaction;
      const AOp: TPortappixTxOperation): TUndoOutcome;
    function ReconcileRegistryBackup(const ATx: TPortappixTransaction;
      const AIndex: Integer; const AOp: TPortappixTxOperation): TUndoOutcome;
    function UndoRegistryDelete(const ATx: TPortappixTransaction;
      const AIndex: Integer; const AOp: TPortappixTxOperation): TUndoOutcome;
    function UndoRegistryRestore(const ATx: TPortappixTransaction;
      const AIndex: Integer; const AOp: TPortappixTxOperation): TUndoOutcome;
  public
    constructor Create(const ARegistryOps: IPortappixRegistryOps;
      const AHostPathOps: IPortappixHostPathOps; const ALog: TProc<string> = nil);
    // Returns True when no manual failure occurred; callers must still check
    // ATx.AllOperationsResolved before completing (retryable failures leave
    // operations pending for the next recovery pass).
    function ReconcileTransaction(const ATx: TPortappixTransaction): Boolean;
    property LastError: string read FLastError;
    property ManualFailure: Boolean read FManualFailure;
  end;

procedure CheckCrashPoint(const APoint: string);

implementation

{$IFDEF PORTAPPIX_TESTCRASH}
function SetCrashPointFromString(const AValue: string): Boolean;
var
  Value, IndexText, StatusText: string;
  SecondColon, IndexNumber: Integer;
  State: TPortappixTxState;
  Status: TPortappixTxOpStatus;
begin
  Result := False;
  Value := AValue;
  // Strict grammar: no surrounding or embedded whitespace at all (a shell
  // quoting accident must never arm a different boundary than documented).
  for var Character in Value do
    if CharInSet(Character, [' ', #9, #10, #13]) then
      Exit;
  if Value = '' then
    Exit;

  // Case-sensitive prefix tests (TextStartsWith in Portappix.Common uses
  // SameText, so it is deliberately NOT used here).
  if (Length(Value) > Length('state:')) and
     (Copy(Value, 1, Length('state:')) = 'state:') then
  begin
    // 'state:<canonical state name>'; case-sensitive, no other separators.
    if Length(Value) <= Length('state:') then
      Exit;
    for var Character in Value.Substring(Length('state:')) do
      if not CharInSet(Character, ['A'..'Z', 'a'..'z', '0'..'9']) then
        Exit;
    for State := Low(TPortappixTxState) to High(TPortappixTxState) do
      if Value.Substring(Length('state:')) =
         TPortappixTransaction.StateToString(State) then
      begin
        PortappixCrashPoint := Value;
        Exit(True);
      end;
    Exit;
  end;

  if (Length(Value) > Length('op:')) and
     (Copy(Value, 1, Length('op:')) = 'op:') then
  begin
    // 'op:<non-negative index>:<canonical status>'; The index must be plain
    // digits (no sign, no separators); the status must equal exactly one of
    // the canonical OpStatusToString names.
    SecondColon := 0;
    for var Position := Length('op:') + 1 to Length(Value) do
      if Value[Position] = ':' then
      begin
        SecondColon := Position;
        Break;
      end;
    if SecondColon = 0 then
      Exit;
    IndexText := Value.Substring(Length('op:'), SecondColon - Length('op:') - 1);
    // Substring() is 0-based: it starts at 0-based index SecondColon, which
    // is the character right after the second colon.
    StatusText := Value.Substring(SecondColon);
    if (IndexText = '') or (Length(IndexText) > 9) then
      Exit;
    for var Character in IndexText do
      if not CharInSet(Character, ['0'..'9']) then
        Exit;
    if not TryStrToInt(IndexText, IndexNumber) or (IndexNumber < 0) then
      Exit;

    for Status := Low(TPortappixTxOpStatus) to High(TPortappixTxOpStatus) do
      if StatusText = TPortappixTransaction.OpStatusToString(Status) then
      begin
        PortappixCrashPoint := Value;
        Exit(True);
      end;
    // 'created' is not an OpStatusToString name; the op:N:created checkpoint
    // is fired only by the runner (between junction creation and identity
    // persistence), never by the transaction APIs, but the identifier is part
    // of the documented grammar.
    if StatusText = 'created' then
    begin
      PortappixCrashPoint := Value;
      Exit(True);
    end;
  end;
end;

procedure CheckCrashPoint(const APoint: string);
begin
  if (PortappixCrashPoint <> '') and SameText(PortappixCrashPoint, APoint) then
  begin
    if Assigned(PortappixCrashHook) then
      PortappixCrashHook(APoint)
    else
      TerminateProcess(GetCurrentProcess, 1);
  end;
end;
{$ELSE}
// Production builds: no crash-injection mechanism exists. The call sites
// (state/op persistence boundaries) compile to immediate no-ops and the
// PORTAPPIX_CRASH_AT environment variable is never read by production code
// (the reader exists only in Launcher.dpr behind PORTAPPIX_TESTCRASH).
procedure CheckCrashPoint(const APoint: string);
begin
end;
{$ENDIF}

{ TPortappixJournalStore }

var
  GStoreTempCounter: Integer = 0;

constructor TPortappixJournalStore.Create;
begin
  inherited Create;
  FTestFailMode := tfmNone;
  FTestFailRemaining := 0;
end;

function TPortappixJournalStore.ShouldFailNow: Boolean;
begin
  if FTestFailMode = tfmNone then
    Exit(False);
  if FTestFailRemaining < 0 then
    Exit(True);
  if FTestFailRemaining = 0 then
    Exit(False);
  Dec(FTestFailRemaining);
  Result := True;
end;

function TPortappixJournalStore.Persist(const AFileName, AContent: string): Boolean;
var
  DirectoryName: string;
  TemporaryFile: string;
  Stream: TFileStream;
  ContentBytes: TBytes;
  HalfLength: Integer;
begin
  // Durable sequence: temp file in the same directory -> write -> flush ->
  // verify -> MoveFileEx(REPLACE_EXISTING | WRITE_THROUGH) -> flush parent
  // directory. The previous journal is preserved as <name>.prev before the
  // replace. Any failure leaves the previous journal intact and removes the
  // temporary file.
  Result := False;
  ContentBytes := TEncoding.UTF8.GetBytes(AContent);
  DirectoryName := TPath.GetDirectoryName(TPath.GetFullPath(AFileName));
  if (DirectoryName <> '') and not TDirectory.Exists(DirectoryName) then
    try
      TDirectory.CreateDirectory(DirectoryName);
    except
      Exit(False);
    end;

  if ShouldFailNow and (FTestFailMode = tfmTempCreate) then
    Exit(False);

  TemporaryFile := Format('%s.%d.%d.tmp', [AFileName, GetCurrentProcessId,
    InterlockedIncrement(GStoreTempCounter)]);
  Stream := nil;
  try
    try
      Stream := TFileStream.Create(TemporaryFile, fmCreate or fmShareExclusive);
      if Length(ContentBytes) > 0 then
      begin
        if ShouldFailNow and (FTestFailMode = tfmPartialWrite) then
        begin
          HalfLength := Length(ContentBytes) div 2;
          if HalfLength > 0 then
            Stream.WriteBuffer(ContentBytes[0], HalfLength);
          Exit(False); // partial write: never flushed, never replaced
        end;
        Stream.WriteBuffer(ContentBytes[0], Length(ContentBytes));
        if ShouldFailNow and (FTestFailMode = tfmFlush) then
          Exit(False);
        if not FlushFileBuffers(Stream.Handle) then
          Exit(False);
      end;
      if Stream.Size <> Length(ContentBytes) then
        Exit(False);
    except
      Exit(False);
    end;
  finally
    Stream.Free;
  end;

  if ShouldFailNow and (FTestFailMode = tfmReplace) then
  begin
    TFile.Delete(TemporaryFile);
    Exit(False);
  end;

  // Keep the previous valid journal (best effort) before replacing it.
  if TFile.Exists(AFileName) then
    try
      TFile.Copy(AFileName, AFileName + '.prev', True);
    except
    end;

  if not MoveFileEx(PChar(TemporaryFile), PChar(AFileName),
    MOVEFILE_REPLACE_EXISTING or MOVEFILE_WRITE_THROUGH) then
  begin
    try
      TFile.Delete(TemporaryFile);
    except
    end;
    Exit(False);
  end;

  FlushDirectoryWindows(DirectoryName);
  Result := True;
end;

function TPortappixJournalStore.ReadText(const AFileName: string;
  out AContent: string): Boolean;
begin
  Result := False;
  AContent := '';
  if not TFile.Exists(AFileName) then
    Exit;
  AContent := TFile.ReadAllText(AFileName, TEncoding.UTF8);
  Result := True;
end;

{ TPortappixTransaction }

constructor TPortappixTransaction.Create(const AStore: TPortappixJournalStore;
  const ADirectory, ATxId, AAppId: string; const ACreatedAt: TDateTime;
  const AState: TPortappixTxState; const ADataDir: string;
  const ALegacy: Boolean; const AJunctionOwnership: string);
begin
  inherited Create;
  if AStore <> nil then
  begin
    FStore := AStore;
    FOwnsStore := False;
  end
  else
  begin
    FStore := TPortappixJournalStore.Create;
    FOwnsStore := True;
  end;
  FDirectory := IncludeTrailingPathDelimiter(ADirectory);
  FTxId := ATxId;
  FAppId := AAppId;
  FCreatedAt := ACreatedAt;
  FState := AState;
  FDataDir := ADataDir;
  FLegacy := ALegacy;
  FJunctionOwnership := AJunctionOwnership;
  FOperations := TList<TPortappixTxOperation>.Create;
end;

destructor TPortappixTransaction.Destroy;
begin
  FOperations.Free;
  if FOwnsStore then
    FStore.Free;
  inherited;
end;

procedure TPortappixTransaction.Log(const AMessage: string);
begin
  if Assigned(FOnLog) then
    FOnLog(AMessage);
end;

function TPortappixTransaction.TransactionFileName: string;
begin
  Result := TPath.Combine(FDirectory, 'transaction.json');
end;

class function TPortappixTransaction.NewTxId(const AAppId: string): string;
var
  TickPart: string;
  RandomPart: string;
  Guid: TGUID;
  GuidHex: string;
begin
  if not ValidTxAppId(AAppId) then
    raise EPortappixTransactionError.CreateFmt(
      'Cannot create a transaction id for invalid app id "%s".', [AAppId]);
  TickPart := IntToHex(GetTickCount64, 16).ToLower;
  CreateGUID(Guid);
  // Flatten the GUID into 32 hex characters (groups are 8-4-4-4-12).
  GuidHex := Copy(Guid.ToString, 2, 8) + Copy(Guid.ToString, 11, 4) +
    Copy(Guid.ToString, 16, 4) + Copy(Guid.ToString, 21, 4) +
    Copy(Guid.ToString, 26, 12);
  RandomPart := Copy(GuidHex.ToLower, 1, 16);
  Result := AAppId.ToLower + '-' + TickPart + '-' + RandomPart;
  if not ValidateTxId(Result) then
    raise EPortappixTransactionError.Create('Generated transaction id failed validation.');
end;

class function TPortappixTransaction.ValidTxAppId(const AAppId: string): Boolean;
begin
  // The app id becomes a transaction-directory component: safe file name AND
  // compatible with the transaction id pattern (no spaces or other
  // characters IsSafeFileComponent happens to allow).
  Result := (AAppId <> '') and IsSafeFileComponent(AAppId) and
    TRegex.IsMatch(AAppId.ToLower, '^[a-z0-9][a-z0-9._-]{0,63}$');
end;

class function TPortappixTransaction.ValidateTxId(const AValue: string): Boolean;
begin
  // <appid>-<16 hex>-<16 hex>; the app id part must be a safe component.
  Result := TRegex.IsMatch(AValue,
    '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}-[0-9a-f]{16}-[0-9a-f]{16}$');
end;

class function TPortappixTransaction.TxIdAppId(const AValue: string): string;
const
  SuffixLength = 34; // 1 dash + 16 hex + 1 dash + 16 hex
begin
  if (Length(AValue) > SuffixLength + 1) and ValidateTxId(AValue) then
    Result := Copy(AValue, 1, Length(AValue) - SuffixLength)
  else
    Result := '';
end;

class function TPortappixTransaction.StateToString(
  const AState: TPortappixTxState): string;
const
  Names: array[TPortappixTxState] of string = (
    'preparing', 'prepared', 'hostBackupComplete', 'hostStateChanging',
    'hostStateChanged', 'running', 'cleaning', 'completed',
    'recoveryRequired');
begin
  Result := Names[AState];
end;

class function TPortappixTransaction.StringToState(
  const AValue: string): TPortappixTxState;
var
  State: TPortappixTxState;
begin
  for State := Low(TPortappixTxState) to High(TPortappixTxState) do
    if SameText(StateToString(State), AValue) then
      Exit(State);
  raise EPortappixTransactionError.CreateFmt('Unknown transaction state "%s".', [AValue]);
end;

class function TPortappixTransaction.OpKindToString(
  const AKind: TPortappixTxOpKind): string;
const
  Names: array[TPortappixTxOpKind] of string = (
    'junctionRemoveOld', 'hostDirBackup', 'junctionCreate', 'registryBackup',
    'registryDelete', 'junctionRemove', 'hostDirRestore', 'registryRestore');
begin
  Result := Names[AKind];
end;

class function TPortappixTransaction.StringToOpKind(
  const AValue: string): TPortappixTxOpKind;
var
  Kind: TPortappixTxOpKind;
begin
  for Kind := Low(TPortappixTxOpKind) to High(TPortappixTxOpKind) do
    if SameText(OpKindToString(Kind), AValue) then
      Exit(Kind);
  raise EPortappixTransactionError.CreateFmt('Unknown transaction operation kind "%s".',
    [AValue]);
end;

class function TPortappixTransaction.OpStatusToString(
  const AStatus: TPortappixTxOpStatus): string;
const
  Names: array[TPortappixTxOpStatus] of string = (
    'pending', 'done', 'absent', 'failed', 'restored');
begin
  Result := Names[AStatus];
end;

class function TPortappixTransaction.StringToOpStatus(
  const AValue: string): TPortappixTxOpStatus;
var
  Status: TPortappixTxOpStatus;
begin
  for Status := Low(TPortappixTxOpStatus) to High(TPortappixTxOpStatus) do
    if SameText(OpStatusToString(Status), AValue) then
      Exit(Status);
  raise EPortappixTransactionError.CreateFmt('Unknown operation status "%s".', [AValue]);
end;

class function TPortappixTransaction.TransitionAllowed(AFrom,
  ATo: TPortappixTxState): Boolean;
begin
  if AFrom = ATo then
    Exit(False);
  // The recovery engine may send any non-terminal state to
  // recoveryRequired; nothing may leave recoveryRequired or completed.
  case AFrom of
    txPreparing:
      Result := ATo = txPrepared;
    txPrepared:
      Result := ATo in [txHostBackupComplete, txCleaning];
    txHostBackupComplete:
      Result := ATo in [txHostStateChanging, txCleaning];
    txHostStateChanging:
      Result := ATo in [txHostStateChanged, txCleaning];
    txHostStateChanged:
      Result := ATo in [txRunning, txCleaning];
    txRunning:
      Result := ATo = txCleaning;
    txCleaning:
      Result := ATo = txCompleted;
  else
    // completed and recoveryRequired are terminal for the state machine.
    Result := False;
  end;
  if (ATo = txRecoveryRequired) and
     (AFrom in [txPreparing..txCleaning]) then
    Result := True;
end;

procedure TPortappixTransaction.CheckTransition(const ATarget: TPortappixTxState);
begin
  if not TransitionAllowed(FState, ATarget) then
    raise EPortappixTransactionError.CreateFmt(
      'Invalid transaction state transition %s -> %s (tx %s).',
      [StateToString(FState), StateToString(ATarget), FTxId]);
end;

function TPortappixTransaction.ToJson: string;
var
  Root, OperationJson: TJSONObject;
  Operations, LegacyArray: TJSONArray;
  Operation: TPortappixTxOperation;
  LegacyValue: string;
begin
  Root := TJSONObject.Create;
  try
    Root.AddPair('schemaVersion', TJSONNumber.Create(PortappixJournalSchemaVersion));
    Root.AddPair('txId', FTxId);
    Root.AddPair('appId', FAppId);
    Root.AddPair('createdAt', DateToISO8601(FCreatedAt, False));
    Root.AddPair('state', StateToString(FState));
    Root.AddPair('dataDir', FDataDir);
    Root.AddPair('legacy', TJSONBool.Create(FLegacy));
    // Transaction provenance (Phase 3): persisted on every journal written
    // by a Phase 3 build, before any junction operation; journals without
    // the field are positively identified as Phase 2 legacy on load.
    if FJunctionOwnership <> '' then
      Root.AddPair(PortappixOwnershipField, FJunctionOwnership);
    if FLegacy then
    begin
      // The legacy payload must survive persistence; recovery applies the
      // proven legacy cleanup to these values verbatim.
      LegacyArray := TJSONArray.Create;
      for LegacyValue in FLegacyKeys do
        LegacyArray.Add(LegacyValue);
      Root.AddPair('legacyKeys', LegacyArray);
      LegacyArray := TJSONArray.Create;
      for LegacyValue in FLegacyJunctions do
        LegacyArray.Add(LegacyValue);
      Root.AddPair('legacyJunctions', LegacyArray);
    end;
    Root.AddPair('lastError', FLastError);

    Operations := TJSONArray.Create;
    for Operation in FOperations do
    begin
      OperationJson := TJSONObject.Create;
      OperationJson.AddPair('kind', OpKindToString(Operation.Kind));
      OperationJson.AddPair('status', OpStatusToString(Operation.Status));
      OperationJson.AddPair('hostPath', Operation.HostPath);
      OperationJson.AddPair('targetPath', Operation.TargetPath);
      OperationJson.AddPair('backupPath', Operation.BackupPath);
      OperationJson.AddPair('registryKey', Operation.RegistryKey);
      OperationJson.AddPair('expectedOriginal', Operation.ExpectedOriginal);
      OperationJson.AddPair('reparseTag', Operation.ReparseTag);
      OperationJson.AddPair('identity', Operation.Identity);
      Operations.Add(OperationJson);
    end;
    Root.AddPair('operations', Operations);
    Result := Root.Format(2);
  finally
    Root.Free;
  end;
end;

procedure TPortappixTransaction.ParseJsonInto(const AJson: string);
var
  Root: TJSONValue;
  RootObject: TJSONObject;
  TxId, AppId, DataDir: string;
  SchemaVersion: Integer;
  State: TPortappixTxState;
  CreatedAt: TDateTime;
  OperationsValue: TJSONValue;
  OperationsArray: TJSONArray;
  Operations: TList<TPortappixTxOperation>;
  Index: Integer;
  LegacyValue, LastErrorValue: TJSONValue;
  JunctionOwnershipValue: TJSONValue;
  JunctionOwnership: string;
  LegacyKeysValue, LegacyJunctionsValue: TJSONValue;
  LegacyEntry: TJSONValue;
  KeysList, JunctionsList: TList<string>;
  LegacyKeys, LegacyJunctions: TArray<string>;

  function RequiredString(const AName: string): string;
  var
    Value: TJSONValue;
  begin
    Value := RootObject.GetValue(AName);
    if not (Value is TJSONString) then
      raise EPortappixTransactionError.CreateFmt(
        'Transaction journal property "%s" must be a string.', [AName]);
    Result := TJSONString(Value).Value;
  end;

begin
  Root := TJSONObject.ParseJSONValue(AJson);
  if Root = nil then
    raise EPortappixTransactionError.Create('Transaction journal is not valid JSON.');
  try
    if not (Root is TJSONObject) then
      raise EPortappixTransactionError.Create(
        'Transaction journal must contain a JSON object.');
    RootObject := TJSONObject(Root);

    SchemaVersion := -1;
    if RootObject.GetValue('schemaVersion') is TJSONNumber then
      SchemaVersion := TJSONNumber(RootObject.GetValue('schemaVersion')).AsInt;
    if SchemaVersion <> PortappixJournalSchemaVersion then
      raise EPortappixTransactionError.CreateFmt(
        'Transaction journal uses unsupported schema version %d.', [SchemaVersion]);

    TxId := RequiredString('txId');
    if not ValidateTxId(TxId) then
      raise EPortappixTransactionError.Create('Transaction journal has an invalid txId.');
    if (FTxId <> '') and (not SameText(TxId, FTxId)) then
      raise EPortappixTransactionError.CreateFmt(
        'Transaction id "%s" does not match the transaction directory.', [TxId]);

    AppId := RequiredString('appId');
    if (AppId = '') or not IsSafeFileComponent(AppId) then
      raise EPortappixTransactionError.CreateFmt(
        'Transaction "%s" has an invalid app id.', [TxId]);
    if not SameText(TxIdAppId(TxId), AppId.ToLower) then
      raise EPortappixTransactionError.CreateFmt(
        'Transaction id "%s" does not encode its app id "%s".', [TxId, AppId]);

    State := StringToState(RequiredString('state'));
    CreatedAt := ISO8601ToDate(RequiredString('createdAt'));

    DataDir := RequiredString('dataDir');

    OperationsValue := RootObject.GetValue('operations');
    if not (OperationsValue is TJSONArray) then
      raise EPortappixTransactionError.CreateFmt(
        'Transaction "%s" has an invalid operations list.', [TxId]);
    OperationsArray := TJSONArray(OperationsValue);
    Operations := TList<TPortappixTxOperation>.Create;
    try
      for Index := 0 to OperationsArray.Count - 1 do
      begin
        if not (OperationsArray.Items[Index] is TJSONObject) then
          raise EPortappixTransactionError.CreateFmt(
            'Transaction "%s" has a non-object operation entry.', [TxId]);
        Operations.Add(ParseOperation(TJSONObject(OperationsArray.Items[Index])));
      end;

      LegacyValue := RootObject.GetValue('legacy');
      LastErrorValue := RootObject.GetValue('lastError');

      // Transaction provenance (Phase 3): optional for schema-2
      // compatibility with Phase 2 journals, but when present it must be a
      // KNOWN value. An unrecognized provenance is ambiguous by definition
      // and FAILS CLOSED: the journal is rejected rather than silently
      // classified as a legacy Phase 2 transaction.
      JunctionOwnershipValue := RootObject.GetValue(PortappixOwnershipField);
      if JunctionOwnershipValue <> nil then
      begin
        if not (JunctionOwnershipValue is TJSONString) then
          raise EPortappixTransactionError.CreateFmt(
            'Transaction "%s" journal property "%s" must be a string; the ' +
            'transaction provenance is ambiguous and fails closed.',
            [TxId, PortappixOwnershipField]);
        JunctionOwnership := TJSONString(JunctionOwnershipValue).Value;
        if not SameText(JunctionOwnership, PortappixOwnershipFieldIdentity) then
          raise EPortappixTransactionError.CreateFmt(
            'Transaction "%s" has an unknown "%s" provenance "%s"; the ' +
            'transaction provenance is ambiguous and fails closed.',
            [TxId, PortappixOwnershipField, JunctionOwnership]);
      end
      else
        JunctionOwnership := '';

      if (LegacyValue is TJSONBool) and TJSONBool(LegacyValue).AsBoolean then
      begin
        LegacyKeysValue := RootObject.GetValue('legacyKeys');
        LegacyJunctionsValue := RootObject.GetValue('legacyJunctions');
        if not (LegacyKeysValue is TJSONArray) or
           not (LegacyJunctionsValue is TJSONArray) then
          raise EPortappixTransactionError.CreateFmt(
            'Legacy transaction "%s" is missing its payload arrays.', [TxId]);
        KeysList := TList<string>.Create;
        try
          for LegacyEntry in TJSONArray(LegacyKeysValue) do
            if LegacyEntry is TJSONString then
              KeysList.Add(LegacyEntry.Value);
          JunctionsList := TList<string>.Create;
          try
            for LegacyEntry in TJSONArray(LegacyJunctionsValue) do
              if LegacyEntry is TJSONString then
                JunctionsList.Add(LegacyEntry.Value);
            LegacyKeys := KeysList.ToArray;
            LegacyJunctions := JunctionsList.ToArray;
          finally
            JunctionsList.Free;
          end;
        finally
          KeysList.Free;
        end;
      end;

      // Commit: everything validated, now assign.
      FTxId := TxId;
      FAppId := AppId;
      FState := State;
      FCreatedAt := CreatedAt;
      FLegacy := (LegacyValue is TJSONBool) and TJSONBool(LegacyValue).AsBoolean;
      FJunctionOwnership := JunctionOwnership;
      FLegacyKeys := LegacyKeys;
      FLegacyJunctions := LegacyJunctions;
      FLastError := LastErrorValue.Value;
      FOperations.Clear;
      FOperations.AddRange(Operations);
      if FDataDir = '' then
        FDataDir := DataDir;
    finally
      Operations.Free;
    end;
  finally
    Root.Free;
  end;
end;

procedure TPortappixTransaction.Persist;
begin
  if not FStore.Persist(TransactionFileName, ToJson) then
    raise EPortappixTransactionError.CreateFmt(
      'Unable to persist transaction journal "%s"; the associated host ' +
      'operation must not proceed.', [TransactionFileName]);
end;

function TPortappixTransaction.Load: Boolean;
var
  Content: string;
begin
  // Re-read the on-disk journal into this object. Falls back to the .prev
  // copy when the primary journal is unreadable; raises only when both are
  // unusable (the caller preserves the corrupt files for diagnosis).
  Result := False;
  if FStore.ReadText(TransactionFileName, Content) then
  begin
    try
      ParseJsonInto(Content);
      Exit(True);
    except
      on E: EPortappixTransactionError do
        Log('Primary transaction journal is invalid, trying the .prev copy: ' +
          E.Message);
    end;
  end;

  if FStore.ReadText(TransactionFileName + '.prev', Content) then
  begin
    ParseJsonInto(Content);
    Result := True;
  end;
end;

procedure TPortappixTransaction.RemoveTransactionDirectory;
begin
  if TDirectory.Exists(FDirectory) then
    try
      TDirectory.Delete(FDirectory, True);
    except
      on E: Exception do
        Log(Format('Unable to remove transaction directory "%s": %s',
          [FDirectory, E.Message]));
    end;
end;

function TPortappixTransaction.RegistryBackupFileName(const AIndex: Integer): string;
begin
  Result := TPath.Combine(FDirectory, Format('registry_backup_%d.reg', [AIndex]));
end;

procedure TPortappixTransaction.SetLegacyPayload(const AKeys,
  AJunctions: TArray<string>);
begin
  FLegacyKeys := AKeys;
  FLegacyJunctions := AJunctions;
end;

procedure TPortappixTransaction.SetDataDir(const ADataDir: string);
begin
  FDataDir := ADataDir;
end;

class function TPortappixTransaction.MakeOperation(AKind: TPortappixTxOpKind;
  const AHostPath, ATargetPath, ABackupPath, ARegistryKey: string): TPortappixTxOperation;
begin
  Result.Kind := AKind;
  Result.Status := opPending;
  Result.HostPath := AHostPath;
  Result.TargetPath := ATargetPath;
  Result.BackupPath := ABackupPath;
  Result.RegistryKey := ARegistryKey;
  Result.ExpectedOriginal := '';
  Result.ReparseTag := '';
  Result.Identity := '';
end;

class function TPortappixTransaction.MakeJunctionOperation(
  AKind: TPortappixTxOpKind; const AHostPath, ATargetPath,
  AExpectedOriginal: string): TPortappixTxOperation;
begin
  Result := MakeOperation(AKind, AHostPath, ATargetPath, '', '');
  Result.ExpectedOriginal := AExpectedOriginal;
end;

class function TPortappixTransaction.ParseOperation(
  const AValue: TJSONObject): TPortappixTxOperation;

  function RequiredString(const AName: string): string;
  var
    Field: TJSONValue;
  begin
    Field := AValue.GetValue(AName);
    if not (Field is TJSONString) then
      raise EPortappixTransactionError.CreateFmt(
        'Operation property "%s" must be a string.', [AName]);
    Result := TJSONString(Field).Value;
  end;

  function OptionalString(const AName: string): string;
  var
    Field: TJSONValue;
  begin
    Result := '';
    Field := AValue.GetValue(AName);
    if Field is TJSONString then
      Result := TJSONString(Field).Value;
  end;

begin
  if AValue = nil then
    raise EPortappixTransactionError.Create('Operation must be a JSON object.');

  Result.Kind := StringToOpKind(RequiredString('kind'));
  Result.Status := StringToOpStatus(RequiredString('status'));
  Result.HostPath := RequiredString('hostPath');
  Result.TargetPath := RequiredString('targetPath');
  Result.BackupPath := RequiredString('backupPath');
  Result.RegistryKey := RequiredString('registryKey');
  // Phase 3 ownership metadata: optional so schema-2 journals written by
  // the Phase 2 build still load (empty disables the stricter identity
  // checks for those records).
  Result.ExpectedOriginal := OptionalString('expectedOriginal');
  Result.ReparseTag := OptionalString('reparseTag');
  Result.Identity := OptionalString('identity');
end;

class function TPortappixTransaction.ParseTransaction(const ADirectory, AJson,
  AExpectedTxId: string; const AStore: TPortappixJournalStore): TPortappixTransaction;
begin
  Result := TPortappixTransaction.Create(AStore, ADirectory, AExpectedTxId, '',
    0, txPreparing, '');
  try
    Result.ParseJsonInto(AJson);
  except
    Result.Free;
    raise;
  end;
end;

class function TPortappixTransaction.SameCanonicalPath(const APath,
  AOther: string): Boolean;
var
  FullPath, FullOther: TArray<string>;
  Index: Integer;
begin
  Result := False;
  if (APath = '') or (AOther = '') then
    Exit;
  if (APath.IndexOf('..') >= 0) or (AOther.IndexOf('..') >= 0) then
    Exit;
  FullPath := LowerCase(IncludeTrailingPathDelimiter(TPath.GetFullPath(APath)))
    .Split(['\'], TStringSplitOptions.ExcludeEmpty);
  FullOther := LowerCase(IncludeTrailingPathDelimiter(TPath.GetFullPath(AOther)))
    .Split(['\'], TStringSplitOptions.ExcludeEmpty);
  if Length(FullPath) <> Length(FullOther) then
    Exit;
  for Index := 0 to High(FullPath) do
    if FullPath[Index] <> FullOther[Index] then
      Exit;
  Result := True;
end;

class function TPortappixTransaction.IsCanonicalPathUnder(const APath,
  ARoot: string): Boolean;
var
  FullPath, FullRoot: TArray<string>;
  Index: Integer;
begin
  // Component-wise containment with separator-boundary awareness; never a
  // plain string-prefix comparison. Traversal is rejected before
  // canonicalization so '..' can never sneak through GetFullPath.
  Result := False;
  if (APath = '') or (ARoot = '') then
    Exit;
  if APath.IndexOf('..') >= 0 then
    Exit;

  FullPath := LowerCase(IncludeTrailingPathDelimiter(TPath.GetFullPath(APath)))
    .Split(['\'], TStringSplitOptions.ExcludeEmpty);
  FullRoot := LowerCase(IncludeTrailingPathDelimiter(TPath.GetFullPath(ARoot)))
    .Split(['\'], TStringSplitOptions.ExcludeEmpty);

  if Length(FullPath) <= Length(FullRoot) then
    Exit; // must be strictly below the root
  for Index := 0 to High(FullRoot) do
    if FullPath[Index] <> FullRoot[Index] then
      Exit;
  Result := True;
end;

class function TPortappixTransaction.ValidateOwnedFilePath(const APath,
  AExpectedDirectory, AExpectedName: string): Boolean;
begin
  // The path must be exactly <expected directory>\<expected file name> —
  // used for registry backup references so a journal can never point
  // reg.exe at an arbitrary file.
  Result := False;
  if (APath = '') or (AExpectedDirectory = '') or (AExpectedName = '') then
    Exit;
  if APath.IndexOf('..') >= 0 then
    Exit;
  Result := SameCanonicalPath(APath,
    TPath.Combine(AExpectedDirectory, AExpectedName));
end;

class function TPortappixTransaction.ValidateDataDir(const APath, ARoot,
  AAppId: string): Boolean;
begin
  // The only legal data directory is <root>\Data\<appId>.
  Result := False;
  if (AAppId = '') or not IsSafeFileComponent(AAppId) then
    Exit;
  if APath.IndexOf('..') >= 0 then
    Exit;
  Result := SameCanonicalPath(APath,
    TPath.Combine(TPath.Combine(ARoot, 'Data'), AAppId));
end;

class function TPortappixTransaction.ValidateHostPath(const APath: string): Boolean;
var
  FullPath: string;
  Component: string;
begin
  // A host path recorded in a journal must be absolute, non-UNC, not a drive
  // root, traversal-free, and never inside Portappix transaction storage.
  Result := False;
  if APath = '' then
    Exit;
  if APath.StartsWith('\\') then
    Exit; // UNC
  if APath.IndexOf('..') >= 0 then
    Exit; // traversal
  FullPath := TPath.GetFullPath(APath);
  if Length(FullPath) <= 3 then
    Exit; // drive root (e.g. "C:\")
  if (Length(FullPath) >= 2) and (FullPath[2] <> ':') then
    Exit; // not a drive-letter absolute path
  for Component in FullPath.Split(['\'], TStringSplitOptions.ExcludeEmpty) do
    if SameText(Component, 'Transactions') then
      Exit; // never treat transaction storage as a junction host path
  Result := True;
end;

{ IPortappixTransaction }

function TPortappixTransaction.IdentityOwnershipRequired: Boolean;
begin
  // Only a positively-identified Phase 3 journal requires the persisted
  // creation identity; legacy journals (field absent) do not. Unknown
  // values never reach here because parsing rejects them.
  Result := SameText(FJunctionOwnership, PortappixOwnershipFieldIdentity);
end;

function TPortappixTransaction.GetTxId: string;
begin
  Result := FTxId;
end;

function TPortappixTransaction.GetState: TPortappixTxState;
begin
  Result := FState;
end;

function TPortappixTransaction.GetDirectory: string;
begin
  Result := ExcludeTrailingPathDelimiter(FDirectory);
end;

function TPortappixTransaction.GetDataDir: string;
begin
  Result := FDataDir;
end;

procedure TPortappixTransaction.IPortappixTransaction_SetState(
  const ATarget: TPortappixTxState);
begin
  ApplyState(ATarget);
end;

procedure TPortappixTransaction.ApplyState(const ATarget: TPortappixTxState);
begin
  CheckTransition(ATarget);
  FState := ATarget;
  Persist;
  CheckCrashPoint('state:' + StateToString(FState));
end;

function TPortappixTransaction.RecordOperationInternal(
  const AOperation: TPortappixTxOperation): Integer;
var
  Operation: TPortappixTxOperation;
begin
  Operation := AOperation;
  Operation.Status := opPending;
  FOperations.Add(Operation);
  Result := FOperations.Count - 1;
  // Registry backups are recorded without a file name; the transaction owns
  // the naming (registry_backup_<opIndex>.reg) and assigns it here so the
  // ownership validation can never drift from the recorded reference.
  if (Operation.Kind = okRegistryBackup) and (Operation.BackupPath = '') then
  begin
    Operation.BackupPath := RegistryBackupFileName(Result);
    FOperations[Result] := Operation;
  end;
  Persist;
  CheckCrashPoint(Format('op:%d:pending', [Result]));
end;

procedure TPortappixTransaction.ApplyOperationStatus(const AIndex: Integer;
  const AStatus: TPortappixTxOpStatus);
var
  Operation: TPortappixTxOperation;
begin
  if (AIndex < 0) or (AIndex >= FOperations.Count) then
    raise EPortappixTransactionError.CreateFmt('Invalid operation index %d.', [AIndex]);
  Operation := FOperations[AIndex];
  Operation.Status := AStatus;
  FOperations[AIndex] := Operation;
  Persist;
  CheckCrashPoint(Format('op:%d:%s', [AIndex, OpStatusToString(AStatus)]));
end;

function TPortappixTransaction.GetOperationCount: Integer;
begin
  Result := FOperations.Count;
end;

function TPortappixTransaction.OperationAt(
  const AIndex: Integer): TPortappixTxOperation;
begin
  if (AIndex < 0) or (AIndex >= FOperations.Count) then
    raise EPortappixTransactionError.CreateFmt('Invalid operation index %d.', [AIndex]);
  Result := FOperations[AIndex];
end;

procedure TPortappixTransaction.SetErrorInternal(const AMessage: string);
begin
  SetErrorPersisted(AMessage);
end;

procedure TPortappixTransaction.SetErrorPersisted(const AMessage: string);
begin
  FLastError := AMessage;
  try
    Persist;
  except
    on E: Exception do
      Log('Unable to persist the transaction error: ' + E.Message);
  end;
end;

procedure TPortappixTransaction.MarkJunctionCreatedInternal(const AIndex: Integer;
  const ATag, AIdentity: string);
var
  Operation: TPortappixTxOperation;
begin
  if (AIndex < 0) or (AIndex >= FOperations.Count) then
    raise EPortappixTransactionError.CreateFmt('Invalid operation index %d.', [AIndex]);
  Operation := FOperations[AIndex];
  Operation.Status := opDone;
  Operation.ReparseTag := ATag;
  Operation.Identity := AIdentity;
  FOperations[AIndex] := Operation;
  Persist;
  CheckCrashPoint(Format('op:%d:done', [AIndex]));
end;

procedure TPortappixTransaction.CompleteAndRemove;
begin
  ApplyState(txCompleted);
  RemoveTransactionDirectory;
end;

function TPortappixTransaction.AllOperationsResolved: Boolean;
var
  Operation: TPortappixTxOperation;
begin
  // A transaction may be completed only when every mutation has been undone
  // and confirmed (opRestored) or recorded as a no-op. Registry backups are
  // the exception: their forward action is a read-only export with nothing
  // to undo, so opDone is a terminal state for them. A crash in the middle
  // of the cleanup leaves undoable operations as opDone, which keeps the
  // transaction open for the next recovery pass instead of silently
  // completing it with host state still mutated.
  Result := True;
  for Operation in FOperations do
  begin
    if Operation.Status in [opPending, opFailed] then
      Exit(False);
    if (Operation.Kind <> okRegistryBackup) and (Operation.Status = opDone) then
      Exit(False);
  end;
end;

{ TPortappixHostPathOps }

function TPortappixHostPathOps.PathExists(const APath: string): Boolean;
begin
  Result := TDirectory.Exists(APath) or TFile.Exists(APath);
end;

function TPortappixHostPathOps.IsDirectory(const APath: string): Boolean;
begin
  Result := TDirectory.Exists(APath);
end;

function TPortappixHostPathOps.IsReparsePoint(const APath: string): Boolean;
begin
  Result := Portappix.Junction.IsReparsePoint(APath);
end;

function TPortappixHostPathOps.GetJunctionTarget(const APath: string): string;
begin
  Result := Portappix.Junction.GetJunctionTarget(APath);
end;

function TPortappixHostPathOps.InspectPath(const APath: string): TPortappixPathInspection;
begin
  Result := Portappix.Junction.InspectPath(APath);
end;

function TPortappixHostPathOps.CreateJunction(const APath, ATarget: string): Boolean;
begin
  Result := Portappix.Junction.CreateJunction(APath, ATarget);
end;

function TPortappixHostPathOps.DeleteJunction(const APath: string): Boolean;
begin
  Result := Portappix.Junction.DeleteJunction(APath);
end;

function TPortappixHostPathOps.RenamePath(const AFrom, ATo: string): Boolean;
begin
  Result := RenameFile(AFrom, ATo);
end;

{ TPortappixTransactionReconciler }

constructor TPortappixTransactionReconciler.Create(
  const ARegistryOps: IPortappixRegistryOps; const AHostPathOps: IPortappixHostPathOps;
  const ALog: TProc<string>);
begin
  inherited Create;
  FRegistryOps := ARegistryOps;
  FHostPathOps := AHostPathOps;
  FOnLog := ALog;
  FManualFailure := False;
end;

procedure TPortappixTransactionReconciler.Log(const AMessage: string);
begin
  if Assigned(FOnLog) then
    FOnLog(AMessage);
end;

function TPortappixTransactionReconciler.Manual(const ATx: TPortappixTransaction;
  const AMessage: string): TUndoOutcome;
begin
  FLastError := AMessage;
  FManualFailure := True;
  Log('RECOVERY MANUAL INTERVENTION REQUIRED (tx ' + ATx.TxId + '): ' + AMessage);
  Result := uoManual;
end;

function TPortappixTransactionReconciler.Retry(const AMessage: string): TUndoOutcome;
begin
  FLastError := AMessage;
  Log('Recovery step failed (will be retried on the next recovery pass): ' + AMessage);
  Result := uoRetry;
end;

class function TPortappixTransactionReconciler.ValidateRegistryKey(
  const AKey: string): Boolean;
var
  IgnoredError: string;
begin
  // Journal-supplied registry keys are validated before any reg.exe call:
  // HKCU\Software\<vendor>\<app> depth (shared with policy), safe components,
  // no reserved vendors, and no traversal or separator tricks.
  Result := ValidateRegistryKeyDepthAndVendor(AKey, IgnoredError);
end;

function TPortappixTransactionReconciler.ValidateOwnedBackup(
  const ATx: TPortappixTransaction; const ABackupPath: string): Boolean;
var
  FileName: string;
begin
  // The reference must point into THIS transaction's directory with the
  // transaction-owned backup file naming.
  Result := False;
  FileName := TPath.GetFileName(ABackupPath);
  if not TRegex.IsMatch(LowerCase(FileName), '^registry_backup_[0-9]+\.reg$') then
    Exit;
  Result := TPortappixTransaction.ValidateOwnedFilePath(ABackupPath,
    ExcludeTrailingPathDelimiter(ATx.Directory), FileName);
end;

function TPortappixTransactionReconciler.ValidateJunctionHost(
  const ATx: TPortappixTransaction; const APath: string): Boolean;
begin
  Result := TPortappixTransaction.ValidateHostPath(APath);
end;

function TPortappixTransactionReconciler.ValidateJunctionTarget(
  const ATx: TPortappixTransaction; const APath: string): Boolean;
begin
  // Portappix junction targets must live inside the transaction's data dir.
  Result := (ATx.DataDir <> '') and
    TPortappixTransaction.IsCanonicalPathUnder(APath, ATx.DataDir);
end;

function TPortappixTransactionReconciler.UndoJunctionRemoveOld(
  const ATx: TPortappixTransaction; const AOp: TPortappixTxOperation): TUndoOutcome;
var
  CurrentTarget: string;
  Inspection: TPortappixPathInspection;

  function VerifyRestored: TUndoOutcome;
  begin
    Inspection := FHostPathOps.InspectPath(AOp.HostPath);
    if Inspection.IsMountPoint and Inspection.TargetParsed and
       TPortappixTransaction.SameCanonicalPath(Inspection.Target, AOp.TargetPath) then
      Result := uoRestored
    else
      Result := Retry(Format('the original junction "%s" was recreated but does not ' +
        'verify against the recorded target.', [AOp.HostPath]));
  end;

begin
  // Intent: remove a pre-existing reparse point at HostPath (its original
  // target recorded in TargetPath). Restore = ensure that junction exists
  // again exactly as recorded. The original junction's full identity is its
  // mount-point tag plus target, so recreation from the recorded target IS
  // preservation; the durable record (persisted before removal) is the
  // preserved copy.
  if not ValidateJunctionHost(ATx, AOp.HostPath) then
    Exit(Manual(ATx, Format('junction host path "%s" failed validation.', [AOp.HostPath])));
  if (AOp.TargetPath <> '') and not TPortappixTransaction.ValidateHostPath(AOp.TargetPath) then
    Exit(Manual(ATx, Format('recorded original junction target "%s" failed validation.',
      [AOp.TargetPath])));

  Inspection := FHostPathOps.InspectPath(AOp.HostPath);
  case Inspection.Kind of
    rkMissing:
      begin
        if AOp.TargetPath = '' then
          Exit(Manual(ATx, Format('the original junction target for "%s" was not ' +
            'recorded; manual restoration required.', [AOp.HostPath])));
        if not FHostPathOps.PathExists(AOp.TargetPath) then
          Log(Format('REPORT: the original junction target "%s" no longer exists; ' +
            'the junction is restored exactly as recorded (dangling target).',
            [AOp.TargetPath]));
        if not FHostPathOps.CreateJunction(AOp.HostPath, AOp.TargetPath) then
          Exit(Retry(Format('unable to recreate the original junction "%s" -> "%s".',
            [AOp.HostPath, AOp.TargetPath])));
        Result := VerifyRestored;
        if Result = uoRestored then
          Log(Format('Restored original junction "%s" -> "%s".', [AOp.HostPath, AOp.TargetPath]));
      end;

    rkJunction:
      begin
        if not Inspection.TargetParsed then
          Exit(Manual(ATx, Format('the junction target of "%s" cannot be parsed; ' +
            'restoration state cannot be verified.', [AOp.HostPath])));
        CurrentTarget := Inspection.Target;
        if not TPortappixTransaction.SameCanonicalPath(CurrentTarget, AOp.TargetPath) then
          Exit(Manual(ATx, Format('"%s" holds a junction with an unexpected target; ' +
            'the recorded original junction cannot be restored over it.',
            [AOp.HostPath])));
        Exit(uoRestored); // already restored: idempotent, nothing destructive
      end;

    rkSymlink:
      Exit(Manual(ATx, Format('"%s" now holds a symbolic link; the recorded original ' +
        'junction cannot be restored over it; manual intervention required.',
        [AOp.HostPath])));

    rkOtherReparse:
      Exit(Manual(ATx, Format('"%s" now holds an unsupported reparse point (%s); the ' +
        'recorded original junction cannot be restored over it.', [AOp.HostPath,
        Inspection.ErrorMessage])));

    rkDirectory, rkFile:
      Exit(Manual(ATx, Format('"%s" is occupied by an ordinary %s; the recorded ' +
        'original junction cannot be restored; manual intervention required.',
        [AOp.HostPath, IfThen(Inspection.Kind = rkDirectory, 'directory', 'file')])));

    rkInspectionFailed:
      Exit(Manual(ATx, Format('cannot inspect "%s": %s', [AOp.HostPath,
        Inspection.ErrorMessage])));
  else
    Exit(Manual(ATx, 'unknown inspection classification.'));
  end;
end;

function TPortappixTransactionReconciler.UndoHostDirBackup(
  const ATx: TPortappixTransaction; const AOp: TPortappixTxOperation): TUndoOutcome;
var
  ExpectedBackup: string;
begin
  // Intent: rename HostPath to BackupPath (<host>_host_backup); also used
  // for cleanup-phase hostDirRestore. Restore = rename it back.
  if not ValidateJunctionHost(ATx, AOp.HostPath) then
    Exit(Manual(ATx, Format('junction host path "%s" failed validation.', [AOp.HostPath])));
  ExpectedBackup := TrimTrailingPathDelimiter(AOp.HostPath) + '_host_backup';
  if not TPortappixTransaction.SameCanonicalPath(AOp.BackupPath, ExpectedBackup) then
    Exit(Manual(ATx, Format('backup path "%s" does not match the expected backup name "%s".',
      [AOp.BackupPath, ExpectedBackup])));

  if FHostPathOps.PathExists(AOp.BackupPath) then
  begin
    if FHostPathOps.PathExists(AOp.HostPath) then
      Exit(Manual(ATx, Format('both "%s" and its backup "%s" exist; manual ' +
        'reconciliation required.', [AOp.HostPath, AOp.BackupPath])));
    if not FHostPathOps.RenamePath(AOp.BackupPath, AOp.HostPath) then
      Exit(Retry(Format('unable to restore host directory "%s" from its backup.',
        [AOp.HostPath])));
    Log(Format('Restored host directory "%s" from its backup.', [AOp.HostPath]));
    Exit(uoRestored);
  end;

  if FHostPathOps.PathExists(AOp.HostPath) then
    Exit(uoRestored); // the rename never happened or was already undone

  Exit(Manual(ATx, Format('host directory "%s" and its backup are both missing; ' +
    'manual reconciliation required.', [AOp.HostPath])));
end;

function TPortappixTransactionReconciler.UndoJunctionCreate(
  const ATx: TPortappixTransaction; const AOp: TPortappixTxOperation): TUndoOutcome;
var
  Inspection: TPortappixPathInspection;
begin
  // Removal of a Portappix-created junction. The object is removed ONLY
  // when inspection positively identifies it as the recorded junction:
  // mount-point tag, exact recorded target, and (when the record carries
  // one) the exact filesystem object identity captured at creation.
  if not ValidateJunctionHost(ATx, AOp.HostPath) then
    Exit(Manual(ATx, Format('junction host path "%s" failed validation.', [AOp.HostPath])));
  if not ValidateJunctionTarget(ATx, AOp.TargetPath) then
    Exit(Manual(ATx, Format('junction target "%s" is outside the transaction data dir.',
      [AOp.TargetPath])));

  Inspection := FHostPathOps.InspectPath(AOp.HostPath);
  case Inspection.Kind of
    rkMissing:
      Exit(uoRestored); // already absent

    rkInspectionFailed:
      Exit(Manual(ATx, Format('cannot inspect "%s": %s',
        [AOp.HostPath, Inspection.ErrorMessage])));

    rkSymlink:
      Exit(Manual(ATx, Format('"%s" now holds a symbolic link, not the recorded ' +
        'Portappix junction; external replacement detected and preserved.',
        [AOp.HostPath])));

    rkOtherReparse:
      Exit(Manual(ATx, Format('"%s" now holds an unsupported reparse point (%s); ' +
        'external replacement detected and preserved.', [AOp.HostPath,
        Inspection.ErrorMessage])));

    rkDirectory, rkFile:
      Exit(Manual(ATx, Format('"%s" was replaced by an ordinary %s; external ' +
        'replacement detected and preserved.', [AOp.HostPath,
        IfThen(Inspection.Kind = rkDirectory, 'directory', 'file')])));

    rkJunction:
      begin
        if not Inspection.TargetParsed then
          Exit(Manual(ATx, Format('the junction target of "%s" cannot be parsed; ' +
            'ownership cannot be verified.', [AOp.HostPath])));
        if not TPortappixTransaction.SameCanonicalPath(Inspection.Target, AOp.TargetPath) then
          Exit(Manual(ATx, Format('refusing to remove "%s": its target does not match ' +
            'the recorded Portappix junction; external replacement detected and preserved.',
            [AOp.HostPath])));
        // Object-identity ownership check. Phase 3 provenance makes the
        // PERSISTED creation identity MANDATORY: a crash between the
        // junction's creation and MarkJunctionCreated's durable persist
        // leaves the record without an identity, and in that window the
        // on-disk object could have been swapped for a junction with the
        // same canonical target by any other process. Target+tag equality
        // proves nothing then, so ownership cannot be established: the
        // object is preserved untouched, every piece of recovery metadata
        // is retained, and the reconciler reports a manual-intervention
        // failure (the recovery engine turns that into recoveryRequired).
        // Phase 2 journals (positively identified by the absence of the
        // provenance field) keep the documented strict target+tag match,
        // which is still positive verification, not a blind removal.
        if ATx.IdentityOwnershipRequired and (AOp.Identity = '') then
          Exit(Manual(ATx, Format('refusing to remove "%s": ownership could not be ' +
            'established. This transaction is a Phase 3 junction-create record, but ' +
            'the filesystem identity of the created junction was never persisted ' +
            '(a crash between junction creation and the durable persistence of the ' +
            'creation identity); the reparse tag and target match do not prove ' +
            'ownership in that window, so the junction is preserved untouched for ' +
            'manual review.', [AOp.HostPath])));
        // When the record carries an identity but the filesystem cannot
        // supply a comparable one (non-NTFS), fall back to the strict
        // target+tag match and say so in the log; the record-side gap above
        // is never tolerated, only the filesystem-side gap is documented.
        if (AOp.Identity <> '') and (Inspection.Identity <> '') and
           not SameText(Inspection.Identity, AOp.Identity) then
          Exit(Manual(ATx, Format('refusing to remove "%s": the object identity does ' +
            'not match the recorded Portappix junction; external replacement detected ' +
            'and preserved.', [AOp.HostPath])))
        else if (AOp.Identity <> '') and (Inspection.Identity = '') and
                ATx.IdentityOwnershipRequired then
          Log(Format('WARNING: the recorded identity of "%s" could not be verified ' +
            'because the filesystem supplies no object identity; ownership fell back ' +
            'to the strict target+tag match.', [AOp.HostPath]));
        if not FHostPathOps.DeleteJunction(AOp.HostPath) then
          Exit(Retry(Format('unable to remove the Portappix junction "%s".', [AOp.HostPath])));
        // Verify the removal before reporting success.
        Inspection := FHostPathOps.InspectPath(AOp.HostPath);
        if Inspection.Kind <> rkMissing then
          Exit(Retry(Format('the junction "%s" is still present after removal.',
            [AOp.HostPath])));
        Log(Format('Removed Portappix junction "%s" (ownership verified).', [AOp.HostPath]));
        Exit(uoRestored);
      end;
  else
    Exit(Manual(ATx, 'unknown inspection classification.'));
  end;
end;

function TPortappixTransactionReconciler.ReconcileRegistryBackup(
  const ATx: TPortappixTransaction; const AIndex: Integer;
  const AOp: TPortappixTxOperation): TUndoOutcome;
var
  ExpectedFile: string;
begin
  // Export op: nothing to undo; the backup file must be present and owned.
  ExpectedFile := ATx.RegistryBackupFileName(AIndex);
  if not TPortappixTransaction.SameCanonicalPath(AOp.BackupPath, ExpectedFile) then
    Exit(Manual(ATx, Format('registry backup reference "%s" does not match the ' +
      'transaction-owned file "%s".', [AOp.BackupPath, ExpectedFile])));
  if FRegistryOps = nil then
    Exit(Manual(ATx, 'no registry operations available for recovery.'));

  if TFile.Exists(AOp.BackupPath) then
  begin
    if AOp.Status = opPending then
      ATx.ApplyOperationStatus(AIndex, opDone); // export happened before the crash
    Exit(uoRestored);
  end;

  if AOp.Status = opAbsent then
    Exit(uoRestored); // the key did not exist when the export ran; no file expected

  if AOp.Status in [opPending, opFailed] then
  begin
    // The export never completed; redo it if the key still exists.
    if FRegistryOps.KeyExists(AOp.RegistryKey) then
    begin
      if FRegistryOps.ExportKey(AOp.RegistryKey, AOp.BackupPath) then
      begin
        ATx.ApplyOperationStatus(AIndex, opDone);
        Exit(uoRestored);
      end;
      Exit(Retry(Format('unable to export the host registry key "%s".', [AOp.RegistryKey])));
    end;
    Exit(Manual(ATx, Format('registry backup "%s" is missing and the key "%s" no longer ' +
      'exists; the original state cannot be verified.', [AOp.BackupPath, AOp.RegistryKey])));
  end;

  Exit(Manual(ATx, Format('registry backup "%s" is recorded as done but the file is ' +
    'missing before completion; the journal is inconsistent.', [AOp.BackupPath])));
end;

function TPortappixTransactionReconciler.UndoRegistryDelete(
  const ATx: TPortappixTransaction; const AIndex: Integer;
  const AOp: TPortappixTxOperation): TUndoOutcome;
begin
  if not ValidateRegistryKey(AOp.RegistryKey) then
    Exit(Manual(ATx, Format('registry key "%s" failed validation; refusing to run reg.exe.',
      [AOp.RegistryKey])));
  if FRegistryOps = nil then
    Exit(Manual(ATx, 'no registry operations available for recovery.'));

  if AOp.BackupPath <> '' then
  begin
    if not ValidateOwnedBackup(ATx, AOp.BackupPath) then
      Exit(Manual(ATx, Format('registry backup reference "%s" is not a ' +
        'transaction-owned backup file.', [AOp.BackupPath])));
    if not TFile.Exists(AOp.BackupPath) then
      Exit(Manual(ATx, Format('registry backup "%s" is missing; the key "%s" cannot be ' +
        'restored.', [AOp.BackupPath, AOp.RegistryKey])));
    // Match the proven forward-cleanup order: clear the whole key first (so
    // values the app added after the backup cannot leak onto the host), then
    // re-import the original values. Both steps are idempotent.
    if FRegistryOps.KeyExists(AOp.RegistryKey) then
      if not FRegistryOps.DeleteKey(AOp.RegistryKey) then
        Exit(Retry(Format('unable to clear the key "%s" before restoring its backup; the ' +
          'backup file is retained.', [AOp.RegistryKey])));
    if not FRegistryOps.ImportFile(AOp.BackupPath) then
      Exit(Retry(Format('unable to re-import the registry backup for "%s"; the backup ' +
        'file is retained.', [AOp.RegistryKey])));
    Log(Format('Restored host registry key "%s" from its backup.', [AOp.RegistryKey]));
    Exit(uoRestored);
  end;

  // No backup recorded: the original key did not exist. Restore that state.
  if FRegistryOps.KeyExists(AOp.RegistryKey) then
  begin
    if not FRegistryOps.DeleteKey(AOp.RegistryKey) then
      Exit(Retry(Format('unable to delete the key "%s" that did not exist before the run.',
        [AOp.RegistryKey])));
    Exit(uoRestored);
  end;
  Result := uoRestored;
end;

function TPortappixTransactionReconciler.UndoRegistryRestore(
  const ATx: TPortappixTransaction; const AIndex: Integer;
  const AOp: TPortappixTxOperation): TUndoOutcome;
begin
  if not ValidateRegistryKey(AOp.RegistryKey) then
    Exit(Manual(ATx, Format('registry key "%s" failed validation; refusing to run reg.exe.',
      [AOp.RegistryKey])));
  if not ValidateOwnedBackup(ATx, AOp.BackupPath) then
    Exit(Manual(ATx, Format('registry backup reference "%s" is not a transaction-owned ' +
      'backup file.', [AOp.BackupPath])));
  if AOp.Status = opDone then
    Exit(uoRestored); // verified during the run
  if FRegistryOps = nil then
    Exit(Manual(ATx, 'no registry operations available for recovery.'));
  if not TFile.Exists(AOp.BackupPath) then
    Exit(Manual(ATx, Format('registry backup "%s" is missing; restoration of "%s" cannot ' +
      'be verified.', [AOp.BackupPath, AOp.RegistryKey])));
  if not FRegistryOps.ImportFile(AOp.BackupPath) then
    Exit(Retry(Format('unable to re-import the registry backup for "%s".', [AOp.RegistryKey])));
  Result := uoRestored;
end;

function TPortappixTransactionReconciler.ReconcileTransaction(
  const ATx: TPortappixTransaction): Boolean;
var
  Index: Integer;
  Op: TPortappixTxOperation;
  Outcome: TUndoOutcome;
begin
  // Reverse-order undo: restore operations are applied newest-first so the
  // original host state is rebuilt in the opposite order of mutation.
  Result := True;
  FLastError := '';
  FManualFailure := False;
  for Index := ATx.GetOperationCount - 1 downto 0 do
  begin
    Op := ATx.OperationAt(Index);
    Log(Format('Reconciling op %d (%s/%s)...',
      [Index, TPortappixTransaction.OpKindToString(Op.Kind), TPortappixTransaction.OpStatusToString(Op.Status)]));
    if Op.Status in [opRestored, opAbsent] then
      Continue;
    case Op.Kind of
      okJunctionRemoveOld: Outcome := UndoJunctionRemoveOld(ATx, Op);
      okHostDirBackup:     Outcome := UndoHostDirBackup(ATx, Op);
      okJunctionCreate:    Outcome := UndoJunctionCreate(ATx, Op);
      okRegistryBackup:    Outcome := ReconcileRegistryBackup(ATx, Index, Op);
      okRegistryDelete:    Outcome := UndoRegistryDelete(ATx, Index, Op);
      okJunctionRemove:    Outcome := UndoJunctionCreate(ATx, Op);
      okHostDirRestore:    Outcome := UndoHostDirBackup(ATx, Op);
      okRegistryRestore:   Outcome := UndoRegistryRestore(ATx, Index, Op);
    else
      Outcome := Manual(ATx, 'unknown operation kind.');
    end;
    case Outcome of
      uoRestored:
        ATx.ApplyOperationStatus(Index, opRestored);
      uoManual:
        begin
          ATx.SetErrorPersisted(FLastError);
          Exit(False);
        end;
      uoRetry:
        begin
          // Transient failure: keep the operation pending for the next
          // recovery pass; never report the transaction as resolved.
          Result := False;
        end;
    end;
  end;
end;

end.
