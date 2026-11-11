unit Portappix.State;

{
  Crash journal for Portappix (Phase 2).

  Each portable-app run is a transaction under Transactions\<txid>\ with a
  durable, strictly-validated transaction.json (schema 2, see
  Portappix.Transactions). The legacy schema-1 run_state.json is migrated on
  recovery: entries become legacy transactions that reuse the proven
  export-before-delete cleanup (TPortableAppRunner.PerformCleanup), and the
  original file is preserved as run_state.json.legacy.

  Cross-process safety: a journal-scoped named mutex serializes transaction
  creation, recovery and completion. An ABANDONED mutex (its owner crashed)
  triggers journal validation and a recovery assessment before new
  transactions may be created — never blind continuation. A lock timeout
  raises EPortappixJournalBusy rather than proceeding unlocked.

  The journal is stored in a user-writable directory; it is NOT tamper-proof
  (see Portappix.Transactions header). Everything loaded from it is strictly
  validated and anything inconsistent fails closed into recoveryRequired.
}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes,
  System.SyncObjs,
  System.DateUtils,
  System.IOUtils,
  System.JSON,
  System.RegularExpressions,
  System.Generics.Collections,
  System.Generics.Defaults,
  Portappix.Common,
  Portappix.Process,
  Portappix.Registry,
  Portappix.Transactions,
  Portappix.Runner;

type
  EPortappixStateError = class(Exception);
  EPortappixJournalBusy = class(EPortappixStateError);

  TPortappixJournal = class(TInterfacedObject, IPortappixJournal)
  private
    FRootPath: string;
    FStateFile: string;
    FTransactionsDir: string;
    FSync: TCriticalSection;
    FStore: TPortappixJournalStore;
    FOwnsStore: Boolean;
    FRegistryOps: IPortappixRegistryOps;
    FHostPathOps: IPortappixHostPathOps;
    FOnLog: TProc<string>;
    procedure Log(const AMessage: string);
    function DataDirFor(const AAppId: string): string;
    function AcquireJournalLock(out AAbandoned: Boolean): THandle;
    procedure ReleaseJournalLock(var AHandle: THandle);
    function ListTransactionIds: TArray<string>;
    function LoadTransaction(const ATxId: string): TPortappixTransaction;
    procedure QuarantineTransaction(const ATxId: string);
    procedure AssessExistingTransactions;
    procedure MigrateLegacyJournal;
    procedure ReconcileAllTransactions;
    function ReconcileOneTransaction(const ATx: TPortappixTransaction): Boolean;
    function RecoverLegacyTransaction(const ATx: TPortappixTransaction): Boolean;
    procedure RestoreScannedBackups(const ADataDir: string);
    function GetOnLog: TProc<string>;
    procedure SetOnLog(const AValue: TProc<string>);
  public
    constructor Create(const ARootPath: string = '';
      const ARegistryOps: IPortappixRegistryOps = nil;
      const AHostPathOps: IPortappixHostPathOps = nil;
      const AStore: TPortappixJournalStore = nil);
    destructor Destroy; override;

    function BeginTransaction(const AAppId: string): IPortappixTransaction;
    procedure RecoverPendingCleanups;

    property RootPath: string read FRootPath;
    property LegacyStateFile: string read FStateFile;
    property TransactionsDirectory: string read FTransactionsDir;
    property OnLog: TProc<string> read GetOnLog write SetOnLog;
  end;

implementation

function TryGetObjectValue(const AObject: TJSONObject; const AName: string;
  out AValue: TJSONObject): Boolean;
var
  Value: TJSONValue;
begin
  AValue := nil;
  if AObject = nil then
    Exit(False);

  Value := AObject.GetValue(AName);
  Result := (Value <> nil) and (Value is TJSONObject);
  if Result then
    AValue := TJSONObject(Value);
end;

{ TPortappixJournal }

constructor TPortappixJournal.Create(const ARootPath: string;
  const ARegistryOps: IPortappixRegistryOps; const AHostPathOps: IPortappixHostPathOps;
  const AStore: TPortappixJournalStore);
begin
  inherited Create;
  FSync := TCriticalSection.Create;
  FRootPath := ResolveRootPath(ARootPath);
  FStateFile := TPath.Combine(FRootPath, 'run_state.json');
  FTransactionsDir := TPath.Combine(FRootPath, 'Transactions');
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
  if ARegistryOps <> nil then
    FRegistryOps := ARegistryOps
  else
    FRegistryOps := TPortappixRegistryOps.Create;
  if AHostPathOps <> nil then
    FHostPathOps := AHostPathOps
  else
    FHostPathOps := TPortappixHostPathOps.Create;
end;

destructor TPortappixJournal.Destroy;
begin
  FRegistryOps := nil;
  FHostPathOps := nil;
  if FOwnsStore then
    FStore.Free;
  FSync.Free;
  inherited;
end;

procedure TPortappixJournal.Log(const AMessage: string);
begin
  if Assigned(FOnLog) then
    FOnLog(AMessage);
end;

function TPortappixJournal.GetOnLog: TProc<string>;
begin
  Result := FOnLog;
end;

procedure TPortappixJournal.SetOnLog(const AValue: TProc<string>);
begin
  FOnLog := AValue;
end;

function TPortappixJournal.DataDirFor(const AAppId: string): string;
begin
  Result := TPath.Combine(TPath.Combine(FRootPath, 'Data'), AAppId);
end;

function TPortappixJournal.AcquireJournalLock(out AAbandoned: Boolean): THandle;
var
  Handle: THandle;
  WaitResult: DWORD;
  Attempt: Integer;
begin
  // Journal-scoped mutex (distinct from the launcher and per-app mutexes so
  // a headless --run can proceed while the tray launcher is running, while
  // journal mutations stay serialized across processes). Windows releases
  // an abandoned mutex when its owner dies; WAIT_ABANDONED means we own the
  // mutex but the previous holder may have died mid-update, so callers must
  // validate the journal before continuing.
  Result := 0;
  AAbandoned := False;
  for Attempt := 1 to 2 do
  begin
    Handle := CreateMutex(nil, False,
      PChar(MutexNameFor('Journal', FRootPath.ToLower)));
    if Handle = 0 then
      raise EPortappixStateError.Create('Unable to create the journal mutex.');
    WaitResult := WaitForSingleObject(Handle, 5000);
    case WaitResult of
      WAIT_OBJECT_0:
        Exit(Handle);
      WAIT_ABANDONED:
        begin
          Log('The journal mutex was abandoned by a previous launcher; the journal ' +
            'will be validated before it is used.');
          ReleaseMutex(Handle);
          CloseHandle(Handle);
          Handle := 0;
          if Attempt = 1 then
          begin
            AAbandoned := True;
            Continue;
          end;
          raise EPortappixStateError.Create(
            'The journal mutex keeps being abandoned; the journal could not be ' +
            'stabilized. Manual inspection of the Transactions folder is required.');
        end;
      WAIT_TIMEOUT:
        begin
          CloseHandle(Handle);
          raise EPortappixJournalBusy.Create(
            'Another Portappix process is holding the journal lock; try again later.');
        end;
    else
      CloseHandle(Handle);
      raise EPortappixStateError.CreateFmt(
        'Waiting for the journal mutex failed (error %u).', [GetLastError]);
    end;
  end;
end;

procedure TPortappixJournal.ReleaseJournalLock(var AHandle: THandle);
begin
  if AHandle <> 0 then
  begin
    ReleaseMutex(AHandle);
    CloseHandle(AHandle);
    AHandle := 0;
  end;
end;

function TPortappixJournal.ListTransactionIds: TArray<string>;
var
  Directories: TArray<string>;
  Ids: TList<string>;
  DirectoryName: string;
begin
  Ids := TList<string>.Create;
  try
    if TDirectory.Exists(FTransactionsDir) then
    begin
      Directories := TDirectory.GetDirectories(FTransactionsDir);
      for DirectoryName in Directories do
        if TPortappixTransaction.ValidateTxId(
          TPath.GetFileName(ExcludeTrailingPathDelimiter(DirectoryName))) then
          Ids.Add(TPath.GetFileName(ExcludeTrailingPathDelimiter(DirectoryName)))
        else
          Log(Format('Ignoring "%s": not a Portappix transaction directory.',
            [DirectoryName]));
    end;
    Result := Ids.ToArray;
  finally
    Ids.Free;
  end;
end;

procedure TPortappixJournal.QuarantineTransaction(const ATxId: string);
var
  DirectoryName, Primary, Quarantine: string;
begin
  // Preserve corrupt journals for diagnosis; never delete them and never
  // attempt destructive recovery from them.
  DirectoryName := TPath.Combine(FTransactionsDir, ATxId);
  Primary := TPath.Combine(DirectoryName, 'transaction.json');
  if TFile.Exists(Primary) then
  begin
    Quarantine := Primary + '.bad';
    try
      if TFile.Exists(Quarantine) then
        TFile.Delete(Quarantine);
      TFile.Move(Primary, Quarantine);
      Log(Format('The journal for transaction "%s" is corrupt; it was preserved as %s.',
        [ATxId, Quarantine]));
    except
      on E: Exception do
        Log(Format('Unable to quarantine the corrupt journal for "%s": %s',
          [ATxId, E.Message]));
    end;
  end;
end;

function TPortappixJournal.LoadTransaction(
  const ATxId: string): TPortappixTransaction;
var
  Transaction: TPortappixTransaction;
begin
  Result := nil;
  Transaction := TPortappixTransaction.Create(FStore,
    TPath.Combine(FTransactionsDir, ATxId), ATxId, '', 0, txPreparing, '');
  try
    Transaction.OnLog := FOnLog;
    if not Transaction.Load then
    begin
      // Neither transaction.json nor the .prev copy exists: treat as
      // corrupt/abandoned and quarantine (nothing was restored from it).
      Transaction.Free;
      QuarantineTransaction(ATxId);
      Exit;
    end;

    // Fail closed on a dataDir outside the app's Portappix-owned directory.
    if not TPortappixTransaction.ValidateDataDir(Transaction.DataDir, FRootPath,
      Transaction.AppId) then
    begin
      Transaction.SetErrorPersisted(Format(
        'The journal dataDir "%s" is outside the Portappix-owned application ' +
        'directory; refusing to use it.', [Transaction.DataDir]));
      Transaction.ApplyState(txRecoveryRequired);
      Log(Format('Transaction "%s" failed dataDir validation; manual intervention required.',
        [ATxId]));
    end;
    Result := Transaction;
  except
    on E: Exception do
    begin
      Transaction.Free;
      QuarantineTransaction(ATxId);
      Log(Format('Transaction "%s" could not be loaded: %s', [ATxId, E.Message]));
    end;
  end;
end;

procedure TPortappixJournal.AssessExistingTransactions;
var
  TxId: string;
  Transaction: TPortappixTransaction;
begin
  // Called under the journal lock before a new transaction is created: an
  // incomplete recovery blocks new host work entirely.
  for TxId in ListTransactionIds do
  begin
    Transaction := LoadTransaction(TxId);
    if Transaction = nil then
      Continue;
    try
      if Transaction.State = txRecoveryRequired then
        raise EPortappixStateError.CreateFmt(
          'Transaction "%s" (app "%s") requires manual intervention before new ' +
          'applications can run: %s See ' +
          'docs/security/JOURNAL_TRANSACTION_AND_RECOVERY.md for the manual ' +
          'recovery procedure.',
          [TxId, Transaction.AppId, Transaction.LastError]);
      if SameText(Transaction.AppId, '') then
        Continue;
    finally
      Transaction.Free;
    end;
  end;
end;

function TPortappixJournal.BeginTransaction(
  const AAppId: string): IPortappixTransaction;
var
  Lock: THandle;
  Abandoned: Boolean;
  Transaction: TPortappixTransaction;
  TxId, TxDir: string;
  Existing: TPortappixTransaction;
begin
  if (AAppId = '') or not IsSafeFileComponent(AAppId) then
    raise EPortappixStateError.CreateFmt('Invalid app id "%s".', [AAppId]);

  Result := nil;
  Transaction := nil;
  TxDir := '';
  FSync.Enter;
  try
    try
    Lock := AcquireJournalLock(Abandoned);
    try
      if Abandoned then
      begin
        // The previous lock owner may have died mid-update: run the full
        // recovery assessment before any new transaction is created.
        MigrateLegacyJournal;
        ReconcileAllTransactions;
      end;

      // Refuse new work while any recovery requires manual intervention, and
      // while the same app already has an unfinished transaction.
      for TxId in ListTransactionIds do
      begin
        Existing := LoadTransaction(TxId);
        if Existing = nil then
          Continue;
        try
          if Existing.State = txRecoveryRequired then
            raise EPortappixStateError.CreateFmt(
              'Transaction "%s" (app "%s") requires manual intervention before new ' +
              'applications can run: %s',
              [TxId, Existing.AppId, Existing.LastError]);
          if SameText(Existing.AppId, AAppId) then
            raise EPortappixStateError.CreateFmt(
              'App "%s" already has an unfinished transaction ("%s"); recover it first.',
              [AAppId, TxId]);
        finally
          Existing.Free;
        end;
      end;

      ForceDirectories(FTransactionsDir);
      TxId := TPortappixTransaction.NewTxId(AAppId);
      TxDir := TPath.Combine(FTransactionsDir, TxId);
      TDirectory.CreateDirectory(TxDir);
      // Phase 3 provenance: every journal written by this build carries
      // "junctionOwnership": "identity" from its FIRST durable persist,
      // before any junction operation exists. This is what positively
      // distinguishes new Phase 3 transactions from Phase 2 journals: a
      // Phase 3 transaction can never be classified as legacy because an
      // optional field is missing, so the reconciler may require the
      // persisted creation identity even after a crash-missed
      // MarkJunctionCreated persist.
      Transaction := TPortappixTransaction.Create(FStore, TxDir, TxId, AAppId,
        Now, txPreparing, DataDirFor(AAppId), False,
        PortappixOwnershipFieldIdentity);
      Transaction.OnLog := FOnLog;
      Transaction.Persist;               // 'preparing' is durable on disk
      Transaction.ApplyState(txPrepared); // intent complete; mutations may begin
      Result := Transaction;
      Transaction := nil;
    finally
      ReleaseJournalLock(Lock);
    end;
    except
      // Never leave a half-created transaction behind.
      try
        Transaction.Free;
      except
      end;
      if (TxDir <> '') and TDirectory.Exists(TxDir) then
        try
          TDirectory.Delete(TxDir, True);
        except
        end;
      raise;
    end;
  finally
    FSync.Leave;
  end;
end;

procedure TPortappixJournal.RecoverPendingCleanups;
var
  Lock: THandle;
  Abandoned: Boolean;
begin
  FSync.Enter;
  try
    Lock := AcquireJournalLock(Abandoned);
    try
      MigrateLegacyJournal;
      ReconcileAllTransactions;
    finally
      ReleaseJournalLock(Lock);
    end;
  finally
    FSync.Leave;
  end;
end;

procedure TPortappixJournal.MigrateLegacyJournal;
var
  Content: string;
  RootValue, AppsValue, EntryValue: TJSONValue;
  RootObject, AppsObject, EntryObject: TJSONObject;
  Pair: TJSONPair;
  AppId, DataDir, TxId: string;
  Keys, Junctions: TArray<string>;
  Transaction: TPortappixTransaction;
  Index, KeyIndex, JunctionIndex: Integer;

  function ReadStringArray(const AEntry: TJSONObject;
    const AName: string): TArray<string>;
  var
    Value: TJSONValue;
    ValuesArray: TJSONArray;
    Values: TList<string>;
    Item: TJSONValue;
  begin
    Result := nil;
    Value := AEntry.GetValue(AName);
    if not (Value is TJSONArray) then
      Exit;
    ValuesArray := TJSONArray(Value);
    Values := TList<string>.Create;
    try
      for Item in ValuesArray do
        if (Item is TJSONString) and (Item.Value.Trim <> '') then
          Values.Add(Item.Value.Trim);
      Result := Values.ToArray;
    finally
      Values.Free;
    end;
  end;

begin
  if not TFile.Exists(FStateFile) then
    Exit;

  // Read the legacy schema-1 journal tolerantly. A corrupt file is left in
  // place (a copy is kept as .bad) — migration never destroys it.
  try
    Content := TFile.ReadAllText(FStateFile, TEncoding.UTF8);
  except
    on E: Exception do
    begin
      Log('Unable to read the legacy run_state.json: ' + E.Message);
      Exit;
    end;
  end;

  RootValue := TJSONObject.ParseJSONValue(Content);
  if RootValue = nil then
  begin
    if not TFile.Exists(FStateFile + '.bad') then
      try
        TFile.Copy(FStateFile, FStateFile + '.bad', True);
        Log('The legacy run_state.json is corrupt; a copy was kept as run_state.json.bad.');
      except
      end
    else
      Log('The legacy run_state.json is corrupt; it is kept for manual inspection.');
    Exit;
  end;

  try
    if not (RootValue is TJSONObject) then
      Exit;
    RootObject := TJSONObject(RootValue);
    AppsValue := RootObject.GetValue('apps');
    if not (AppsValue is TJSONObject) then
      Exit;
    AppsObject := TJSONObject(AppsValue);

    Log('Migrating the legacy run_state.json to transaction journals...');
    for Index := 0 to AppsObject.Count - 1 do
    begin
      Pair := AppsObject.Pairs[Index];
      if Pair = nil then
        Continue;
      if Pair.JsonString = nil then
        Continue;
      AppId := Pair.JsonString.Value;
      if (AppId = '') or not TPortappixTransaction.ValidTxAppId(AppId) then
      begin
        Log(Format('Legacy journal entry "%s" has an invalid app id; it was not ' +
          'migrated and needs manual review.', [AppId]));
        Continue;
      end;
      EntryValue := Pair.JsonValue;
      if not (EntryValue is TJSONObject) then
        Continue;
      EntryObject := TJSONObject(EntryValue);

      // Registry keys: normalize and validate; unusable entries are dropped
      // (never invented) with a log line.
      Keys := ReadStringArray(EntryObject, 'hijackedKeys');
      for KeyIndex := Length(Keys) - 1 downto 0 do
        if not TPortappixTransactionReconciler.ValidateRegistryKey(Keys[KeyIndex]) then
        begin
          Log(Format('Legacy key "%s" for app "%s" is not a valid HKCU path; ' +
            'manual review required.', [Keys[KeyIndex], AppId]));
          // Keep the key out of the migrated payload rather than risking a
          // reg.exe call with an unvalidated path.
          Keys[KeyIndex] := '';
        end;

      Junctions := ReadStringArray(EntryObject, 'junctions');
      for JunctionIndex := Length(Junctions) - 1 downto 0 do
        if not TPortappixTransaction.ValidateHostPath(Junctions[JunctionIndex]) then
        begin
          Log(Format('Legacy junction path "%s" for app "%s" failed validation; ' +
            'manual review required.', [Junctions[JunctionIndex], AppId]));
          Junctions[JunctionIndex] := '';
        end;

      // The recorded dataDir is redundant and untrusted: only the derived
      // Portappix-owned directory is ever used.
      DataDir := '';
      if EntryObject.GetValue('dataDir') is TJSONString then
        DataDir := TJSONString(EntryObject.GetValue('dataDir')).Value;
      if (DataDir = '') or
         not TPortappixTransaction.ValidateDataDir(DataDir, FRootPath, AppId) then
      begin
        if DataDir <> '' then
          Log(Format('Legacy dataDir "%s" for app "%s" is not the Portappix-owned ' +
            'directory; the derived location is used instead.', [DataDir, AppId]));
        DataDir := DataDirFor(AppId);
      end;

      // Legacy entries are ambiguous by nature (the app may or may not have
      // run), so they become transactions in hostStateChanging with the
      // legacy payload preserved verbatim; recovery applies the proven
      // export-before-delete cleanup and keeps backups until confirmed.
      TxId := TPortappixTransaction.NewTxId(AppId);
      Transaction := TPortappixTransaction.Create(FStore,
        TPath.Combine(FTransactionsDir, TxId), TxId, AppId, Now,
        txHostStateChanging, DataDir, True);
      try
        Transaction.OnLog := FOnLog;
        Transaction.SetLegacyPayload(Keys, Junctions);
        Transaction.Persist;
        Log(Format('Migrated legacy journal entry for "%s" into transaction "%s".',
          [AppId, Transaction.TxId]));
      finally
        Transaction.Free;
      end;
    end;
  finally
    RootValue.Free;
  end;

  // Preserve the original journal and remove it so migration runs once.
  try
    TFile.Copy(FStateFile, FStateFile + '.legacy', True);
    TFile.Delete(FStateFile);
  except
    on E: Exception do
      Log('Unable to archive the legacy run_state.json (migration will be retried): ' +
        E.Message);
  end;
end;

procedure TPortappixJournal.RestoreScannedBackups(const ADataDir: string);
var
  BackupFile: string;
begin
  // Legacy behaviour: import any remaining host backup file found in the
  // app's data directory, deleting it only after a successful import.
  if (ADataDir = '') or not TDirectory.Exists(ADataDir) then
    Exit;

  for BackupFile in TDirectory.GetFiles(ADataDir, 'host_backup_*.reg') do
  begin
    Log('Restoring scanned host registry backup: ' + BackupFile);
    try
      if FRegistryOps.ImportFile(BackupFile) then
      begin
        try
          TFile.Delete(BackupFile);
        except
          on E: Exception do
            Log('Unable to delete restored backup "' + BackupFile + '": ' + E.Message);
        end;
      end
      else
        Log('reg.exe import failed for host backup: ' + BackupFile);
    except
      on E: Exception do
        Log('Unable to restore scanned host registry backup "' + BackupFile + '": ' +
          E.Message);
    end;
  end;
end;

function TPortappixJournal.RecoverLegacyTransaction(
  const ATx: TPortappixTransaction): Boolean;
var
  Keys, Junctions: TArray<string>;
  Key, Junction: string;
  BackupFiles: TArray<string>;
  Index: Integer;
  UnexpectedBackup: Boolean;
  ExpectedName: string;
begin
  // Legacy schema-1 semantics, unchanged: export the hijacked keys into the
  // portable registry BEFORE deleting them, restore the recorded junctions,
  // and import every remaining host backup file. The transaction completes
  // only when no host backups remain.
  Keys := nil;
  for Key in ATx.LegacyKeys do
    if (Key <> '') and TPortappixTransactionReconciler.ValidateRegistryKey(Key) then
    begin
      SetLength(Keys, Length(Keys) + 1);
      Keys[High(Keys)] := Key;
    end;

  Junctions := nil;
  for Junction in ATx.LegacyJunctions do
    if (Junction <> '') and TPortappixTransaction.ValidateHostPath(Junction) then
    begin
      SetLength(Junctions, Length(Junctions) + 1);
      Junctions[High(Junctions)] := Junction;
    end;

  TPortableAppRunner.PerformCleanup(ATx.AppId, Keys, Junctions, ATx.DataDir,
    FOnLog, FRegistryOps, FHostPathOps);
  RestoreScannedBackups(ATx.DataDir);

  if TDirectory.Exists(ATx.DataDir) then
    BackupFiles := TDirectory.GetFiles(ATx.DataDir, 'host_backup_*.reg')
  else
    SetLength(BackupFiles, 0);

  // Any backup file with an unexpected name is flagged for manual review
  // instead of being silently imported; expected ones are retryable.
  UnexpectedBackup := False;
  for Index := 0 to High(BackupFiles) do
  begin
    ExpectedName := TPath.GetFileName(BackupFiles[Index]);
    if not TRegex.IsMatch(LowerCase(ExpectedName), '^host_backup_[0-9]+\.reg$') then
    begin
      Log(Format('Unexpected backup file "%s"; manual review required.', [ExpectedName]));
      UnexpectedBackup := True;
    end;
  end;
  if UnexpectedBackup then
  begin
    ATx.SetErrorPersisted('Unexpected host backup file name(s); manual review required.');
    Exit(False);
  end;

  if Length(BackupFiles) > 0 then
  begin
    ATx.SetErrorPersisted(Format('%d host registry backup file(s) remain; the legacy ' +
      'recovery will be retried.', [Length(BackupFiles)]));
    Exit(False);
  end;

  if ATx.State <> txCleaning then
    ATx.ApplyState(txCleaning);
  ATx.ApplyState(txCompleted);
  ATx.RemoveTransactionDirectory;
  Log(Format('Legacy transaction for "%s" recovered.', [ATx.AppId]));
  Result := True;
end;

procedure TPortappixJournal.ReconcileAllTransactions;
var
  TxIds: TArray<string>;
  Transactions: TList<TPortappixTransaction>;
  Transaction: TPortappixTransaction;
  TxId: string;
begin
  Transactions := TList<TPortappixTransaction>.Create;
  try
    for TxId in ListTransactionIds do
    begin
      Transaction := LoadTransaction(TxId);
      if Transaction <> nil then
        Transactions.Add(Transaction);
    end;

    // Oldest first so recovery follows the original mutation order.
    Transactions.Sort(TComparer<TPortappixTransaction>.Construct(
      function(const Left, Right: TPortappixTransaction): Integer
      begin
        Result := CompareDateTime(Left.CreatedAt, Right.CreatedAt);
      end));

    for Transaction in Transactions do
    begin
      case Transaction.State of
        txPreparing:
          begin
            // Nothing host-visible happens before 'prepared'; the durable
            // 'preparing' record means creation itself was interrupted.
            Log(Format('Discarding transaction "%s" (state preparing; no host state ' +
              'was touched).', [Transaction.TxId]));
            Transaction.RemoveTransactionDirectory;
          end;
        txCompleted:
          begin
            Log(Format('Finalizing completed transaction "%s".', [Transaction.TxId]));
            Transaction.RemoveTransactionDirectory;
          end;
        txRecoveryRequired:
          Log(Format('Transaction "%s" (app "%s") requires MANUAL INTERVENTION: %s',
            [Transaction.TxId, Transaction.AppId, Transaction.LastError]));
      else
        begin
          if IsAppRunning(FRootPath, Transaction.AppId) then
          begin
            Log(Format('Skipping recovery for "%s" because the app is currently running.',
              [Transaction.AppId]));
            Continue;
          end;
          ReconcileOneTransaction(Transaction);
        end;
      end;
    end;
  finally
    for Transaction in Transactions do
      Transaction.Free;
    Transactions.Free;
  end;
end;

function TPortappixJournal.ReconcileOneTransaction(
  const ATx: TPortappixTransaction): Boolean;
var
  Reconciler: TPortappixTransactionReconciler;
  KeysList: TList<string>;
  Index: Integer;
  Op: TPortappixTxOperation;
begin
  Reconciler := TPortappixTransactionReconciler.Create(FRegistryOps, FHostPathOps, FOnLog);
  try
    if ATx.Legacy then
      Exit(RecoverLegacyTransaction(ATx));

    if (ATx.State in [txRunning, txCleaning]) and (ATx.DataDir <> '') and TDirectory.Exists(ATx.DataDir) then
    begin
      KeysList := TList<string>.Create;
      try
        for Index := 0 to ATx.GetOperationCount - 1 do
        begin
          Op := ATx.OperationAt(Index);
          if (Op.Kind in [okRegistryBackup, okRegistryDelete]) and (Op.RegistryKey <> '') then
            if not KeysList.Contains(Op.RegistryKey) then
              KeysList.Add(Op.RegistryKey);
        end;
        if KeysList.Count > 0 then
          ExportKeysToRegistryFile(FRegistryOps, KeysList.ToArray, ATx.DataDir, FOnLog);
      finally
        KeysList.Free;
      end;
    end;

    if not Reconciler.ReconcileTransaction(ATx) then
    begin
      if Reconciler.ManualFailure then
      begin
        ATx.ApplyState(txRecoveryRequired);
        Log(Format('Transaction "%s" is now recoveryRequired; manual intervention is ' +
          'required before new applications can run.', [ATx.TxId]));
      end
      else
        ATx.SetErrorPersisted('Recovery incomplete: ' + Reconciler.LastError);
      Exit(False);
    end;

    if not ATx.AllOperationsResolved then
    begin
      ATx.SetErrorPersisted('Recovery incomplete: some operations are not resolved; ' +
        'they will be retried.');
      Exit(False);
    end;

    if ATx.State <> txCleaning then
      ATx.ApplyState(txCleaning);
    ATx.ApplyState(txCompleted);
    ATx.RemoveTransactionDirectory;
    Log(Format('Transaction "%s" recovered and completed.', [ATx.TxId]));
    Result := True;
  finally
    Reconciler.Free;
  end;
end;

end.
