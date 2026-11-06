import PublicationProofs
open Aeneas Aeneas.Std RustM pathward
namespace BootstrapProofs

theorem preparation_iff (r c s j : Bool) :
    bootstrap.preparation_allowed r c s j = ok true ↔ r = true ∧ c = true ∧ s = true ∧ j = true := by
  cases r <;> cases c <;> cases s <;> cases j <;> simp [bootstrap.preparation_allowed]
theorem no_rescue_no_install (c s j : Bool) :
    bootstrap.preparation_allowed false c s j = ok false := rfl
theorem changed_initial_request_denied (r s j : Bool) :
    bootstrap.preparation_allowed r false s j ≠ ok true := by simp [preparation_iff]
theorem candidate_running_denies_prepare (r c j : Bool) :
    bootstrap.preparation_allowed r c false j ≠ ok true := by simp [preparation_iff]
theorem pending_jobs_deny_prepare (r c s : Bool) :
    bootstrap.preparation_allowed r c s false ≠ ok true := by simp [preparation_iff]

theorem package_iff (s e p u : Bool) :
    bootstrap.package_allowed s e p u = ok true ↔ s = true ∧ e = true ∧ p = true ∧ u = true := by
  cases s <;> cases e <;> cases p <;> cases u <;> simp [bootstrap.package_allowed]
theorem tampered_upload_denied (e p u : Bool) :
    bootstrap.package_allowed false e p u = ok false := rfl
theorem stale_upload_denied (s e p : Bool) :
    bootstrap.package_allowed s e p false ≠ ok true := by simp [package_iff]
theorem wrong_profile_configuration_denied (s p u : Bool) :
    bootstrap.package_allowed s false p u ≠ ok true := by simp [package_iff]

theorem asset_iff (k a i e : Bool) :
    bootstrap.asset_allowed k a i e = ok true ↔
    (k = true ∨ a = true) ∧ (i = false ∨ k = false ∨ e = true) := by
  cases k <;> cases a <;> cases i <;> cases e <;> simp [bootstrap.asset_allowed]
theorem unknown_route_denied (i e : Bool) :
    bootstrap.asset_allowed false false i e = ok false := rfl
theorem immutable_collision_denied (a : Bool) :
    bootstrap.asset_allowed true a true false ≠ ok true := by simp [asset_iff]
theorem identical_immutable_asset_allowed (a : Bool) :
    bootstrap.asset_allowed true a true true = ok true := by cases a <;> rfl
theorem restore_iff (s o v : Bool) :
    bootstrap.restore_allowed s o v = ok true ↔ s = true ∧ o = true ∧ v = true := by
  cases s <;> cases o <;> cases v <;> simp [bootstrap.restore_allowed]
theorem newer_edit_not_replaced (s v : Bool) :
    bootstrap.restore_allowed s false v ≠ ok true := by simp [restore_iff]
theorem changed_backend_not_restored (o v : Bool) :
    bootstrap.restore_allowed false o v = ok false := rfl
theorem unverified_backup_not_restored (s o : Bool) :
    bootstrap.restore_allowed s o false ≠ ok true := by simp [restore_iff]

/-- The I/O adapter must preserve these preconditions. Installation steps cannot
authorize the candidate. This model does not prove systemd or filesystem behavior. -/
structure Preparation where
  rescue : Bool
  gates : Bool
  sourceRunning : Bool
  candidatePermit : Bool
inductive Step : Preparation → Preparation → Prop
  | rescue (s) : Step s {s with rescue := true}
  | gate (s) (h : s.rescue = true) : Step s {s with gates := true}
  | finish (s) (h : s.gates = true) : Step s s
theorem preparation_step_preserves_source (a b : Preparation) (h : Step a b) :
    b.sourceRunning = a.sourceRunning := by cases h <;> rfl
theorem preparation_step_does_not_grant_candidate (a b : Preparation) (h : Step a b) :
    b.candidatePermit = a.candidatePermit := by cases h <;> rfl
inductive Run : Preparation → Preparation → Prop
  | stop (s) : Run s s
  | next {a b c} : Step a b → Run b c → Run a c
theorem every_interrupted_preparation_keeps_source (a b : Preparation) (h : Run a b) :
    b.sourceRunning = a.sourceRunning ∧ b.candidatePermit = a.candidatePermit := by
  induction h with
  | stop => exact ⟨rfl, rfl⟩
  | next hs _ ih => exact ⟨ih.1.trans (preparation_step_preserves_source _ _ hs),
      ih.2.trans (preparation_step_does_not_grant_candidate _ _ hs)⟩

def restoreFile (current written previous : Nat) : Nat :=
  if current = written then previous else current
theorem restore_keeps_newer_file (c w p : Nat) (h : c ≠ w) : restoreFile c w p = c := by
  simp [restoreFile,h]
theorem repeated_restore_is_idempotent (c w p : Nat) :
    restoreFile (restoreFile c w p) w p = restoreFile c w p := by
  unfold restoreFile
  split_ifs <;> simp_all
theorem reviewed_asset_iff (c o e : Bool) :
    bootstrap.reviewed_asset_allowed c o e = ok true ↔ c = true ∧ (o = true ∨ e = true) := by
  cases c <;> cases o <;> cases e <;> simp [bootstrap.reviewed_asset_allowed]
theorem reviewed_exception_cannot_escape (o e : Bool) :
    bootstrap.reviewed_asset_allowed false o e = ok false := rfl
theorem unreviewed_exception_denied :
    bootstrap.reviewed_asset_allowed true false false = ok false := rfl
theorem explicit_public_exception_allowed :
    bootstrap.reviewed_asset_allowed true false true = ok true := rfl
theorem bridge_receipt_iff (p b s f : Bool) :
    bootstrap.bridge_receipt_allowed p b s f = ok true ↔
    p = true ∧ b = true ∧ s = true ∧ f = true := by
  cases p <;> cases b <;> cases s <;> cases f <;> simp [bootstrap.bridge_receipt_allowed]
theorem another_policy_receipt_denied (b s f : Bool) :
    bootstrap.bridge_receipt_allowed false b s f = ok false := rfl
theorem previous_boot_receipt_denied (p s f : Bool) :
    bootstrap.bridge_receipt_allowed p false s f ≠ ok true := by simp [bridge_receipt_iff]
theorem previous_bridge_process_receipt_denied (p b f : Bool) :
    bootstrap.bridge_receipt_allowed p b false f ≠ ok true := by simp [bridge_receipt_iff]
theorem stale_bridge_receipt_denied (p b s : Bool) :
    bootstrap.bridge_receipt_allowed p b s false ≠ ok true := by simp [bridge_receipt_iff]

/-- A cooperative-writer model. OS lock lifetime, inode identity, process identity,
and the wrapper's observation of the current bridge are adapter obligations. -/
structure BridgeState where
  readers : Nat
  switching : Bool
  epoch : Nat
def BridgeSafe (s : BridgeState) : Prop := s.switching = true → s.readers = 0
inductive BridgeStep : BridgeState → BridgeState → Prop
  | acquire (s) (h : s.switching = false) : BridgeStep s {s with readers := s.readers + 1}
  | release (s) (h : s.readers > 0) : BridgeStep s {s with readers := s.readers - 1}
  | switch (s) (h : s.readers = 0) (q : s.switching = false) :
      BridgeStep s {s with switching := true, epoch := s.epoch + 1}
  | finish (s) : BridgeStep s {s with switching := false}
theorem bridge_step_preserves_exclusion (a b : BridgeState) (h : BridgeStep a b)
    (safe : BridgeSafe a) : BridgeSafe b := by
  cases h <;> simp_all [BridgeSafe]
theorem bridge_step_epoch_nondecreasing (a b : BridgeState) (h : BridgeStep a b) :
    a.epoch ≤ b.epoch := by
  cases h with
  | acquire => exact Nat.le_refl _
  | release => exact Nat.le_refl _
  | switch => exact Nat.le_succ _
  | finish => exact Nat.le_refl _
inductive BridgeRun : BridgeState → BridgeState → Prop
  | done (s) : BridgeRun s s
  | next {a b c} : BridgeStep a b → BridgeRun b c → BridgeRun a c
theorem every_bridge_interleaving_excludes_writers (a b : BridgeState)
    (h : BridgeRun a b) (safe : BridgeSafe a) : BridgeSafe b := by
  induction h with
  | done => exact safe
  | next step _ ih => exact ih (bridge_step_preserves_exclusion _ _ step safe)
theorem bridge_run_epoch_nondecreasing (a b : BridgeState) (h : BridgeRun a b) :
    a.epoch ≤ b.epoch := by
  induction h with
  | done => exact Nat.le_refl _
  | next step _ ih => exact Nat.le_trans (bridge_step_epoch_nondecreasing _ _ step) ih
def EpochMatches (s : BridgeState) (staged : Nat) : Prop :=
  s.switching = false ∧ staged = s.epoch
theorem switch_rejects_staged_publication (s : BridgeState) :
    ¬ EpochMatches {s with switching := true, epoch := s.epoch + 1} s.epoch := by
  intro h
  exact Bool.noConfusion h.1
theorem rollback_to_same_mode_cannot_revive_stale_upload (before after : BridgeState)
    (h : before.epoch < after.epoch) : ¬ EpochMatches after before.epoch := by
  intro valid
  exact (Nat.ne_of_lt h) valid.2
end BootstrapProofs
