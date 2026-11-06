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
end BootstrapProofs
