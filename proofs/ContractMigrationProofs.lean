import PlanMigrationProofs
open Aeneas Aeneas.Std RustM pathward
namespace ContractMigrationProofs
open recovery

theorem install_iff (a b c d e f : Bool) :
    contract_install_allowed a b c d e f = ok true ↔
    a = true ∧ b = true ∧ c = true ∧ d = true ∧ e = true ∧ f = true := by
  cases a <;> cases b <;> cases c <;> cases d <;> cases e <;> cases f <;> simp [contract_install_allowed]
theorem missing_rescue_denied (b c d e f : Bool) :
    contract_install_allowed false b c d e f = ok false := rfl
theorem running_source_denied (a c d e f : Bool) :
    contract_install_allowed a false c d e f = ok false := by cases a <;> rfl
theorem pending_jobs_denied (a b d e f : Bool) :
    contract_install_allowed a b false d e f = ok false := by cases a <;> cases b <;> rfl
theorem live_permit_denied (a b c e f : Bool) :
    contract_install_allowed a b c false e f = ok false := by cases a <;> cases b <;> cases c <;> rfl
theorem stale_install_denied (a b c d f : Bool) :
    contract_install_allowed a b c d false f = ok false := by cases a <;> cases b <;> cases c <;> cases d <;> rfl
theorem unverified_contract_denied (a b c d e : Bool) :
    contract_install_allowed a b c d e false = ok false := by cases a <;> cases b <;> cases c <;> cases d <;> cases e <;> rfl

theorem commit_iff (a b c d e f : Bool) :
    contract_commit_allowed a b c d e f = ok true ↔
    a = true ∧ b = true ∧ c = true ∧ d = true ∧ e = true ∧ f = true := by
  cases a <;> cases b <;> cases c <;> cases d <;> cases e <;> cases f <;> simp [contract_commit_allowed]
theorem failed_health_cannot_commit (a b c e f : Bool) :
    contract_commit_allowed a b c false e f = ok false := by cases a <;> cases b <;> cases c <;> rfl
theorem missing_fallback_cannot_commit (a b c d f : Bool) :
    contract_commit_allowed a b c d false f = ok false := by cases a <;> cases b <;> cases c <;> cases d <;> rfl
theorem mixed_running_contract_cannot_commit (a b d e f : Bool) :
    contract_commit_allowed a b false d e f = ok false := by cases a <;> cases b <;> rfl

theorem gate_iff (choice : ContractChoice) (m b r p i : Bool) :
    contract_gate_allowed choice m b r p i = ok true ↔
    choice ≠ ContractChoice.Hold ∧ m = true ∧ b = true ∧ r = true ∧ p = true ∧ i = true := by
  cases choice <;> cases m <;> cases b <;> cases r <;> cases p <;> cases i <;>
    simp [contract_gate_allowed]
theorem held_gate_denied (m b r p i : Bool) :
    contract_gate_allowed ContractChoice.Hold m b r p i = ok false := rfl
theorem old_boot_cannot_start (choice : ContractChoice) (m r p i : Bool) :
    contract_gate_allowed choice m false r p i ≠ ok true := by
  intro h; have := (gate_iff ..).mp h; simp_all
theorem old_request_cannot_start (choice : ContractChoice) (m b p i : Bool) :
    contract_gate_allowed choice m b false p i ≠ ok true := by
  intro h; have := (gate_iff ..).mp h; simp_all
theorem nonmember_cannot_start (choice : ContractChoice) (b r p i : Bool) :
    contract_gate_allowed choice false b r p i ≠ ok true := by
  intro h; have := (gate_iff ..).mp h; simp_all
theorem partially_installed_contract_cannot_start (choice : ContractChoice) (m b r p : Bool) :
    contract_gate_allowed choice m b r p false ≠ ok true := by
  intro h; have := (gate_iff ..).mp h; simp_all

theorem uncommitted_boot_uses_source (f p o : Bool) :
    contract_recovery_choice false f p o true = ok ContractChoice.Source := rfl
theorem uncommitted_never_selects_primary (f p o s : Bool) :
    contract_recovery_choice false f p o s ≠ ok ContractChoice.Primary := by cases s <;> simp [contract_recovery_choice]
theorem failed_primary_uses_verified_fallback (s : Bool) :
    contract_recovery_choice true false false true s = ok ContractChoice.Fallback := rfl
theorem requested_fallback_does_not_restart_primary (p s : Bool) :
    contract_recovery_choice true true p true s = ok ContractChoice.Fallback := rfl
theorem no_verified_role_holds (c f : Bool) :
    contract_recovery_choice c f false false false = ok ContractChoice.Hold := by cases c <;> cases f <;> rfl
theorem primary_requires_commit_and_validation (c f p o s : Bool)
    (h : contract_recovery_choice c f p o s = ok ContractChoice.Primary) :
    c = true ∧ f = false ∧ p = true := by
  cases c <;> cases f <;> cases p <;> cases o <;> cases s <;> simp_all [contract_recovery_choice]
theorem invalid_target_can_restore_source (f : Bool) :
    contract_recovery_choice true f false false true = ok ContractChoice.Source := by cases f <;> rfl

theorem watchdog_iff (c i r : Bool) :
    contract_watchdog_allowed c i r = ok true ↔ c = false ∧ i = true ∧ r = true := by
  cases c <;> cases i <;> cases r <;> simp [contract_watchdog_allowed]
theorem watchdog_cannot_undo_commit (i r : Bool) :
    contract_watchdog_allowed true i r = ok false := rfl
theorem stale_watchdog_denied (c i : Bool) :
    contract_watchdog_allowed c i false = ok false := by cases c <;> cases i <;> rfl

/-- Adapter model after rescue is durable. `installed = none` represents a
partially replaced set of unit files, not an atomic multi-file update. Accurate
service/job observation, gates, locking and fsync are explicit adapter duties. -/
structure State where
  installed : Option Nat
  permit : Option Nat
  running : Option Nat
  rescue : Bool
  sourceKept : Bool

def safe (s : State) : Prop :=
  s.rescue = true ∧ s.sourceKept = true ∧
  (∀ c, s.permit = some c → s.installed = some c) ∧
  (∀ c, s.running = some c → s.installed = some c)

inductive Step : State → State → Prop
  | revoke (s) : Step s {s with permit := none}
  | drain (s) (closed : s.permit = none) : Step s {s with running := none}
  | beginInstall (s) (closed : s.permit = none) (quiet : s.running = none) :
      Step s {s with installed := none}
  | finishInstall (s) (closed : s.permit = none) (quiet : s.running = none) (c) :
      Step s {s with installed := some c}
  | authorize (s) (c) (loaded : s.installed = some c) :
      Step s {s with permit := some c}
  | start (s) (c) (allowed : s.permit = some c) :
      Step s {s with running := some c}
  | processExit (s) : Step s s
  | reboot (s) : Step s {s with permit := none, running := none}

inductive Run : State → State → Prop
  | refl (s) : Run s s
  | next {a b c} : Run a b → Step b c → Run a c

theorem rescue_boundary_safe (source : Nat) :
    safe ⟨some source,some source,some source,true,true⟩ := ⟨rfl,rfl,fun _ h => h,fun _ h => h⟩
theorem step_preserves_contract_safety (a b : State) (h : safe a) (step : Step a b) : safe b := by
  rcases h with ⟨rescue,kept,permit,running⟩
  cases step with
  | revoke => exact ⟨rescue,kept,(fun _ h => nomatch h),running⟩
  | drain closed => exact ⟨rescue,kept,permit,(fun _ h => nomatch h)⟩
  | beginInstall closed quiet =>
      exact ⟨rescue,kept,(fun _ h => nomatch closed.symm.trans h),(fun _ h => nomatch quiet.symm.trans h)⟩
  | finishInstall closed quiet c =>
      exact ⟨rescue,kept,(fun _ h => nomatch closed.symm.trans h),(fun _ h => nomatch quiet.symm.trans h)⟩
  | authorize c loaded => exact ⟨rescue,kept,(fun _ h => loaded.trans h),running⟩
  | start c allowed => exact ⟨rescue,kept,permit,(fun _ h => (permit c allowed).trans h)⟩
  | processExit => exact ⟨rescue,kept,permit,running⟩
  | reboot => exact ⟨rescue,kept,(fun _ h => nomatch h),(fun _ h => nomatch h)⟩
theorem every_interrupted_prefix_safe (a b : State) (h : safe a) (run : Run a b) : safe b := by
  induction run with
  | refl => exact h
  | next _ step ih => exact step_preserves_contract_safety _ _ ih step
theorem partial_install_has_no_start_authority (s : State) (h : safe s) (mixed : s.installed = none) :
    s.permit = none ∧ s.running = none := by
  constructor
  · cases hp : s.permit with
    | none => rfl
    | some c => exact nomatch mixed.symm.trans (h.2.2.1 c hp)
  · cases hr : s.running with
    | none => rfl
    | some c => exact nomatch mixed.symm.trans (h.2.2.2 c hr)
theorem permit_and_running_contract_agree (s : State) (h : safe s) (p r : Nat)
    (hp : s.permit = some p) (hr : s.running = some r) : p = r :=
  Option.some.inj ((h.2.2.1 p hp).symm.trans (h.2.2.2 r hr))
theorem changing_contract_requires_drain (a b : State) (step : Step a b)
    (changed : a.installed ≠ b.installed) : a.permit = none ∧ a.running = none := by
  cases step with
  | beginInstall closed quiet => exact ⟨closed,quiet⟩
  | finishInstall closed quiet c => exact ⟨closed,quiet⟩
  | _ => exact False.elim (changed rfl)
theorem source_and_rescue_survive (a b : State) (h : safe a) (run : Run a b) :
    b.rescue = true ∧ b.sourceKept = true := by
  have s := every_interrupted_prefix_safe _ _ h run
  exact ⟨s.1,s.2.1⟩
theorem reboot_revokes_all_volatile_authority (s : State) :
    ({s with permit := none, running := none} : State).permit = none ∧
    ({s with permit := none, running := none} : State).running = none := ⟨rfl,rfl⟩

end ContractMigrationProofs
