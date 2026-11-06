import RecoveryProofs
open Aeneas Aeneas.Std RustM pathward recovery
namespace GuardUpgradeProofs

def decision (base target : U64) (a b ready compatible stable : Bool) : UpgradeAction :=
  if ready = true ∧ compatible = true ∧ stable = true ∧
      base.val < 18446744073709551615 ∧ target.val = base.val + 1 then
    if a = true ∧ b = true then .Reject
    else if b = true then .Finish else if a = true then .Install else .Reject
  else .Reject

theorem action_eq (base target : U64) (a b ready compatible stable : Bool) :
    upgrade_action base target a b ready compatible stable = ok (decision base target a b ready compatible stable) := by
  by_cases hb : base.val < 18446744073709551615
  · have hm : base ≠ core.num.U64.MAX := by
      intro h; have hv := congrArg UScalar.val h
      simp [core.num.U64.MAX, U64.rMax] at hv
      omega
    obtain ⟨v, hv, hvv, _⟩ := WP.spec_imp_exists (U64.add_bv_spec (x := base) (y := 1#u64) (by scalar_tac))
    have he : target = v ↔ target.val = base.val + 1 := by
      constructor
      · intro h; subst target; simpa using hvv
      · intro h; apply UScalar.eq_of_val_eq; simpa using h.trans hvv.symm
    cases a <;> cases b <;> cases ready <;> cases compatible <;> cases stable <;>
      simp_all [upgrade_action, decision]
    all_goals split <;> rfl
  · have hm : base = core.num.U64.MAX := by
      apply UScalar.eq_of_val_eq
      simp [core.num.U64.MAX, U64.rMax]
      scalar_tac
    cases a <;> cases b <;> cases ready <;> cases compatible <;> cases stable <;>
      simp_all [upgrade_action, decision]

theorem install_iff (base target : U64) (a b r c s : Bool) :
    upgrade_action base target a b r c s = ok .Install ↔
      r = true ∧ c = true ∧ s = true ∧ base.val < 18446744073709551615 ∧
      target.val = base.val + 1 ∧ a = true ∧ b = false := by
  rw [action_eq]
  cases a <;> cases b <;> simp [decision] <;> split <;> simp_all

theorem finish_iff (base target : U64) (a b r c s : Bool) :
    upgrade_action base target a b r c s = ok .Finish ↔
      r = true ∧ c = true ∧ s = true ∧ base.val < 18446744073709551615 ∧
      target.val = base.val + 1 ∧ a = false ∧ b = true := by
  rw [action_eq]
  cases a <;> cases b <;> simp [decision] <;> split <;> simp_all

theorem unready_rejects (base target : U64) (a b c s : Bool) :
    upgrade_action base target a b false c s = ok .Reject := rfl

theorem incompatible_rejects (base target : U64) (a b r s : Bool) :
    upgrade_action base target a b r false s = ok .Reject := by cases r <;> rfl

theorem pending_cutover_rejects (base target : U64) (a b r c : Bool) :
    upgrade_action base target a b r c false = ok .Reject := by cases r <;> cases c <;> rfl

theorem stale_request_rejects (base target : U64) (r c s : Bool) :
    upgrade_action base target false false r c s = ok .Reject := by
  rw [action_eq]; simp [decision]

theorem ambiguous_identity_rejects (base target : U64) (r c s : Bool) :
    upgrade_action base target true true r c s = ok .Reject := by
  rw [action_eq]; simp [decision]

theorem exhausted_epoch_rejects (target : U64) (a b r c s : Bool) :
    upgrade_action 18446744073709551615#u64 target a b r c s = ok .Reject := by
  rw [action_eq]; simp [decision]

theorem cannot_skip_or_rewind (base target : U64) (a b r c s : Bool)
    (wrong : target.val ≠ base.val + 1) :
    upgrade_action base target a b r c s = ok .Reject := by
  rw [action_eq]; simp [decision, wrong]

theorem installed_retry_only_finishes (base target : U64)
    (space : base.val < 18446744073709551615) (next : target.val = base.val + 1) :
    upgrade_action base target false true true true true = ok .Finish := by
  rw [finish_iff]; simp [space, next]

theorem install_strictly_increases_epoch (base target : U64) (a b r c s : Bool)
    (h : upgrade_action base target a b r c s = ok .Install) : base.val < target.val := by
  have hs := (install_iff ..).mp h; omega

/-- Durable immutable bundles, atomic pointer replacement, and compatible unit
adoption are assumptions of this transition model, not filesystem theorems. -/
structure State where
  current : Nat
  ready : Bool
  linked : Bool
  receipt : Bool
  application : Nat
  deriving DecidableEq

def safe (base application : Nat) (s : State) : Prop :=
  (s.current = base ∨ s.current = base + 1) ∧
  (s.current = base + 1 → s.ready = true ∧ s.linked = true) ∧
  s.application = application

def complete (s : State) : State := {s with receipt := true}

inductive Step (base : Nat) : State → State → Prop
  | stage (s) : Step base s {s with ready := true}
  | adopt (s) (h : s.ready = true) : Step base s {s with linked := true}
  | activate (s) (h : s.ready = true ∧ s.linked = true ∧ s.current = base) :
      Step base s {s with current := base + 1}
  | finish (s) (h : s.current = base + 1) : Step base s (complete s)
  | interrupt (s) : Step base s s

inductive Run (base : Nat) : State → State → Prop
  | refl (s) : Run base s s
  | next {a b c} : Run base a b → Step base b c → Run base a c

theorem initial_safe (base app : Nat) : safe base app ⟨base, false, false, false, app⟩ := by
  simp [safe]

theorem step_preserves_safe (base app : Nat) (a b : State)
    (h : safe base app a) (step : Step base a b) : safe base app b := by
  cases step <;> simp_all [safe, complete]

theorem every_interrupted_prefix_safe (base app : Nat) (a b : State)
    (h : safe base app a) (run : Run base a b) : safe base app b := by
  induction run with
  | refl => exact h
  | next prior step ih => exact step_preserves_safe _ _ _ _ ih step

theorem step_never_decreases_epoch (base : Nat) (a b : State) (h : Step base a b) : a.current ≤ b.current := by
  cases h <;> simp_all [complete]

theorem run_never_decreases_epoch (base : Nat) (a b : State) (h : Run base a b) : a.current ≤ b.current := by
  induction h with
  | refl => exact Nat.le_refl _
  | next prior step ih => exact Nat.le_trans ih (step_never_decreases_epoch _ _ _ step)

theorem retries_are_idempotent (s : State) : complete (complete s) = complete s := rfl

theorem installed_generation_has_durable_bundle (base app : Nat) (s : State)
    (h : safe base app s) (new : s.current = base + 1) : s.ready = true ∧ s.linked = true := h.2.1 new

theorem upgrade_preserves_application (base app : Nat) (a b : State)
    (h : safe base app a) (run : Run base a b) : b.application = app :=
  (every_interrupted_prefix_safe _ _ _ _ h run).2.2

end GuardUpgradeProofs
