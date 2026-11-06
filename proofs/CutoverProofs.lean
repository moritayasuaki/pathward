import RuntimeProofs
open Aeneas Aeneas.Std RustM pathward
namespace CutoverProofs

theorem stop_old_eq (pending armed preflight unchanged : Bool) :
    cutover.stop_old_allowed pending armed preflight unchanged = ok
      (decide (pending = true ∧ armed = true ∧ preflight = true ∧ unchanged = true)) := by
  cases pending <;> cases armed <;> cases preflight <;> cases unchanged <;> rfl

theorem cannot_stop_without_guard (pending preflight unchanged : Bool) :
    cutover.stop_old_allowed pending false preflight unchanged = ok false := by
  simp [stop_old_eq]

theorem window_eq (boot : Bool) (started now : U64) :
    cutover.window_allowed boot started now = ok (decide
      (boot = true ∧ started.val ≤ now.val ∧ now.val < started.val + 900000000000)) := by
  cases boot
  · simp [cutover.window_allowed]
  · by_cases h : started.val ≤ now.val
    · obtain ⟨v, hv, he, _⟩ := WP.spec_imp_exists (U64.sub_bv_spec (x := now) (y := started) h)
      have bound : (now.val - started.val < 900000000000) ↔ now.val < started.val + 900000000000 := by omega
      simp [cutover.window_allowed, h, hv, he, bound]
    · simp [cutover.window_allowed, h]

theorem deadline_and_boot_required (boot : Bool) (started now : U64)
    (h : cutover.window_allowed boot started now = ok true) :
    boot = true ∧ started.val ≤ now.val ∧ now.val - started.val < 900000000000 := by
  simp [window_eq] at h
  exact ⟨h.1, h.2.1, by omega⟩

theorem reboot_cannot_commit (started now : U64) :
    cutover.window_allowed false started now = ok false := rfl

theorem expired_cannot_commit (boot : Bool) (started now : U64)
    (h : started.val + 900000000000 ≤ now.val) :
    cutover.window_allowed boot started now = ok false := by
  simp [window_eq]
  omega

theorem backwards_clock_denied (boot : Bool) (started now : U64) (h : now.val < started.val) :
    cutover.window_allowed boot started now = ok false := by
  simp [window_eq]
  omega

theorem commit_eq (awaiting verified window armed : Bool) :
    cutover.commit_allowed awaiting verified window armed = ok
      (decide (awaiting = true ∧ verified = true ∧ window = true ∧ armed = true)) := by
  cases awaiting <;> cases verified <;> cases window <;> cases armed <;> rfl

theorem commit_requires_all_checks (awaiting verified window armed : Bool)
    (h : cutover.commit_allowed awaiting verified window armed = ok true) :
    awaiting = true ∧ verified = true ∧ window = true ∧ armed = true := by
  simpa [commit_eq] using h

theorem disarm_eq (committed : Bool) (persisted current : U64) :
    cutover.disarm_allowed committed persisted current = ok
      (decide (committed = true ∧ 0 < current.val ∧ persisted = current)) := by
  cases committed <;> simp [cutover.disarm_allowed]
  split_ifs <;> simp_all

theorem disarm_requires_same_durable_epoch (committed : Bool) (persisted current : U64)
    (h : cutover.disarm_allowed committed persisted current = ok true) :
    committed = true ∧ 0 < current.val ∧ persisted = current := by
  simpa [disarm_eq] using h

theorem stale_commit_cannot_disarm (committed : Bool) (persisted current : U64)
    (stale : persisted ≠ current) : cutover.disarm_allowed committed persisted current = ok false := by
  simp [disarm_eq, stale]

theorem watchdog_eq (committed prepared restored : Bool) :
    cutover.watchdog_required committed prepared restored = ok
      (decide (committed = false ∧ prepared = false ∧ restored = false)) := by
  cases committed <;> cases prepared <;> cases restored <;> rfl

theorem watchdog_preserves_commit (prepared restored : Bool) :
    cutover.watchdog_required true prepared restored = ok false := rfl

theorem gates_total (boot : Bool) (started now : U64) :
    ∃ b, cutover.window_allowed boot started now = ok b := ⟨_, window_eq boot started now⟩

/-- Controller-process failure model. Atomic record writes and an independent
systemd watchdog are premises of these transitions. Host reboot, torn storage,
external service changes and subprocess success are not proved here. -/
inductive Phase | prepared | pending | awaiting | committed | restored
  deriving DecidableEq

structure State where
  phase : Phase
  guard : Bool
  oldStopped : Bool
  verified : Bool
  epoch : U64
  durableEpoch : U64

def Safe (s : State) : Prop :=
  (s.oldStopped = true ∧ s.phase ≠ .committed → s.guard = true) ∧
  (s.phase = .committed → s.durableEpoch = s.epoch)

theorem prepared_is_safe (epoch : U64) :
    Safe ⟨.prepared, false, false, false, epoch, 0#u64⟩ := by simp [Safe]

inductive Step : State → State → Prop
  | begin (s : State) (phase : s.phase = .prepared) (old : s.oldStopped = false) :
      Step s { s with phase := .pending }
  | arm (s : State) (phase : s.phase = .pending) : Step s { s with guard := true }
  | stopOld (s : State) (preflight unchanged : Bool)
      (gate : cutover.stop_old_allowed (decide (s.phase = .pending)) s.guard preflight unchanged = ok true) :
      Step s { s with oldStopped := true }
  | ready (s : State) (phase : s.phase = .pending) (guard : s.guard = true) :
      Step s { s with phase := .awaiting, verified := true }
  | persist (s : State) (window : Bool)
      (gate : cutover.commit_allowed (decide (s.phase = .awaiting)) s.verified window s.guard = ok true) :
      Step s { s with phase := .committed, durableEpoch := s.epoch }
  | disarm (s : State)
      (gate : cutover.disarm_allowed (decide (s.phase = .committed)) s.durableEpoch s.epoch = ok true) :
      Step s { s with guard := false }
  | watchdog (s : State)
      (gate : cutover.watchdog_required (decide (s.phase = .committed))
        (decide (s.phase = .prepared)) (decide (s.phase = .restored)) = ok true) :
      Step s { s with phase := .restored, guard := false, oldStopped := false, verified := false }
  | processCrash (s : State) : Step s { s with verified := false }

theorem step_preserves_guard_coverage (before after : State) (step : Step before after)
    (safe : Safe before) : Safe after := by
  cases step with
  | begin phase old => simp [Safe, old]
  | arm phase => simp [Safe, phase]
  | stopOld preflight unchanged gate =>
      have h := gate
      simp [stop_old_eq] at h
      simp [Safe, h.1, h.2.1]
  | ready phase guard => simp [Safe, guard]
  | persist window gate => simp [Safe]
  | disarm gate =>
      have h := disarm_requires_same_durable_epoch _ _ _ gate
      have committed : before.phase = .committed := by simpa using h.1
      simp [Safe, committed, h.2.2]
  | watchdog gate => simp [Safe]
  | processCrash => exact safe

theorem disarm_step_has_commit (before after : State) (step : Step before after)
    (stopped : after.oldStopped = true) (unguarded : after.guard = false)
    (safe : Safe before) : after.phase = .committed ∧ after.durableEpoch = after.epoch := by
  have h := step_preserves_guard_coverage before after step safe
  have committed : after.phase = .committed := by
    by_contra notCommitted
    have := h.1 ⟨stopped, notCommitted⟩
    simp [unguarded] at this
  exact ⟨committed, h.2 committed⟩

inductive Run : State → State → Prop
  | nil (s : State) : Run s s
  | cons {a b c : State} (head : Step a b) (tail : Run b c) : Run a c

theorem process_failures_keep_guard (first last : State) (run : Run first last)
    (safe : Safe first) : Safe last := by
  induction run with
  | nil => exact safe
  | cons head tail ih => exact ih (step_preserves_guard_coverage _ _ head safe)

theorem watchdog_cannot_undo_durable_commit (s : State) (committed : s.phase = .committed) :
    cutover.watchdog_required (decide (s.phase = .committed))
      (decide (s.phase = .prepared)) (decide (s.phase = .restored)) = ok false := by
  simp [committed, watchdog_eq]

end CutoverProofs
