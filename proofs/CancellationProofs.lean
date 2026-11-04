import DeliveryProofs
open Aeneas Aeneas.Std RustM pathward
namespace CancellationProofs

theorem head_slot_eq (active : U64) (held : Bool) :
    delivery.head_slot active held = ok (decide (held = false ∧ active.val < 32)) := by
  cases held <;> simp [delivery.head_slot]

theorem held_head_bounded (active : U64) (held : Bool)
    (h : delivery.head_slot active held = ok true) :
    held = false ∧ active.val + 1 ≤ 32 := by
  simp [head_slot_eq] at h
  exact ⟨h.1, by omega⟩

theorem cancellation_wins (elapsed : U64) :
    delivery.held_action true elapsed = ok delivery.HeldAction.Discard := rfl

theorem discard_iff_cancelled (cancelled : Bool) (elapsed : U64) :
    delivery.held_action cancelled elapsed = ok delivery.HeldAction.Discard ↔ cancelled = true := by
  cases cancelled <;> simp [delivery.held_action]
  split_ifs <;> simp

theorem try_admission_iff (cancelled : Bool) (elapsed : U64) :
    delivery.held_action cancelled elapsed = ok delivery.HeldAction.TryAdmission ↔
      cancelled = false ∧ elapsed.val < 5000 := by
  cases cancelled <;> simp [delivery.held_action]

theorem expired_cannot_start (cancelled : Bool) (elapsed : U64)
    (h : 5000 ≤ elapsed.val) :
    delivery.held_action cancelled elapsed ≠ ok delivery.HeldAction.TryAdmission := by
  simp [try_admission_iff]
  omega

/-- Abstract adapter states. The implementation must use these transitions:
accept one head, move it into a task, discard/expire it, or complete one task.
This model does not extract the async executor, h2, atomics or Rust Drop. -/
structure Window where
  active : Nat
  held : Bool

def occupied (w : Window) : Nat := w.active + if w.held then 1 else 0

inductive Step : Window → Window → Prop
  | take (active : U64) (held : Bool)
      (gate : delivery.head_slot active held = ok true) :
      Step ⟨active.val, held⟩ ⟨active.val, true⟩
  | start (active : Nat) : Step ⟨active, true⟩ ⟨active + 1, false⟩
  | discard (active : Nat) (cancelled : Bool) (elapsed : U64)
      (gate : delivery.held_action cancelled elapsed = ok delivery.HeldAction.Discard) :
      Step ⟨active, true⟩ ⟨active, false⟩
  | expire (active : Nat) (cancelled : Bool) (elapsed : U64)
      (gate : delivery.held_action cancelled elapsed = ok delivery.HeldAction.Expire) :
      Step ⟨active, true⟩ ⟨active, false⟩
  | finish (active : Nat) (held : Bool) : Step ⟨active + 1, held⟩ ⟨active, held⟩

theorem step_preserves_bound (before after : Window) (step : Step before after)
    (bound : occupied before ≤ 32) : occupied after ≤ 32 := by
  cases step with
  | take active held gate => exact (held_head_bounded active held gate).2
  | start active => simpa [occupied] using bound
  | discard active cancelled elapsed gate => simp [occupied] at bound ⊢; omega
  | expire active cancelled elapsed gate => simp [occupied] at bound ⊢; omega
  | finish active held => cases held <;> simp [occupied] at bound ⊢ <;> omega

inductive Run : Window → Window → Prop
  | nil (state : Window) : Run state state
  | step {first next last : Window} (head : Step first next) (tail : Run next last) : Run first last

theorem every_interleaving_bounded (first last : Window) (run : Run first last)
    (initial : occupied first ≤ 32) : occupied last ≤ 32 := by
  induction run with
  | nil => exact initial
  | step head tail ih => exact ih (step_preserves_bound _ _ head initial)

theorem cancellation_releases_held_slot (active : Nat) :
    occupied ⟨active, false⟩ + 1 = occupied ⟨active, true⟩ := rfl

end CancellationProofs
