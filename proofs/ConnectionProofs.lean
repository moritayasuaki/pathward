import DeliveryProofs
open Aeneas Aeneas.Std RustM pathward
namespace ConnectionProofs

theorem candidate_slot_eq (n : U64) :
    connection.candidate_slot n = ok (decide (n.val < 8)) := by
  simp [connection.candidate_slot]

theorem request_live_eq (elapsed budget : U64) :
    connection.request_live elapsed budget = ok (decide
      (0 < budget.val ∧ budget.val ≤ 30000000000 ∧ elapsed.val < budget.val)) := by
  simp [connection.request_live]
  split_ifs <;> simp_all

theorem launch_eq (total launched elapsed budget : U64) (spaced : Bool) :
    connection.launch_allowed total launched elapsed budget spaced = ok (decide
      (0 < total.val ∧ total.val ≤ 8 ∧ launched.val < total.val ∧ spaced = true ∧
       0 < budget.val ∧ budget.val ≤ 30000000000 ∧ elapsed.val < budget.val)) := by
  simp [connection.launch_allowed, request_live_eq]
  split_ifs <;> simp_all

theorem launch_bounded (total launched elapsed budget : U64) (spaced : Bool)
    (h : connection.launch_allowed total launched elapsed budget spaced = ok true) :
    launched.val + 1 ≤ total.val ∧ total.val ≤ 8 ∧ elapsed.val < budget.val ∧
      budget.val ≤ 30000000000 ∧ spaced = true := by
  simp [launch_eq] at h
  obtain ⟨_, bound, room, spacing, _, budgetBound, time⟩ := h
  exact ⟨by omega, bound, time, budgetBound, spacing⟩

theorem ninth_attempt_denied (total elapsed budget : U64) (spaced : Bool) :
    connection.launch_allowed total 8#u64 elapsed budget spaced = ok false := by
  simp [launch_eq]
  omega

theorem expired_launch_denied (total launched elapsed budget : U64) (spaced : Bool)
    (h : budget.val ≤ elapsed.val) :
    connection.launch_allowed total launched elapsed budget spaced = ok false := by
  simp [launch_eq]
  omega

theorem success_eq (elapsed budget : U64) :
    connection.success_allowed elapsed budget = ok (decide
      (0 < budget.val ∧ budget.val ≤ 30000000000 ∧ elapsed.val < budget.val)) := by
  simp [connection.success_allowed, request_live_eq]

theorem deadline_wins_over_success (elapsed budget : U64) (h : budget.val ≤ elapsed.val) :
    connection.success_allowed elapsed budget = ok false := by
  simp [success_eq]
  omega

theorem expired_never_reopens (first later budget : U64)
    (time : first.val ≤ later.val) (expired : budget.val ≤ first.val) :
    connection.request_live later budget = ok false := by
  simp [request_live_eq]
  omega

theorem gates_total (total launched elapsed budget : U64) (spaced : Bool) :
    (∃ b, connection.launch_allowed total launched elapsed budget spaced = ok b) ∧
    (∃ b, connection.success_allowed elapsed budget = ok b) :=
  ⟨⟨_, launch_eq total launched elapsed budget spaced⟩, ⟨_, success_eq elapsed budget⟩⟩

/-- Ownership model of dial futures, not a proof of the executor or socket Drop.
`winner` is a returned connection owned by the enclosing HTTP request. -/
structure Window where
  launched : Nat
  held : Nat
  released : Nat
  winner : Nat
  closed : Bool
  started : Nat
  budget : Nat
  elapsed : Nat

def Valid (w : Window) : Prop :=
  w.held + w.released + w.winner = w.launched ∧ w.launched ≤ 8 ∧ w.winner ≤ 1 ∧
  (w.closed = true → w.held = 0) ∧ (w.winner = 1 → w.closed = true)

theorem initial_valid (started budget : Nat) :
    Valid ⟨0, 0, 0, 0, false, started, budget, 0⟩ := by simp [Valid]

inductive Step : Window → Window → Prop
  | launch (w : Window) (total n elapsed budget : U64) (spaced : Bool)
      (open_ : w.closed = false) (hn : n.val = w.launched)
      (he : elapsed.val = w.elapsed) (hb : budget.val = w.budget)
      (gate : connection.launch_allowed total n elapsed budget spaced = ok true) :
      Step w { w with launched := w.launched + 1, held := w.held + 1 }
  | failed (w : Window) (open_ : w.closed = false) (held : 0 < w.held) :
      Step w { w with held := w.held - 1, released := w.released + 1 }
  | success (w : Window) (elapsed budget : U64) (open_ : w.closed = false)
      (held : 0 < w.held) (he : elapsed.val = w.elapsed) (hb : budget.val = w.budget)
      (gate : connection.success_allowed elapsed budget = ok true) :
      Step w { w with held := 0, released := w.released + w.held - 1, winner := 1, closed := true }
  | cancel (w : Window) :
      Step w { w with held := 0, released := w.released + w.held, closed := true }
  | tick (w : Window) (elapsed : Nat) (forward : w.elapsed ≤ elapsed) :
      Step w { w with elapsed := elapsed }

theorem step_preserves_ownership (before after : Window) (step : Step before after)
    (valid : Valid before) : Valid after := by
  cases step with
  | launch total n elapsed budget spaced opened hn he hb gate =>
      have bound := launch_bounded total n elapsed budget spaced gate
      simp [Valid, opened] at valid ⊢
      omega
  | failed opened held =>
      simp [Valid, opened] at valid ⊢
      omega
  | success elapsed budget opened held he hb gate =>
      simp [Valid, opened] at valid ⊢
      omega
  | cancel =>
      simp [Valid] at valid ⊢
      omega
  | tick elapsed forward => exact valid

theorem step_keeps_request_clock (before after : Window) (step : Step before after) :
    after.started = before.started ∧ after.budget = before.budget ∧ before.elapsed ≤ after.elapsed := by
  cases step <;> simp_all

theorem terminal_does_not_launch (before after : Window) (step : Step before after)
    (closed : before.closed = true) : after.closed = true ∧ after.launched = before.launched := by
  cases step <;> simp_all

inductive Run : Window → Window → Prop
  | nil (w : Window) : Run w w
  | cons {a b c : Window} (head : Step a b) (tail : Run b c) : Run a c

theorem every_interleaving_bounded (first last : Window) (run : Run first last)
    (valid : Valid first) : Valid last := by
  induction run with
  | nil => exact valid
  | cons head tail ih => exact ih (step_preserves_ownership _ _ head valid)

theorem attempts_cannot_extend_deadline (first last : Window) (run : Run first last) :
    last.started = first.started ∧ last.budget = first.budget ∧ first.elapsed ≤ last.elapsed := by
  induction run with
  | nil => simp
  | cons head tail ih =>
      have h := step_keeps_request_clock _ _ head
      omega

theorem terminal_run_cannot_redial (first last : Window) (run : Run first last)
    (closed : first.closed = true) : last.closed = true ∧ last.launched = first.launched := by
  induction run with
  | nil => exact ⟨closed, rfl⟩
  | cons head tail ih =>
      have h := terminal_does_not_launch _ _ head closed
      obtain ⟨hc, hn⟩ := ih h.1
      exact ⟨hc, hn.trans h.2⟩

theorem terminal_releases_pending (first last : Window) (run : Run first last)
    (valid : Valid first) (closed : last.closed = true) :
    last.held = 0 ∧ last.released + last.winner = last.launched ∧ last.winner ≤ 1 := by
  have h := every_interleaving_bounded first last run valid
  obtain ⟨accounting, bound, winner, released, terminal⟩ := h
  have empty := released closed
  exact ⟨empty, by omega, winner⟩

end ConnectionProofs
