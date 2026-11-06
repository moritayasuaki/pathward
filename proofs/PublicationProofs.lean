import PlanMigrationProofs
open Aeneas Aeneas.Std RustM pathward
namespace PublicationProofs

theorem mapping_iff (c s y : Bool) :
    publication.mapping_allowed c s y = ok true ↔ c = true ∧ (s = true ∨ y = true) := by
  cases c <;> cases s <;> cases y <;> simp [publication.mapping_allowed]
theorem unselected_file_denied (c : Bool) :
    publication.mapping_allowed c false false = ok false := by cases c <;> rfl
theorem noncanonical_mapping_denied (s y : Bool) :
    publication.mapping_allowed false s y = ok false := rfl

theorem receipt_iff (p b r s f : Bool) (a o n : U64) :
    publication.receipt_allowed p b r s f a o n = ok true ↔
    p = true ∧ b = true ∧ r = true ∧ s = true ∧ f = true ∧ a.val < o.val ∧ o.val ≤ n.val := by
  simp [publication.receipt_allowed]
  split_ifs <;> simp_all
theorem old_receipt_denied (p b r s f : Bool) (a o n : U64) (old : o.val ≤ a.val) :
    publication.receipt_allowed p b r s f a o n ≠ ok true := by
  intro h; have := (receipt_iff ..).mp h; omega
theorem future_receipt_denied (p b r s f : Bool) (a o n : U64) (future : n.val < o.val) :
    publication.receipt_allowed p b r s f a o n ≠ ok true := by
  intro h; have := (receipt_iff ..).mp h; omega
theorem previous_boot_denied (p r s f : Bool) (a o n : U64) :
    publication.receipt_allowed p false r s f a o n ≠ ok true := by simp [receipt_iff]
theorem changed_policy_denied (b r s f : Bool) (a o n : U64) :
    publication.receipt_allowed false b r s f a o n ≠ ok true := by simp [receipt_iff]
theorem wrong_revision_denied (p b s f : Bool) (a o n : U64) :
    publication.receipt_allowed p b false s f a o n ≠ ok true := by simp [receipt_iff]
theorem wrong_source_denied (p b r f : Bool) (a o n : U64) :
    publication.receipt_allowed p b r false f a o n ≠ ok true := by simp [receipt_iff]
theorem changed_file_set_denied (p b r s : Bool) (a o n : U64) :
    publication.receipt_allowed p b r s false a o n ≠ ok true := by simp [receipt_iff]
theorem receipt_time_order (p b r s f : Bool) (a o n : U64)
    (h : publication.receipt_allowed p b r s f a o n = ok true) : a.val < n.val := by
  have := (receipt_iff ..).mp h; omega

theorem collection_iff (s b o p e : Bool) :
    publication.collection_allowed s b o p e = ok true ↔
    s = true ∧ b = true ∧ o = true ∧ p = false ∧ e = true := by
  cases s <;> cases b <;> cases o <;> cases p <;> cases e <;> simp [publication.collection_allowed]
theorem same_boot_collection_denied (s o p e : Bool) :
    publication.collection_allowed s false o p e ≠ ok true := by simp [collection_iff]
theorem protected_collection_denied (s b o e : Bool) :
    publication.collection_allowed s b o true e ≠ ok true := by simp [collection_iff]
theorem unobserved_collection_denied (s b p e : Bool) :
    publication.collection_allowed s b false p e ≠ ok true := by simp [collection_iff]
theorem changed_member_collection_denied (s b o p : Bool) :
    publication.collection_allowed s b o p false ≠ ok true := by simp [collection_iff]
theorem busy_collection_denied (b o p e : Bool) :
    publication.collection_allowed false b o p e ≠ ok true := by simp [collection_iff]

/-- The adapter supplies exact file-digest maps. This is about the observation
time of a receipt, not an assertion that later administrators cannot activate. -/
structure Receipt where
  boot : Nat
  policy : Nat
  revision : Nat
  source : Nat
  files : Nat → Option Nat
  observed : Nat

def Matches (r : Receipt) (boot policy revision source after now : Nat)
    (files : Nat → Option Nat) : Prop :=
  r.boot = boot ∧ r.policy = policy ∧ r.revision = revision ∧ r.source = source ∧
  r.files = files ∧ after < r.observed ∧ r.observed ≤ now

theorem matching_receipt_has_exact_digests (r : Receipt) (b p v s a n : Nat)
    (files : Nat → Option Nat) (h : Matches r b p v s a n files) (key : Nat) :
    r.files key = files key := by rw [h.2.2.2.2.1]
theorem matching_receipt_cannot_add_file (r : Receipt) (b p v s a n : Nat)
    (files : Nat → Option Nat) (h : Matches r b p v s a n files) (key : Nat)
    (absent : files key = none) : r.files key = none := by rw [h.2.2.2.2.1, absent]
theorem matching_receipt_follows_switch (r : Receipt) (b p v s a n : Nat)
    (files : Nat → Option Nat) (h : Matches r b p v s a n files) : a < r.observed := h.2.2.2.2.2.1

/-- A move to trash and each partial unlink are separate interruption points.
Protected roots must remain in the live namespace throughout every prefix. -/
structure Storage where
  live : Nat → Bool
  trash : Nat → Bool
def Protected (roots : Nat → Bool) (s : Storage) : Prop :=
  ∀ x, roots x = true → s.live x = true
inductive Step (roots : Nat → Bool) : Storage → Storage → Prop
  | move (s id) (free : roots id = false) : Step roots s
      ⟨PlanMigrationProofs.remove s.live id, fun x => if x = id then true else s.trash x⟩
  | unlink (s id) : Step roots s ⟨s.live, PlanMigrationProofs.remove s.trash id⟩
  | interrupted (s) : Step roots s s
theorem collection_step_preserves_live_roots (roots : Nat → Bool) (a b : Storage)
    (h : Protected roots a) (step : Step roots a b) : Protected roots b := by
  cases step with
  | move id free => exact PlanMigrationProofs.remove_preserves_roots _ _ _ h free
  | unlink => exact h
  | interrupted => exact h
inductive Run (roots : Nat → Bool) : Storage → Storage → Prop
  | nil (s) : Run roots s s
  | cons {a b c} : Run roots a b → Step roots b c → Run roots a c
theorem every_interrupted_prefix_preserves_roots (roots : Nat → Bool) (a b : Storage)
    (h : Protected roots a) (run : Run roots a b) : Protected roots b := by
  induction run with
  | nil => exact h
  | cons _ step ih => exact collection_step_preserves_live_roots _ _ _ ih step
theorem transitive_dependencies_survive (root : Nat → Prop) (edge : Nat → Nat → Prop)
    (marked : Nat → Bool) (a b : Storage)
    (start : ∀ x, root x → marked x = true)
    (closed : ∀ x y, marked x = true → edge x y → marked y = true)
    (safe : Protected marked a) (run : Run marked a b)
    (x : Nat) (reachable : PlanMigrationProofs.Reachable root edge x) : b.live x = true := by
  exact every_interrupted_prefix_preserves_roots _ _ _ safe run x
    (PlanMigrationProofs.reachable_is_marked _ _ _ start closed x reachable)
theorem partial_unlink_retry_idempotent (s : Storage) (id x : Nat) :
    PlanMigrationProofs.remove (PlanMigrationProofs.remove s.trash id) id x =
    PlanMigrationProofs.remove s.trash id x := PlanMigrationProofs.remove_retry_idempotent _ _ _

end PublicationProofs
