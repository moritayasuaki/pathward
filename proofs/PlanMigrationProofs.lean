import GuardUpgradeProofs
open Aeneas Aeneas.Std RustM pathward
namespace PlanMigrationProofs

theorem migration_iff (a b c d e f : Bool) :
    recovery.migration_allowed a b c d e f = ok true ↔
    a = true ∧ b = true ∧ c = true ∧ d = true ∧ e = true ∧ f = true := by
  cases a <;> cases b <;> cases c <;> cases d <;> cases e <;> cases f <;>
    simp [recovery.migration_allowed]

theorem shared_records_denied (b c d e f : Bool) :
    recovery.migration_allowed false b c d e f = ok false := rfl
theorem changed_roles_denied (a c d e f : Bool) :
    recovery.migration_allowed a false c d e f = ok false := by cases a <;> rfl
theorem unstable_source_denied (a b d e f : Bool) :
    recovery.migration_allowed a b false d e f = ok false := by cases a <;> cases b <;> rfl
theorem unready_target_denied (a b c e f : Bool) :
    recovery.migration_allowed a b c false e f = ok false := by cases a <;> cases b <;> cases c <;> rfl
theorem disagreeing_selection_denied (a b c d f : Bool) :
    recovery.migration_allowed a b c d false f = ok false := by
  cases a <;> cases b <;> cases c <;> cases d <;> rfl
theorem missing_fallback_denied (a b c d e : Bool) :
    recovery.migration_allowed a b c d e false = ok false := by
  cases a <;> cases b <;> cases c <;> cases d <;> cases e <;> rfl

theorem collection_iff (a b c d e f : Bool) :
    recovery.collection_allowed a b c d e f = ok true ↔
    a = true ∧ b = true ∧ c = true ∧ d = false ∧ e = true ∧ f = true := by
  cases a <;> cases b <;> cases c <;> cases d <;> cases e <;> cases f <;>
    simp [recovery.collection_allowed]
theorem incomplete_collection_denied (b c d e f : Bool) :
    recovery.collection_allowed false b c d e f = ok false := rfl
theorem same_boot_collection_denied (a c d e f : Bool) :
    recovery.collection_allowed a false c d e f = ok false := by cases a <;> rfl
theorem busy_collection_denied (a b d e f : Bool) :
    recovery.collection_allowed a b false d e f = ok false := by cases a <;> cases b <;> rfl
theorem pinned_collection_denied (a b c e f : Bool) :
    recovery.collection_allowed a b c true e f = ok false := by cases a <;> cases b <;> cases c <;> rfl
theorem future_collection_denied (a b c d f : Bool) :
    recovery.collection_allowed a b c d false f = ok false := by
  cases a <;> cases b <;> cases c <;> cases d <;> rfl
theorem external_collection_denied (a b c d e : Bool) :
    recovery.collection_allowed a b c d e false = ok false := by
  cases a <;> cases b <;> cases c <;> cases d <;> cases e <;> rfl

/-- Model of a same-service handoff. Durable records, verified selection and
atomic pointer replacement are explicit adapter assumptions. -/
structure Handoff where
  target : Bool
  sourcePermit : Option Nat
  targetPermit : Option Nat
  staged : Bool
  sourceKept : Bool

def safe (service : Nat) (s : Handoff) : Prop :=
  s.sourcePermit = some service ∧ (s.targetPermit = none ∨ s.targetPermit = some service) ∧
  (s.target = true → s.targetPermit = some service ∧ s.staged = true) ∧ s.sourceKept = true

inductive Step (service : Nat) : Handoff → Handoff → Prop
  | prepare (s) : Step service s {s with targetPermit := some service, staged := true}
  | activate (s) (ready : s.targetPermit = some service ∧ s.staged = true) :
      Step service s {s with target := true}
  | interrupt (s) : Step service s s

inductive Run (service : Nat) : Handoff → Handoff → Prop
  | refl (s) : Run service s s
  | next {a b c} : Run service a b → Step service b c → Run service a c

theorem initial_safe (service : Nat) : safe service ⟨false,some service,none,false,true⟩ := by simp [safe]
theorem step_preserves_safe (service : Nat) (a b : Handoff) (h : safe service a) (step : Step service a b) :
    safe service b := by cases step <;> simp_all [safe]
theorem interrupted_prefix_safe (service : Nat) (a b : Handoff) (h : safe service a) (run : Run service a b) :
    safe service b := by
  induction run with
  | refl => exact h
  | next _ step ih => exact step_preserves_safe _ _ _ ih step
theorem source_retained (service : Nat) (a b : Handoff) (h : safe service a) (run : Run service a b) :
    b.sourceKept = true := (interrupted_prefix_safe _ _ _ h run).2.2.2
theorem target_selection_agrees (service : Nat) (s : Handoff) (h : safe service s) (active : s.target = true) :
    s.targetPermit = s.sourcePermit := by
  rw [h.1]; exact (h.2.2.1 active).1
theorem either_durable_pointer_safe (service : Nat) (survived : Bool) :
    safe service ⟨survived,some service,some service,true,true⟩ := by simp [safe]

/-- Protected objects include current/parent generations and the transitive
references of retained/prepared generations. The Python mark pass is not extracted. -/
def remove (live : Nat → Bool) (id : Nat) : Nat → Bool := fun x => if x = id then false else live x
def preserves (roots live : Nat → Bool) : Prop := ∀ x, roots x = true → live x = true

theorem remove_preserves_roots (roots live : Nat → Bool) (id : Nat)
    (h : preserves roots live) (unpinned : roots id = false) : preserves roots (remove live id) := by
  intro x hx
  have hn : x ≠ id := by intro he; subst x; simp [unpinned] at hx
  simp [remove, hn, h x hx]
theorem remove_retry_idempotent (live : Nat → Bool) (id x : Nat) :
    remove (remove live id) id x = remove live id x := by simp [remove]

inductive Collection (roots : Nat → Bool) : (Nat → Bool) → (Nat → Bool) → Prop
  | refl (live) : Collection roots live live
  | retire {a b} (prior : Collection roots a b) (id) (unpinned : roots id = false) :
      Collection roots a (remove b id)

theorem interrupted_collection_preserves_roots (roots a b : Nat → Bool)
    (h : preserves roots a) (run : Collection roots a b) : preserves roots b := by
  induction run with
  | refl => exact h
  | retire _ id unpinned ih => exact remove_preserves_roots _ _ _ ih unpinned
theorem current_and_parent_survive (roots a b : Nat → Bool) (current parent : Nat)
    (hc : roots current = true) (hp : roots parent = true) (h : preserves roots a)
    (run : Collection roots a b) : b current = true ∧ b parent = true :=
  ⟨interrupted_collection_preserves_roots _ _ _ h run current hc,
   interrupted_collection_preserves_roots _ _ _ h run parent hp⟩

inductive Reachable (root : Nat → Prop) (edge : Nat → Nat → Prop) : Nat → Prop
  | root (x) : root x → Reachable root edge x
  | edge (a b) : Reachable root edge a → edge a b → Reachable root edge b

theorem reachable_is_marked (root : Nat → Prop) (edge : Nat → Nat → Prop) (marked : Nat → Bool)
    (start : ∀ x, root x → marked x = true)
    (closed : ∀ a b, marked a = true → edge a b → marked b = true)
    (x : Nat) (h : Reachable root edge x) : marked x = true := by
  induction h with
  | root x hx => exact start x hx
  | edge a b _ he ih => exact closed a b ih he

end PlanMigrationProofs
