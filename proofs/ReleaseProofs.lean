import ResponseProofs
open Aeneas Aeneas.Std RustM
open pathward PathwardProofs RulesProofs ResponseProofs
namespace ReleaseProofs

abbrev generationPolicy (u t e : Slice U8) (rootAlias : Bool) : Prop :=
  u.val ≠ [] ∧ canonical u.val = true ∧ targetCanonical t.val = true ∧ t.val = e.val ∧
  (if rootAlias then u.val = [47#u8] else u.val.drop 1 = t.val)

theorem generated_eq (u t e : Slice U8) (rootAlias : Bool) :
    release.generated_rule u t e rootAlias = ok (decide (generationPolicy u t e rootAlias)) := by
  unfold release.generated_rule
  by_cases he : u.val = []
  · simp [core.slice.Slice.is_empty,he,generationPolicy]
  · simp only [core.slice.Slice.is_empty]
    have hp : 1 ≤ u.val.length := by have := List.length_pos_iff.mpr he; omega
    rw [split_eq u 1#usize (by simpa using hp)]
    simp [prefixSlice,suffixSlice,valid_path_eq,valid_target_eq,same_path_eq,lift,Array.to_slice,Array.make,generationPolicy,he]
    split_ifs <;> simp_all
    · by_cases h : u.val = [47#u8] <;> simp_all
    · by_cases h : u.val.tail = e.val <;> simp_all

theorem generated_contract (u t e : Slice U8) (rootAlias : Bool) :
    release.generated_rule u t e rootAlias = ok true ↔ generationPolicy u t e rootAlias := by simp [generated_eq]

theorem generated_exact_entry (u t e : Slice U8) (rootAlias : Bool)
    (h : release.generated_rule u t e rootAlias = ok true) : t.val = e.val :=
  (generated_contract u t e rootAlias).mp h |>.2.2.2.1

theorem generated_no_extra_url (u t e : Slice U8)
    (h : release.generated_rule u t e false = ok true) : u.val.drop 1 = e.val := by
  have hp := (generated_contract u t e false).mp h
  simpa [hp.2.2.2.1] using hp.2.2.2.2

theorem generated_safe_target (u t e : Slice U8) (rootAlias : Bool)
    (h : release.generated_rule u t e rootAlias = ok true) : targetCanonical t.val = true :=
  (generated_contract u t e rootAlias).mp h |>.2.2.1

theorem generated_total (u t e : Slice U8) (rootAlias : Bool) :
    ∃ b, release.generated_rule u t e rootAlias = ok b := ⟨_,generated_eq u t e rootAlias⟩

abbrev commitPolicy (c e : Slice U8) (p s d : Bool) : Prop :=
  c.val.length = 64 ∧ c.val = e.val ∧ p = true ∧ s = true ∧ d = false

theorem commit_eq (c e : Slice U8) (p s d : Bool) :
    release.commit_allowed c e p s d = ok (decide (commitPolicy c e p s d)) := by
  have hc : c.len = 64#usize ↔ c.val.length = 64 := by simp [UScalar.eq_equiv]
  simp [release.commit_allowed,same_path_eq,commitPolicy,hc]
  split_ifs <;> simp_all

theorem commit_contract (c e : Slice U8) (p s d : Bool) :
    release.commit_allowed c e p s d = ok true ↔ commitPolicy c e p s d := by simp [commit_eq]

theorem no_unpersisted_commit (c e : Slice U8) (p d : Bool) :
    release.commit_allowed c e p false d = ok false := by simp [commit_eq,commitPolicy]

theorem no_stale_commit (c e : Slice U8) (p s d : Bool) (h : c.val ≠ e.val) :
    release.commit_allowed c e p s d = ok false := by simp [commit_eq,commitPolicy,h]

theorem no_draining_commit (c e : Slice U8) (p s : Bool) :
    release.commit_allowed c e p s true = ok false := by simp [commit_eq,commitPolicy]

theorem admission_eq (a p t : U64) (d : Bool) :
    release.admission_allowed a p t d = ok (decide (d = false ∧ a.val < 12 ∧ p.val < 6 ∧ 0 < t.val)) := by
  simp [release.admission_allowed]
  split_ifs <;> simp_all

theorem admission_contract (a p t : U64) (d : Bool) :
    release.admission_allowed a p t d = ok true ↔ d = false ∧ a.val < 12 ∧ p.val < 6 ∧ 0 < t.val := by simp [admission_eq]

theorem admission_no_exhausted_tokens (a p : U64) (d : Bool) :
    release.admission_allowed a p 0#u64 d = ok false := by simp [admission_eq]

theorem admission_no_draining (a p t : U64) :
    release.admission_allowed a p t true = ok false := by simp [admission_eq]

theorem rejection_eq (a p t : U64) (d : Bool) :
    release.admission_rejection a p t d = ok
      (if d then 1#u64 else if 12 ≤ a.val then 2#u64 else
       if 6 ≤ p.val then 3#u64 else if t.val = 0 then 4#u64 else 0#u64) := by
  simp [release.admission_rejection, UScalar.eq_equiv]
  split_ifs <;> rfl

theorem rejection_accepts_exactly (a p t : U64) (d : Bool) :
    release.admission_rejection a p t d = ok 0#u64 ↔
      release.admission_allowed a p t d = ok true := by
  rw [rejection_eq, admission_contract]
  cases d
  · simp only [Bool.false_eq_true, ↓reduceIte, true_and]
    split_ifs <;> simp_all <;> omega
  · simp

theorem rejection_code_bounded (a p t c : U64) (d : Bool)
    (h : release.admission_rejection a p t d = ok c) : c.val ≤ 4 := by
  rw [rejection_eq] at h
  split_ifs at h <;> cases h <;> decide

theorem rejection_draining (a p t : U64) :
    release.admission_rejection a p t true = ok 1#u64 := by simp [rejection_eq]

theorem rejection_exhausted (a p : U64) (ha : a.val < 12) (hp : p.val < 6) :
    release.admission_rejection a p 0#u64 false = ok 4#u64 := by
  simp [rejection_eq, Nat.not_le_of_gt ha, Nat.not_le_of_gt hp]

theorem rejection_total (a p t : U64) (d : Bool) :
    ∃ c, release.admission_rejection a p t d = ok c := ⟨_, rejection_eq a p t d⟩

theorem gates_total (c e : Slice U8) (p s d : Bool) (a n t : U64) :
    (∃ b, release.commit_allowed c e p s d = ok b) ∧
    (∃ b, release.admission_allowed a n t d = ok b) :=
  ⟨⟨_,commit_eq c e p s d⟩,⟨_,admission_eq a n t d⟩⟩
theorem dispatch_eq (a p : U64) (d : Bool) :
    release.dispatch_allowed a p d = ok (decide (d = false ∧ a.val < 4 ∧ p.val < 2)) := by
  simp [release.dispatch_allowed]
  split_ifs <;> simp_all

theorem dispatch_contract (a p : U64) (d : Bool) :
    release.dispatch_allowed a p d = ok true ↔ d = false ∧ a.val < 4 ∧ p.val < 2 := by simp [dispatch_eq]

theorem dispatch_bounded (a p : U64) (d : Bool)
    (h : release.dispatch_allowed a p d = ok true) : a.val + 1 ≤ 4 ∧ p.val + 1 ≤ 2 := by
  have hp := (dispatch_contract a p d).mp h
  omega

theorem dispatch_no_draining (a p : U64) :
    release.dispatch_allowed a p true = ok false := by simp [dispatch_eq]

theorem dispatch_total (a p : U64) (d : Bool) :
    ∃ b, release.dispatch_allowed a p d = ok b := ⟨_,dispatch_eq a p d⟩
end ReleaseProofs

namespace ReleaseProofs
abbrev migrationPolicy (c i : Slice U8) (r p b s : Bool) : Prop :=
  c.val.length = 64 ∧ c.val = i.val ∧ r = true ∧ p = true ∧ b = true ∧ s = true

theorem migration_eq (c i : Slice U8) (r p b s : Bool) :
    release.migration_allowed c i r p b s = ok (decide (migrationPolicy c i r p b s)) := by
  have hc : c.len = 64#usize ↔ c.val.length = 64 := by simp [UScalar.eq_equiv]
  simp [release.migration_allowed,same_path_eq,migrationPolicy,hc]
  split_ifs <;> simp_all

theorem migration_contract (c i : Slice U8) (r p b s : Bool) :
    release.migration_allowed c i r p b s = ok true ↔ migrationPolicy c i r p b s := by
  simp [migration_eq]

theorem migration_no_stale (c i : Slice U8) (r p b s : Bool) (h : c.val ≠ i.val) :
    release.migration_allowed c i r p b s = ok false := by simp [migration_eq,migrationPolicy,h]

theorem migration_no_unready (c i : Slice U8) (p b s : Bool) :
    release.migration_allowed c i false p b s = ok false := by simp [migration_eq,migrationPolicy]

theorem migration_no_mismatch (c i : Slice U8) (r b s : Bool) :
    release.migration_allowed c i r false b s = ok false := by simp [migration_eq,migrationPolicy]

theorem migration_requires_rollback (c i : Slice U8) (r p s : Bool) :
    release.migration_allowed c i r p false s = ok false := by simp [migration_eq,migrationPolicy]

theorem migration_requires_isolation (c i : Slice U8) (r p b : Bool) :
    release.migration_allowed c i r p b false = ok false := by simp [migration_eq,migrationPolicy]

theorem migration_total (c i : Slice U8) (r p b s : Bool) :
    ∃ result, release.migration_allowed c i r p b s = ok result := ⟨_,migration_eq c i r p b s⟩
end ReleaseProofs
