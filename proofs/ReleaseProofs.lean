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
    split_ifs
    all_goals simp_all
    all_goals omega
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

theorem capacity_global_eq (n : Bool) :
    release.capacity_global n = ok (if n then 192#u64 else 12#u64) := by cases n <;> rfl
theorem capacity_peer_eq (n : Bool) :
    release.capacity_peer n = ok (if n then 144#u64 else 6#u64) := by cases n <;> rfl
theorem capacity_queue_eq (n : Bool) :
    release.capacity_queue n = ok (if n then 188#u64 else 8#u64) := by cases n <;> rfl
theorem capacity_rate_eq (n p : Bool) :
    release.capacity_rate n p = ok
      (if n then (if p then 64#u64 else 128#u64) else (if p then 8#u64 else 64#u64)) := by
  cases n <;> cases p <;> rfl
theorem capacity_burst_eq (n p : Bool) :
    release.capacity_burst n p = ok
      (if n then (if p then 384#u64 else 512#u64) else (if p then 16#u64 else 128#u64)) := by
  cases n <;> cases p <;> rfl

theorem capacity_limits_bounded (n : Bool) (g p q : U64)
    (hg : release.capacity_global n = ok g)
    (hp : release.capacity_peer n = ok p)
    (hq : release.capacity_queue n = ok q) :
    0 < p.val ∧ p.val < g.val ∧ g.val ≤ 192 ∧ q.val + 4 = g.val := by
  cases n <;> simp [release.capacity_global, release.capacity_peer, release.capacity_queue] at hg hp hq
  all_goals subst g; subst p; subst q; decide

theorem capacity_credit_bounded (n p : Bool) (r b : U64)
    (hr : release.capacity_rate n p = ok r)
    (hb : release.capacity_burst n p = ok b) :
    0 < r.val ∧ r.val ≤ 128 ∧ r.val ≤ b.val ∧ b.val ≤ 512 ∧
      60000 * r.val + 1000 * b.val < 2^64 := by
  cases n <;> cases p <;> simp [release.capacity_rate, release.capacity_burst] at hr hb
  all_goals subst r; subst b; decide

theorem capacity_rejection_eq (a p t : U64) (d n : Bool) :
    release.capacity_rejection a p t d n = ok
      (if d then 1#u64 else if (if n then 192 else 12) ≤ a.val then 2#u64 else
       if (if n then 144 else 6) ≤ p.val then 3#u64 else if t.val = 0 then 4#u64 else 0#u64) := by
  cases n <;> simp [release.capacity_rejection, capacity_global_eq, capacity_peer_eq, UScalar.eq_equiv]
  all_goals split_ifs <;> rfl

theorem capacity_accepts_exactly (a p t : U64) (d n : Bool) :
    release.capacity_rejection a p t d n = ok 0#u64 ↔
      d = false ∧ a.val < (if n then 192 else 12) ∧
        p.val < (if n then 144 else 6) ∧ 0 < t.val := by
  rw [capacity_rejection_eq]
  cases d
  · cases n
    all_goals simp only [Bool.false_eq_true, ↓reduceIte, true_and]
    all_goals split_ifs
    all_goals simp_all
    all_goals omega
  · simp

theorem capacity_standard_unchanged (a p t : U64) (d : Bool) :
    release.capacity_rejection a p t d false = release.admission_rejection a p t d := by
  simp [capacity_rejection_eq, rejection_eq]

theorem capacity_code_bounded (a p t c : U64) (d n : Bool)
    (h : release.capacity_rejection a p t d n = ok c) : c.val ≤ 4 := by
  rw [capacity_rejection_eq] at h
  split_ifs at h <;> cases h <;> decide

theorem capacity_no_draining (a p t : U64) (n : Bool) :
    release.capacity_rejection a p t true n = ok 1#u64 := by simp [capacity_rejection_eq]

theorem capacity_no_credit (a p : U64) (n : Bool)
    (ha : a.val < (if n then 192 else 12))
    (hp : p.val < (if n then 144 else 6)) :
    release.capacity_rejection a p 0#u64 false n = ok 4#u64 := by
  simp [capacity_rejection_eq, Nat.not_le_of_gt ha, Nat.not_le_of_gt hp]

theorem capacity_total (a p t : U64) (d n : Bool) :
    ∃ c, release.capacity_rejection a p t d n = ok c := ⟨_, capacity_rejection_eq a p t d n⟩

theorem capacity_reload_eq (current candidate : Bool) :
    release.capacity_reload_allowed current candidate = ok (decide (current = candidate)) := by
  cases current <;> cases candidate <;> rfl

theorem capacity_reload_unchanged (current candidate : Bool)
    (h : release.capacity_reload_allowed current candidate = ok true) : current = candidate := by
  simpa [capacity_reload_eq] using h

theorem capacity_reload_total (current candidate : Bool) :
    ∃ b, release.capacity_reload_allowed current candidate = ok b := ⟨_, capacity_reload_eq current candidate⟩

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
