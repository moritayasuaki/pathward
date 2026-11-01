import PathwardProofs

open Aeneas Aeneas.Std RustM
open pathward PathwardProofs

namespace RulesProofs

def fileAccepts : State → Bool
  | .Root | .Segment => true
  | _ => false

def targetCanonical (bytes : List U8) : Bool :=
  decide (0 < bytes.length ∧ bytes.length ≤ 4095) && fileAccepts (run .Root bytes)

theorem target_loop_eq (p : Slice U8) (s : State) (i : Usize)
    (_hi : i.val ≤ p.val.length) :
    rules.valid_target_loop p s i = ok (run s (p.val.drop i.val)) := by
  rw [rules.valid_target_loop]
  by_cases h : i < Slice.len p
  · have hlt : i.val < p.val.length := by simpa using h
    obtain ⟨j, hj, hv⟩ := succ_exists i (by have := p.property; omega)
    simp only [h, if_pos, index_eq p i hlt, step_eq, bind_tc_ok, hj]
    rw [target_loop_eq p (next s p.val[i.val]) j (by omega)]
    rw [drop_head p.val i.val hlt]
    simp only [run, List.foldl_cons, hv]
  · have hge : p.val.length ≤ i.val := by simpa using h
    simp [h, run, List.drop_eq_nil_of_le hge]
termination_by p.val.length - i.val

theorem valid_target_eq (p : Slice U8) : rules.valid_target p = ok (targetCanonical p.val) := by
  unfold rules.valid_target
  rw [target_loop_eq p .Root 0#usize (by simp)]
  simp [core.slice.Slice.is_empty, targetCanonical, List.length_pos_iff]
  split_ifs <;> simp_all [fileAccepts]
  all_goals cases run State.Root p.val <;> rfl

def contains (p : List U8) (rs : List rules.Publication) : Bool :=
  rs.any (fun r => p == r.path.val)

def validRules : List rules.Publication → Bool
  | [] => true
  | r :: rest => canonical r.path.val && targetCanonical r.target.val &&
      !contains r.path.val rest && validRules rest

theorem contains_path_eq (p : Slice U8) (rs : Slice rules.Publication) (i : Usize)
    (_hi : i.val ≤ rs.val.length) :
    rules.contains_path p rs i = ok (contains p.val (rs.val.drop i.val)) := by
  rw [rules.contains_path]
  by_cases h : i < Slice.len rs
  · have hlt : i.val < rs.val.length := by simpa using h
    obtain ⟨j, hj, hv⟩ := succ_exists i (by have := rs.property; omega)
    simp only [h, if_pos, index_eq rs i hlt, same_path_eq, bind_tc_ok]
    rw [drop_head rs.val i.val hlt]
    by_cases heq : p.val == rs.val[i.val].path.val
    · simp only [contains, List.any_cons, heq, if_true, Bool.true_or]
    · simp only [heq, Bool.false_eq_true, if_false, hj, bind_tc_ok]
      rw [contains_path_eq p rs j (by omega)]
      simp only [contains, hv, List.any_cons, Bool.eq_false_of_not_eq_true heq, Bool.false_or]
  · have hge : rs.val.length ≤ i.val := by simpa using h
    simp [h, contains, List.drop_eq_nil_of_le hge]
termination_by rs.val.length - i.val

theorem valid_rules_eq (rs : Slice rules.Publication) (i : Usize)
    (_hi : i.val ≤ rs.val.length) :
    rules.valid_rules rs i = ok (validRules (rs.val.drop i.val)) := by
  rw [rules.valid_rules]
  by_cases h : i < Slice.len rs
  · have hlt : i.val < rs.val.length := by simpa using h
    obtain ⟨j, hj, hv⟩ := succ_exists i (by have := rs.property; omega)
    simp only [h, if_pos, index_eq rs i hlt, valid_path_eq, valid_target_eq, bind_tc_ok]
    rw [drop_head rs.val i.val hlt]
    simp only [hj, bind_tc_ok, contains_path_eq _ rs j (by omega)]
    rw [valid_rules_eq rs j (by omega)]
    simp only [validRules, hv]
    split_ifs <;> simp_all
  · have hge : rs.val.length ≤ i.val := by simpa using h
    simp [h, List.drop_eq_nil_of_le hge, validRules]
termination_by rs.val.length - i.val

def admissible (rs : List rules.Publication) : Bool :=
  decide (0 < rs.length ∧ rs.length ≤ 4096) && validRules rs

theorem compile_eq (rs : Slice rules.Publication) :
    rules.compile rs = ok (if admissible rs.val then some rs else none) := by
  unfold rules.compile
  rw [valid_rules_eq rs 0#usize (by simp)]
  simp [core.slice.Slice.is_empty, admissible]
  split_ifs <;> simp_all
  all_goals omega

theorem compile_iff (rs out : Slice rules.Publication) :
    rules.compile rs = ok (some out) ↔ admissible rs.val = true ∧ out = rs := by
  rw [compile_eq]
  by_cases h : admissible rs.val = true
  · rw [if_pos h]
    constructor
    · intro he
      cases he
      exact ⟨h, rfl⟩
    · rintro ⟨_, rfl⟩
      rfl
  · rw [if_neg h]
    simp [h]

theorem compile_total (rs : Slice rules.Publication) :
    ∃ result, rules.compile rs = ok result := ⟨_, compile_eq rs⟩

theorem compile_preserves_declarations (rs out : Slice rules.Publication)
    (h : rules.compile rs = ok (some out)) : out = rs := (compile_iff rs out).mp h |>.2

def lookupSpec (p : List U8) : List rules.Publication → Option (Slice U8)
  | [] => none
  | r :: rest => if p == r.path.val then
      if targetCanonical r.target.val then some r.target else none
    else lookupSpec p rest

theorem lookup_from_eq (p : Slice U8) (rs : Slice rules.Publication) (i : Usize)
    (_hi : i.val ≤ rs.val.length) :
    rules.lookup_from p rs i = ok (lookupSpec p.val (rs.val.drop i.val)) := by
  rw [rules.lookup_from]
  by_cases h : i < Slice.len rs
  · have hlt : i.val < rs.val.length := by simpa using h
    obtain ⟨j, hj, hv⟩ := succ_exists i (by have := rs.property; omega)
    simp only [h, if_pos, index_eq rs i hlt, same_path_eq, bind_tc_ok]
    rw [drop_head rs.val i.val hlt]
    simp only [valid_target_eq, bind_tc_ok, hj]
    rw [lookup_from_eq p rs j (by omega)]
    simp [lookupSpec, hv]
    split_ifs <;> rfl
  · have hge : rs.val.length ≤ i.val := by simpa using h
    simp [h, List.drop_eq_nil_of_le hge, lookupSpec]
termination_by rs.val.length - i.val

theorem lookup_eq (p : Slice U8) (rs : Slice rules.Publication) :
    rules.lookup p rs = ok (if rs.val.length ≤ 4096 ∧ canonical p.val = true
      then lookupSpec p.val rs.val else none) := by
  unfold rules.lookup
  rw [valid_path_eq, lookup_from_eq p rs 0#usize (by simp)]
  simp
  split_ifs <;> simp_all
  all_goals omega

theorem lookup_total (p : Slice U8) (rs : Slice rules.Publication) :
    ∃ result, rules.lookup p rs = ok result := ⟨_, lookup_eq p rs⟩

theorem target_canonical_iff (xs : List U8) :
    targetCanonical xs = true ↔ xs ≠ [] ∧ canonical (47#u8 :: xs) = true ∧ run .Root xs ≠ .Separator := by
  simp [targetCanonical, canonical, List.length_pos_iff, run_cons, next]
  cases run State.Root xs <;> simp [fileAccepts, accepts] <;> omega

theorem valid_rules_contract (rs : List rules.Publication) :
    validRules rs = true ↔
      (∀ r ∈ rs, canonical r.path.val = true ∧ targetCanonical r.target.val = true) ∧
      rs.Pairwise (fun r s => r.path.val ≠ s.path.val) := by
  induction rs with
  | nil => simp [validRules]
  | cons r rs ih =>
    simp [validRules, contains, ih, List.pairwise_cons]
    aesop

/-- The complete compiler contract: bounds, unchanged declarations, safe paths,
    safe relative targets, and pairwise-distinct URL keys. -/
theorem compile_contract (rs out : Slice rules.Publication) :
    rules.compile rs = ok (some out) ↔
      out = rs ∧ (0 < rs.val.length ∧ rs.val.length ≤ 4096) ∧
      (∀ r ∈ rs.val, canonical r.path.val = true ∧ targetCanonical r.target.val = true) ∧
      rs.val.Pairwise (fun r s => r.path.val ≠ s.path.val) := by
  rw [compile_iff]
  simp only [admissible, Bool.and_eq_true_iff, decide_eq_true_eq, valid_rules_contract]
  tauto

theorem lookup_spec_sound (p : List U8) (rs : List rules.Publication) (target : Slice U8)
    (h : lookupSpec p rs = some target) :
    ∃ r ∈ rs, p = r.path.val ∧ r.target = target ∧ targetCanonical target.val = true := by
  induction rs with
  | nil => simp [lookupSpec] at h
  | cons r rs ih =>
    by_cases heq : p = r.path.val
    · by_cases ht : targetCanonical r.target.val = true
      · simp [lookupSpec, heq, ht] at h
        subst target
        exact ⟨r, by simp, heq, rfl, ht⟩
      · simp [lookupSpec, heq, ht] at h
    · have hh : lookupSpec p rs = some target := by simpa [lookupSpec, heq] using h
      obtain ⟨found, hm, hp, ht, hc⟩ := ih hh
      exact ⟨found, by simp [hm], hp, ht, hc⟩

theorem lookup_spec_complete (rs : List rules.Publication) (h : validRules rs = true)
    (r : rules.Publication) (hr : r ∈ rs) : lookupSpec r.path.val rs = some r.target := by
  induction rs with
  | nil => simp at hr
  | cons first rest ih =>
    have hc := (valid_rules_contract (first :: rest)).mp h
    have ht : targetCanonical first.target.val = true := (hc.1 first (by simp)).2
    have hrest : validRules rest = true := by
      have hh := h
      simp only [validRules, Bool.and_eq_true_iff] at hh
      exact hh.2
    rcases List.mem_cons.mp hr with he | hm
    · subst r
      simp [lookupSpec, ht]
    · have hne : r.path.val ≠ first.path.val := by
        have hpair := List.pairwise_cons.mp hc.2
        exact Ne.symm (hpair.1 r hm)
      simpa [lookupSpec, hne] using ih hrest hm

/-- A compiled table resolves exactly the configured URL-to-target pairs. -/
theorem compiled_lookup_iff (p target : Slice U8) (rs out : Slice rules.Publication)
    (h : rules.compile rs = ok (some out)) :
    rules.lookup p out = ok (some target) ↔
      ∃ r ∈ rs.val, p.val = r.path.val ∧ r.target = target := by
  have hc := (compile_contract rs out).mp h
  obtain ⟨he, hb, hv, hu⟩ := hc
  subst out
  have hrules : validRules rs.val = true := (valid_rules_contract rs.val).mpr ⟨hv, hu⟩
  rw [lookup_eq]
  constructor
  · intro hl
    split_ifs at hl with hp
    · have hl' : lookupSpec p.val rs.val = some target := by simpa using hl
      obtain ⟨r, hm, heq, ht, _⟩ := lookup_spec_sound p.val rs.val target hl'
      exact ⟨r, hm, heq, ht⟩
    · simp at hl
  · rintro ⟨r, hm, heq, ht⟩
    have hp : canonical p.val = true := by rw [heq]; exact (hv r hm).1
    rw [if_pos ⟨hb.2, hp⟩, heq, lookup_spec_complete rs.val hrules r hm, ht]

theorem lookup_safe (p target : Slice U8) (rs : Slice rules.Publication)
    (h : rules.lookup p rs = ok (some target)) :
    canonical p.val = true ∧ targetCanonical target.val = true ∧
      ∃ r ∈ rs.val, p.val = r.path.val ∧ r.target = target := by
  rw [lookup_eq] at h
  split_ifs at h with hp
  · have hl : lookupSpec p.val rs.val = some target := by simpa using h
    obtain ⟨r, hm, heq, ht, hc⟩ := lookup_spec_sound p.val rs.val target hl
    exact ⟨hp.2, hc, r, hm, heq, ht⟩
  · simp at h

theorem target_not_absolute (xs : List U8) (h : targetCanonical xs = true) :
    ∀ rest, xs ≠ 47#u8 :: rest := by
  intro rest he
  simp [he, targetCanonical, run_cons, next, nameByte, fileAccepts] at h

theorem target_no_traversal (xs : List U8) (h : targetCanonical xs = true) :
    ∀ before after, 47#u8 :: xs ≠ before ++ 47#u8 :: 46#u8 :: after := by
  intro before after he
  have hc := ((target_canonical_iff xs).mp h).2.1
  rw [he, no_hidden_or_traversal] at hc
  contradiction

theorem resolved_target_no_traversal (p target : Slice U8) (rs : Slice rules.Publication)
    (h : rules.lookup p rs = ok (some target)) :
    ∀ before after, 47#u8 :: target.val ≠ before ++ 47#u8 :: 46#u8 :: after :=
  target_no_traversal target.val (lookup_safe p target rs h).2.1

theorem target_no_directory_suffix (xs : List U8) :
    targetCanonical (xs ++ [47#u8]) = false := by
  simp only [targetCanonical, run_append, run_cons, run_nil]
  have h := run_not_start xs .Root (by intro h; cases h)
  cases he : run State.Root xs <;> simp_all [next, nameByte, fileAccepts]

end RulesProofs
