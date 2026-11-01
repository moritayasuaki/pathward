import ServingProofs
open Aeneas Aeneas.Std RustM pathward
namespace ContentProofs

theorem span_eq (size start count : U64) :
    content.span_allowed size start count = ok (decide (size.val ≤ 1073741824 ∧ start.val + count.val ≤ size.val)) := by
  have cap : serving.MAX_FILE_BYTES = ok 1073741824#u64 := by unfold serving.MAX_FILE_BYTES; rfl
  unfold content.span_allowed
  simp only [cap, bind_tc_ok]
  by_cases h : size.val ≤ 1073741824
  · by_cases hs : start.val ≤ size.val
    · obtain ⟨diff, hd, hv, _⟩ := WP.spec_imp_exists (U64.sub_bv_spec (x := size) (y := start) (by omega))
      simp [h, hs, hd, hv]
      omega
    · simp [h, hs]
      omega
  · simp [h]

theorem span_bounded (size start count : U64)
    (h : content.span_allowed size start count = ok true) :
    start.val + count.val ≤ size.val ∧ size.val ≤ 1073741824 := by
  simp [span_eq] at h
  exact h.symm

theorem span_total (size start count : U64) :
    ∃ result, content.span_allowed size start count = ok result := ⟨_,span_eq size start count⟩

def condition (primary secondary : Option Bool) (fallback : Bool) : Bool :=
  primary.getD (secondary.getD fallback)

theorem preconditions_eq (m u n d : Option Bool) :
    content.precondition_status m u n d = ok
      (if condition m u true then if condition n d false then 304#u16 else 200#u16 else 412#u16) := by
  cases m <;> cases u <;> cases n <;> cases d <;>
    simp [content.precondition_status, condition] <;> split_ifs <;> rfl

theorem failed_match_precedes_not_modified (u n d : Option Bool) :
    content.precondition_status (some false) u n d = ok 412#u16 := by
  simp [preconditions_eq, condition]

theorem tag_precedes_date (m u d : Option Bool) :
    content.precondition_status m u (some false) d =
      ok (if condition m u true then 200#u16 else 412#u16) := by
  simp [preconditions_eq, condition]

theorem failed_date_precedes_not_modified (n d : Option Bool) :
    content.precondition_status none (some false) n d = ok 412#u16 := by
  simp [preconditions_eq, condition]

theorem cache_eq (s : U16) (a c : Bool) (t : U64) :
    content.shared_cache_allowed s a c t = ok (decide
      (a = true ∧ c = false ∧ t.val ≤ 31536000 ∧ (s = 200#u16 ∨ s = 206#u16 ∨ s = 304#u16))) := by
  simp [content.shared_cache_allowed]
  split_ifs <;> simp_all

theorem no_credential_cache (s : U16) (a : Bool) (t : U64) :
    content.shared_cache_allowed s a true t = ok false := by simp [cache_eq]

theorem no_unpublished_cache (s : U16) (c : Bool) (t : U64) :
    content.shared_cache_allowed s false c t = ok false := by simp [cache_eq]

theorem cache_status_and_duration (s : U16) (a c : Bool) (t : U64)
    (h : content.shared_cache_allowed s a c t = ok true) :
    t.val ≤ 31536000 ∧ (s = 200#u16 ∨ s = 206#u16 ∨ s = 304#u16) := by
  simp [cache_eq] at h
  exact h.2.2

end ContentProofs
