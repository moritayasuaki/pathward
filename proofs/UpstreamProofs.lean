import RoutingProofs
open Aeneas Aeneas.Std RustM pathward
namespace UpstreamProofs

theorem probe_eq (g c r : Bool) (b n : U64) :
    upstream.probe_allowed g b c r n = ok (decide (g = true ∧ b.val = 0 ∧ c = false ∧ r = true ∧ 0 < n.val ∧ n.val ≤ 32)) := by
  simp [upstream.probe_allowed]
  split_ifs <;> simp_all

theorem probe_read_only (g c r : Bool) (b n : U64)
    (h : upstream.probe_allowed g b c r n = ok true) :
    g = true ∧ b.val = 0 ∧ c = false := by
  simp [probe_eq] at h
  exact ⟨h.1,h.2.1,h.2.2.1⟩

theorem probe_bounded (g c r : Bool) (b n : U64)
    (h : upstream.probe_allowed g b c r n = ok true) : 0 < n.val ∧ n.val ≤ 32 := by
  simp [probe_eq] at h
  exact h.2.2.2.2

theorem next_eq (s : U16) (n : U64) :
    upstream.probe_next s n = ok (decide (s = 404#u16 ∧ 0 < n.val ∧ n.val < 32)) := by
  simp [upstream.probe_next]
  split_ifs <;> simp_all

theorem only_absence_falls_through (s : U16) (n : U64)
    (h : upstream.probe_next s n = ok true) : s = 404#u16 := by
  simp [next_eq] at h
  exact h.1

theorem no_retry_after_last (s : U16) : upstream.probe_next s 0#u64 = ok false := by simp [next_eq]

theorem owned_eq (s : U16) : upstream.probe_owned s = ok (decide
    ((200 ≤ s.val ∧ s.val < 300) ∨ s = 401#u16 ∨ s = 403#u16 ∨ s = 410#u16)) := by
  simp [upstream.probe_owned]
  split_ifs <;> simp_all

theorem authorization_is_final (n : U64) :
    upstream.probe_owned 401#u16 = ok true ∧ upstream.probe_next 401#u16 n = ok false ∧
    upstream.probe_owned 403#u16 = ok true ∧ upstream.probe_next 403#u16 n = ok false := by
  simp [owned_eq,next_eq]

theorem gone_is_final (n : U64) : upstream.probe_owned 410#u16 = ok true ∧ upstream.probe_next 410#u16 n = ok false := by simp [owned_eq,next_eq]

theorem server_error_is_not_owner (s : U16) (h : 500 ≤ s.val) : upstream.probe_owned s = ok false := by
  rw [owned_eq]
  have h401 : s ≠ 401#u16 := by intro he; subst s; simp at h
  have h403 : s ≠ 403#u16 := by intro he; subst s; simp at h
  have h410 : s ≠ 410#u16 := by intro he; subst s; simp at h
  simp [h401,h403,h410]; omega

theorem query_eq (e a : Bool) : upstream.query_match e a = ok (e || a) := by
  cases e <;> cases a <;> rfl

theorem encoded_query_applies (e : Bool) : upstream.query_match e true = ok true := by simp [query_eq]
end UpstreamProofs
