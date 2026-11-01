import RoutingProofs
open Aeneas Aeneas.Std RustM pathward
namespace StreamingProofs

theorem request_eq (e g u v k o : Bool) (l p : U64) :
    streaming.upgrade_request e g l p u v k o = ok (decide (e = true ∧ g = true ∧ l.val = 0 ∧ p.val = 0 ∧ u = true ∧ v = true ∧ k = true ∧ o = true)) := by
  simp [streaming.upgrade_request]
  split_ifs <;> simp_all

theorem response_eq (r v u a p x l t : Bool) (s : U16) :
    streaming.upgrade_response r v s u a p x l t = ok (decide (r = true ∧ v = true ∧ s.val = 101 ∧ u = true ∧ a = true ∧ p = true ∧ x = false ∧ l = false ∧ t = false)) := by
  simp [streaming.upgrade_response]
  split_ifs <;> simp_all

theorem disabled_request (g u v k o : Bool) (l p : U64) : streaming.upgrade_request false g l p u v k o = ok false := rfl

theorem no_unrequested_upgrade (v u a p x l t : Bool) (s : U16) : streaming.upgrade_response false v s u a p x l t = ok false := rfl

theorem request_bodyless (e g u v k o : Bool) (l p : U64) (h : streaming.upgrade_request e g l p u v k o = ok true) :
    l.val = 0 ∧ p.val = 0 ∧ g = true ∧ o = true := by
  simp [request_eq] at h
  tauto

theorem upgrade_no_http_framing (r v u a p x l t : Bool) (s : U16) (h : streaming.upgrade_response r v s u a p x l t = ok true) :
    r = true ∧ s.val = 101 ∧ a = true ∧ p = true ∧ x = false ∧ l = false ∧ t = false := by
  simp [response_eq] at h
  tauto

theorem invalid_accept (r v u p x l t : Bool) (s : U16) : streaming.upgrade_response r v s u false p x l t = ok false := by simp [response_eq]

theorem no_extensions (r v u a p l t : Bool) (s : U16) : streaming.upgrade_response r v s u a p true l t = ok false := by simp [response_eq]

theorem sse_eq (e h m c : Bool) (s : U16) : streaming.sse_response e h s m c = ok (decide (e = true ∧ h = false ∧ s.val = 200 ∧ m = true ∧ c = false)) := by
  simp [streaming.sse_response]
  split_ifs <;> simp_all

theorem no_encoded_sse (e h m : Bool) (s : U16) : streaming.sse_response e h s m true = ok false := by simp [sse_eq]

theorem byte_limit_eq (l : U64) : streaming.byte_limit l = ok (decide (0 < l.val ∧ l.val ≤ 1073741824)) := by
  simp [streaming.byte_limit]
  split_ifs <;> simp_all

theorem bytes_eq (u n l : U64) : streaming.bytes_fit u n l = ok (decide (0 < l.val ∧ l.val ≤ 1073741824 ∧ u.val + n.val ≤ l.val)) := by
  unfold streaming.bytes_fit
  rw [byte_limit_eq]
  by_cases h : 0 < l.val ∧ l.val ≤ 1073741824
  · by_cases hu : u.val ≤ l.val
    · obtain ⟨diff, hd, hv, _⟩ := WP.spec_imp_exists (U64.sub_bv_spec (x := l) (y := u) (by omega))
      simp [h,hu,hd,hv]
      omega
    · simp [h,hu]
      omega
  · simp [h]
    tauto

theorem bytes_bounded (u n l : U64) (h : streaming.bytes_fit u n l = ok true) :
    u.val + n.val ≤ l.val ∧ l.val ≤ 1073741824 := by
  simp [bytes_eq] at h
  tauto

theorem time_eq (i t : U64) : streaming.time_limits i t = ok (decide (100 ≤ i.val ∧ i.val ≤ 300000 ∧ i.val ≤ t.val ∧ t.val ≤ 3600000)) := by
  simp [streaming.time_limits]
  split_ifs <;> simp_all

theorem running_eq (s : Bool) (e q i t : U64) : streaming.running s e q i t = ok (decide (s = false ∧ 100 ≤ i.val ∧ i.val ≤ 300000 ∧ i.val ≤ t.val ∧ t.val ≤ 3600000 ∧ e.val < t.val ∧ q.val < i.val)) := by
  simp [streaming.running,time_eq]
  split_ifs <;> simp_all

theorem stop_ends_stream (e q i t : U64) : streaming.running true e q i t = ok false := rfl

theorem expired_total (s : Bool) (e q i t : U64) (h : t.val ≤ e.val) : streaming.running s e q i t = ok false := by
  simp [running_eq,show ¬e.val < t.val by omega]

theorem expired_idle (s : Bool) (e q i t : U64) (h : i.val ≤ q.val) : streaming.running s e q i t = ok false := by
  simp [running_eq,show ¬q.val < i.val by omega]

theorem admission_eq (a : U64) (s : Bool) : streaming.admission a s = ok (decide (s = false ∧ a.val < 2)) := by
  cases s <;> simp [streaming.admission]

theorem admission_bounded (a : U64) (s : Bool) (h : streaming.admission a s = ok true) : a.val + 1 ≤ 2 := by
  simp [admission_eq] at h
  omega

theorem no_admission_stopped (a : U64) : streaming.admission a true = ok false := rfl

theorem limits_total (a u n l e q i t : U64) (s : Bool) :
    (∃ r, streaming.bytes_fit u n l = ok r) ∧ (∃ r, streaming.time_limits i t = ok r) ∧
    (∃ r, streaming.running s e q i t = ok r) ∧ (∃ r, streaming.admission a s = ok r) :=
  ⟨⟨_,bytes_eq u n l⟩,⟨_,time_eq i t⟩,⟨_,running_eq s e q i t⟩,⟨_,admission_eq a s⟩⟩
end StreamingProofs
