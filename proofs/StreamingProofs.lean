import RoutingProofs
open Aeneas Aeneas.Std RustM pathward
namespace StreamingProofs

theorem request_eq (e g u v k o : Bool) (l p : U64) :
    streaming.upgrade_request e g l p u v k o = ok (decide (e = true ∧ g = true ∧ l.val = 0 ∧ p.val = 0 ∧ u = true ∧ v = true ∧ k = true ∧ o = true)) := by
  simp [streaming.upgrade_request]
  split_ifs <;> simp_all

theorem response_eq (r v u a p x l t : Bool) (s : U16) :
    streaming.upgrade_response r v s u a p x l t = ok (decide (r = true ∧ v = true ∧ s.val = 101 ∧ u = true ∧ a = true ∧ p = true ∧ x = true ∧ l = false ∧ t = false)) := by
  simp [streaming.upgrade_response]
  split_ifs <;> simp_all

theorem disabled_request (g u v k o : Bool) (l p : U64) : streaming.upgrade_request false g l p u v k o = ok false := rfl

theorem no_unrequested_upgrade (v u a p x l t : Bool) (s : U16) : streaming.upgrade_response false v s u a p x l t = ok false := rfl

theorem request_bodyless (e g u v k o : Bool) (l p : U64) (h : streaming.upgrade_request e g l p u v k o = ok true) :
    l.val = 0 ∧ p.val = 0 ∧ g = true ∧ o = true := by
  simp [request_eq] at h
  tauto

theorem upgrade_no_http_framing (r v u a p x l t : Bool) (s : U16) (h : streaming.upgrade_response r v s u a p x l t = ok true) :
    r = true ∧ s.val = 101 ∧ a = true ∧ p = true ∧ x = true ∧ l = false ∧ t = false := by
  simp [response_eq] at h
  tauto

theorem invalid_accept (r v u p x l t : Bool) (s : U16) : streaming.upgrade_response r v s u false p x l t = ok false := by simp [response_eq]

theorem invalid_extensions (r v u a p l t : Bool) (s : U16) : streaming.upgrade_response r v s u a p false l t = ok false := by simp [response_eq]

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

theorem admission_eq (a : U64) (s : Bool) : streaming.admission a s = ok (decide (s = false ∧ a.val < 16)) := by
  cases s <;> simp [streaming.admission]

theorem admission_bounded (a : U64) (s : Bool) (h : streaming.admission a s = ok true) : a.val + 1 ≤ 16 := by
  simp [admission_eq] at h
  omega

theorem no_admission_stopped (a : U64) : streaming.admission a true = ok false := rfl

theorem limits_total (a u n l e q i t : U64) (s : Bool) :
    (∃ r, streaming.bytes_fit u n l = ok r) ∧ (∃ r, streaming.time_limits i t = ok r) ∧
    (∃ r, streaming.running s e q i t = ok r) ∧ (∃ r, streaming.admission a s = ok r) :=
  ⟨⟨_,bytes_eq u n l⟩,⟨_,time_eq i t⟩,⟨_,running_eq s e q i t⟩,⟨_,admission_eq a s⟩⟩
theorem peer_eq (a p : U64) (s : Bool) : streaming.peer_admission a p s = ok (decide (s = false ∧ a.val < 16 ∧ p.val < 8)) := by
  simp [streaming.peer_admission, admission_eq]
  split_ifs <;> simp_all

theorem peer_bounded (a p : U64) (s : Bool) (h : streaming.peer_admission a p s = ok true) : a.val + 1 ≤ 16 ∧ p.val + 1 ≤ 8 ∧ s = false := by
  simp [peer_eq] at h
  exact ⟨by omega, by omega, h.1⟩

theorem service_limit_eq (n : U64) : streaming.service_limit n = ok (decide (0 < n.val ∧ n.val ≤ 16)) := by
  simp [streaming.service_limit]
  split_ifs <;> simp_all

theorem service_eq (a c l : U64) : streaming.service_admission a c l = ok (decide (0 < c.val ∧ c.val ≤ 16 ∧ 0 < l.val ∧ l.val ≤ 16 ∧ a.val < c.val ∧ a.val < l.val)) := by
  simp [streaming.service_admission, service_limit_eq]
  split_ifs <;> simp_all

theorem service_bounded_across_reload (a c l : U64) (h : streaming.service_admission a c l = ok true) : a.val + 1 ≤ c.val ∧ a.val + 1 ≤ l.val ∧ l.val ≤ 16 := by
  simp [service_eq] at h
  omega

theorem revoked_service (a c : U64) : streaming.service_admission a c 0#u64 = ok false := by simp [service_eq]

theorem origin_eq (p s l : Bool) : streaming.origin_allowed p s l = ok (decide (p = false ∨ s = true ∨ l = true)) := by
  cases p <;> cases s <;> cases l <;> rfl

theorem foreign_origin_requires_allowlist (s l : Bool) (hs : s = false) (h : streaming.origin_allowed true s l = ok true) : l = true := by simp [origin_eq, hs] at h; exact h

theorem origin_denied : streaming.origin_allowed true false false = ok false := rfl

theorem deflate_eq (e o s a b p : Bool) : streaming.deflate_allowed e o s a b p = ok (decide (s = false ∨ (e = true ∧ o = true ∧ a = true ∧ b = true ∧ p = true))) := by
  simp [streaming.deflate_allowed]
  split_ifs <;> simp_all

theorem deflate_requires_opt_in_offer_and_resets (e o a b p : Bool) (h : streaming.deflate_allowed e o true a b p = ok true) : e = true ∧ o = true ∧ a = true ∧ b = true ∧ p = true := by simp [deflate_eq] at h; exact h

theorem no_unsolicited_deflate (e a b p : Bool) : streaming.deflate_allowed e false true a b p = ok false := by simp [deflate_eq]

theorem no_context_takeover (e o p : Bool) : streaming.deflate_allowed e o true false true p = ok false ∧ streaming.deflate_allowed e o true true false p = ok false := by simp [deflate_eq]

theorem optional_uncompressed (e o a b p : Bool) : streaming.deflate_allowed e o false a b p = ok true := rfl
end StreamingProofs
