import ServingProofs
open Aeneas Aeneas.Std RustM
open pathward PathwardProofs
namespace TlsProofs

theorem identity_eq (s h c : Slice U8) :
    tls.identity_allowed s h c = ok (decide (s.val ≠ [] ∧ s.val = h.val ∧ h.val = c.val)) := by
  simp [tls.identity_allowed, core.slice.Slice.is_empty, same_path_eq]
  split_ifs <;> simp_all
  by_cases hh : h.val = c.val <;> simp_all

theorem identity_contract (s h c : Slice U8) :
    tls.identity_allowed s h c = ok true ↔ s.val ≠ [] ∧ s.val = h.val ∧ h.val = c.val := by
  simp [identity_eq]

theorem no_domain_fronting (s h c : Slice U8) (hne : s.val ≠ h.val) :
    tls.identity_allowed s h c = ok false := by simp [identity_eq, hne]

theorem no_missing_sni (h c : Slice U8) (s : Slice U8) (he : s.val = []) :
    tls.identity_allowed s h c = ok false := by simp [identity_eq, he]

abbrev secretPolicy (p o : tls.SecretFacts) (uid : U32) : Prop :=
  p.regular = true ∧ o.regular = true ∧ p.owner = uid ∧ o.owner = uid ∧
  p.mode = 384#u32 ∧ o.mode = 384#u32 ∧ p.links = 1#u64 ∧ o.links = 1#u64 ∧
  p.size.val ≤ 1048576 ∧ o.size = p.size ∧ p.device = o.device ∧ p.inode = o.inode

theorem secret_eq (p o : tls.SecretFacts) (uid : U32) :
    tls.secret_allowed p o uid = ok (decide (secretPolicy p o uid)) := by
  simp [tls.secret_allowed, secretPolicy]
  split_ifs <;> simp_all

theorem secret_contract (p o : tls.SecretFacts) (uid : U32) :
    tls.secret_allowed p o uid = ok true ↔ secretPolicy p o uid := by simp [secret_eq]

theorem no_public_secret (p o : tls.SecretFacts) (uid : U32) (hm : o.mode ≠ 384#u32) :
    tls.secret_allowed p o uid = ok false := by simp [secret_eq, secretPolicy, hm]

theorem secret_identity (p o : tls.SecretFacts) (uid : U32)
    (h : tls.secret_allowed p o uid = ok true) : p.device = o.device ∧ p.inode = o.inode := by
  have hp := (secret_contract p o uid).mp h
  exact hp.2.2.2.2.2.2.2.2.2.2

theorem activate_eq (b e n : U64) (k h p : Bool) :
    tls.activate b e n k h p = ok (decide (k = true ∧ h = true ∧ p = true ∧ b.val ≤ n.val ∧ n.val < e.val)) := by
  simp [tls.activate]
  split_ifs <;> simp_all

theorem activate_contract (b e n : U64) (k h p : Bool) :
    tls.activate b e n k h p = ok true ↔ k = true ∧ h = true ∧ p = true ∧ b.val ≤ n.val ∧ n.val < e.val := by
  simp [activate_eq]

theorem no_unpersisted_activation (b e n : U64) (k h : Bool) :
    tls.activate b e n k h false = ok false := by simp [activate_eq]

theorem no_expired_activation (b e n : U64) (k h p : Bool) (hex : e.val ≤ n.val) :
    tls.activate b e n k h p = ok false := by simp [activate_eq, Nat.not_lt.mpr hex]

abbrev renewPolicy (b e n : U64) : Prop :=
  n.val < b.val ∨ e.val ≤ n.val ∨ e.val - n.val ≤ (e.val - b.val) / 3

theorem renewal_eq (b e n : U64) : tls.renewal_due b e n = ok (decide (renewPolicy b e n)) := by
  unfold tls.renewal_due
  by_cases hb : n < b
  · have hv : n.val < b.val := by simpa using hb
    simp [hb, renewPolicy, hv]
  · by_cases he : n ≥ e
    · have hv : e.val ≤ n.val := by simpa using he
      simp [hb, he, renewPolicy, hv]
    · have hbn : b.val ≤ n.val := by simpa using hb
      have hne : n.val < e.val := by simpa using he
      obtain ⟨l, hl, hlv, _⟩ := WP.spec_imp_exists (U64.sub_bv_spec (x := e) (y := b) (by omega))
      obtain ⟨r, hr, hrv, _⟩ := WP.spec_imp_exists (U64.sub_bv_spec (x := e) (y := n) (by omega))
      obtain ⟨d, hd, hdv, _⟩ := WP.spec_imp_exists (U64.div_bv_spec l (y := 3#u64) (by decide))
      simp only [hb, he, if_false, hl, hr, hd, bind_tc_ok]
      simp [renewPolicy, show ¬n.val < b.val by omega, show ¬e.val ≤ n.val by omega, hrv, hdv, hlv]

theorem renewal_contract (b e n : U64) :
    tls.renewal_due b e n = ok true ↔ renewPolicy b e n := by simp [renewal_eq, renewPolicy]

theorem renew_at_expiration (b e n : U64) (h : e.val ≤ n.val) :
    tls.renewal_due b e n = ok true := by simp [renewal_eq, renewPolicy, h]

theorem lifecycle_total (b e n : U64) (k h p : Bool) :
    (∃ result, tls.activate b e n k h p = ok result) ∧
    (∃ result, tls.renewal_due b e n = ok result) := by
  exact ⟨⟨_, activate_eq b e n k h p⟩, ⟨_, renewal_eq b e n⟩⟩

end TlsProofs
