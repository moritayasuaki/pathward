import StreamingProofs
open Aeneas Aeneas.Std RustM
open pathward PathwardProofs
namespace DeliveryProofs

theorem reserve_eq (g p n : U64) (d : Bool) :
    delivery.reserve_allowed g p n d = ok (decide
      (d = false ∧ 0 < n.val ∧ g.val + n.val ≤ 268435456 ∧ p.val + n.val ≤ 201326592)) := by
  unfold delivery.reserve_allowed
  cases d
  · by_cases hn : 0 < n.val
    · by_cases hg : g.val ≤ 268435456
      · by_cases hp : p.val ≤ 201326592
        · obtain ⟨dg, hdg, hvg, _⟩ := WP.spec_imp_exists
            (U64.sub_bv_spec (x := 268435456#u64) (y := g) (by simpa using hg))
          obtain ⟨dp, hdp, hvp, _⟩ := WP.spec_imp_exists
            (U64.sub_bv_spec (x := 201326592#u64) (y := p) (by simpa using hp))
          have hcg : (268435456#u64).val = 268435456 := rfl
          have hcp : (201326592#u64).val = 201326592 := rfl
          rw [hcg] at hvg
          rw [hcp] at hvp
          have hglobal : (n.val ≤ 268435456 - g.val) ↔ g.val + n.val ≤ 268435456 := by omega
          have hpeer : (n.val ≤ 201326592 - p.val) ↔ p.val + n.val ≤ 201326592 := by omega
          simp [hn, hg, hp, hdg, hdp, hvg, hvp, hglobal, hpeer]
          split_ifs <;> simp_all
        · simp [hn, hg, hp]
          omega
      · simp [hn, hg]
        omega
    · simp [hn]
  · simp

theorem reserve_bounded (g p n : U64) (d : Bool)
    (h : delivery.reserve_allowed g p n d = ok true) :
    g.val + n.val ≤ 268435456 ∧ p.val + n.val ≤ 201326592 ∧ d = false := by
  simp [reserve_eq] at h
  tauto

theorem reserve_no_overflow (g p n : U64) (d : Bool)
    (h : delivery.reserve_allowed g p n d = ok true) :
    g.val + n.val < 2^64 ∧ p.val + n.val < 2^64 := by
  have hb := reserve_bounded g p n d h
  omega

theorem reserve_no_draining (g p n : U64) :
    delivery.reserve_allowed g p n true = ok false := rfl

theorem reserve_positive (g p n : U64) (d : Bool)
    (h : delivery.reserve_allowed g p n d = ok true) : 0 < n.val := by
  simp [reserve_eq] at h
  tauto

theorem reserve_total (g p n : U64) (d : Bool) :
    ∃ b, delivery.reserve_allowed g p n d = ok b := ⟨_, reserve_eq g p n d⟩

theorem shrink_eq (b a : U64) :
    delivery.shrink_allowed b a = ok (decide (a.val ≤ b.val)) := by rfl

theorem shrink_cannot_add_credit (b a : U64)
    (h : delivery.shrink_allowed b a = ok true) : a.val ≤ b.val := by
  simpa [shrink_eq] using h

theorem phase_eq (e b : U64) (d : Bool) :
    delivery.phase_live e b d = ok (decide (d = false ∧ 0 < b.val ∧ b.val ≤ 120000 ∧ e.val < b.val)) := by
  simp [delivery.phase_live]
  split_ifs <;> simp_all

theorem phase_bounded (e b : U64) (d : Bool)
    (h : delivery.phase_live e b d = ok true) : e.val < 120000 ∧ d = false := by
  simp [phase_eq] at h
  exact ⟨by omega, h.1⟩

theorem phase_expired (e b : U64) (d : Bool) (h : b.val ≤ e.val) :
    delivery.phase_live e b d = ok false := by
  simp [phase_eq]
  omega

theorem phase_no_draining (e b : U64) : delivery.phase_live e b true = ok false := rfl

theorem idle_has_no_http_timeout : delivery.input_timeout_status 0#u64 = ok 0#u16 := rfl

theorem partial_head_times_out (n : U64) (h : 0 < n.val) :
    delivery.input_timeout_status n = ok 408#u16 := by
  simp [delivery.input_timeout_status, UScalar.eq_equiv]
  omega

end DeliveryProofs
