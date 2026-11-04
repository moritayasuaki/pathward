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

theorem response_storage_eq (body credit : U64) :
    delivery.response_storage body credit = ok (decide
      (2 * body.val + 262144 ≤ credit.val ∧ credit.val ≤ 134479872)) := by
  unfold delivery.response_storage
  by_cases low : 262144 ≤ credit.val
  · by_cases high : credit.val ≤ 134479872
    · obtain ⟨rest, hr, hrv, _⟩ := WP.spec_imp_exists
        (U64.sub_bv_spec (x := credit) (y := 262144#u64) (by simpa using low))
      obtain ⟨half, hh, hhv, _⟩ := WP.spec_imp_exists
        (U64.div_bv_spec rest (y := 2#u64) (by decide))
      have hc : (262144#u64).val = 262144 := rfl
      have ht : (2#u64).val = 2 := rfl
      rw [hc] at hrv
      rw [ht] at hhv
      have equivalent : body.val ≤ (credit.val - 262144) / 2 ↔
          2 * body.val + 262144 ≤ credit.val := by omega
      simp [low, high, hr, hh, hrv, hhv, equivalent]
    · simp [low, high]
  · simp [low]
    omega

theorem response_storage_covers_copies (body credit : U64)
    (h : delivery.response_storage body credit = ok true) :
    2 * body.val + 262144 ≤ credit.val ∧ body.val ≤ 67108864 := by
  simp [response_storage_eq] at h
  exact ⟨h.1, by omega⟩

theorem response_storage_cannot_exceed_cap (body credit : U64)
    (h : delivery.response_storage body credit = ok true) :
    credit.val ≤ 134479872 ∧ credit.val < 2^64 := by
  simp [response_storage_eq] at h
  exact ⟨h.2, by omega⟩

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

theorem reuse_eq (c a : U64) (r d : Bool) :
    delivery.reuse_allowed c a r d = ok (decide
      (r = true ∧ d = false ∧ 0 < c.val ∧ c.val < 100 ∧ a.val < 120000)) := by
  cases r <;> cases d <;> simp [delivery.reuse_allowed]
  split_ifs <;> simp_all

theorem reuse_bounded (c a : U64) (r d : Bool)
    (h : delivery.reuse_allowed c a r d = ok true) :
    c.val < 100 ∧ a.val < 120000 ∧ r = true ∧ d = false := by
  simp [reuse_eq] at h
  tauto

theorem reuse_no_draining (c a : U64) (r : Bool) :
    delivery.reuse_allowed c a r true = ok false := by simp [reuse_eq]

theorem reuse_expired (c a : U64) (r d : Bool) (h : 120000 ≤ a.val) :
    delivery.reuse_allowed c a r d = ok false := by
  simp [reuse_eq]
  omega

theorem reuse_total (c a : U64) (r d : Bool) :
    ∃ b, delivery.reuse_allowed c a r d = ok b := ⟨_, reuse_eq c a r d⟩

theorem request_credit_eq (g p : U64) (d : Bool) :
    delivery.request_credit g p d = ok (decide (d = false ∧ 0 < g.val ∧ 0 < p.val)) := by
  cases d <;> simp [delivery.request_credit]
  split_ifs <;> simp_all

theorem request_credit_positive (g p : U64) (d : Bool)
    (h : delivery.request_credit g p d = ok true) :
    0 < g.val ∧ 0 < p.val ∧ d = false := by
  simp [request_credit_eq] at h
  tauto

theorem request_credit_no_draining (g p : U64) :
    delivery.request_credit g p true = ok false := rfl

theorem request_credit_total (g p : U64) (d : Bool) :
    ∃ b, delivery.request_credit g p d = ok b := ⟨_, request_credit_eq g p d⟩

theorem task_slot_eq (n : U64) :
    delivery.task_slot n = ok (decide (n.val < 64)) := by rfl

theorem tasks_bounded (n : U64) (h : delivery.task_slot n = ok true) : n.val + 1 ≤ 64 := by
  simp [task_slot_eq] at h
  omega

theorem encode_eq (e : Bool) (n : U64) (s : U16) (m p r c t x : Bool) :
    delivery.encode_allowed e n s m p r c t x = ok (decide
      (e = true ∧ 1024 ≤ n.val ∧ n.val ≤ 4194304 ∧ s.val = 200 ∧ m = true ∧
       p = false ∧ r = false ∧ c = false ∧ t = false ∧ x = true)) := by
  simp [delivery.encode_allowed, UScalar.eq_equiv]
  split_ifs <;> simp_all

theorem encode_safe (e : Bool) (n : U64) (s : U16) (m p r c t x : Bool)
    (h : delivery.encode_allowed e n s m p r c t x = ok true) :
    n.val ≤ 4194304 ∧ p = false ∧ r = false ∧ c = false ∧ t = false := by
  simp [encode_eq] at h
  tauto

theorem encode_total (e : Bool) (n : U64) (s : U16) (m p r c t x : Bool) :
    ∃ b, delivery.encode_allowed e n s m p r c t x = ok b := ⟨_, encode_eq e n s m p r c t x⟩

theorem multiplex_eq (a n t : U64) (d : Bool) :
    delivery.multiplex_slot a n t d = ok (decide (d = false ∧ a.val < 32 ∧ n.val < 100 ∧ t.val < 120000)) := by
  simp [delivery.multiplex_slot]
  split_ifs <;> simp_all

theorem multiplex_bounded (a n t : U64) (d : Bool)
    (h : delivery.multiplex_slot a n t d = ok true) :
    a.val + 1 ≤ 32 ∧ n.val + 1 ≤ 100 ∧ t.val < 120000 ∧ d = false := by
  simp [multiplex_eq] at h
  rcases h with ⟨hd, ha, hn, ht⟩
  exact ⟨by omega, by omega, ht, hd⟩

theorem multiplex_total (a n t : U64) (d : Bool) :
    ∃ b, delivery.multiplex_slot a n t d = ok b := ⟨_, multiplex_eq a n t d⟩

theorem early_eq (c r p : Bool) (n : U64) (s : Bool) :
    delivery.early_allowed c r p n s = ok (decide (c = true ∨ (r = true ∧ p = true ∧ n.val = 0 ∧ s = false))) := by
  cases c <;> simp [delivery.early_allowed, UScalar.eq_equiv]
  split_ifs <;> simp_all

theorem early_only_published_reads (r p : Bool) (n : U64) (s : Bool)
    (h : delivery.early_allowed false r p n s = ok true) :
    r = true ∧ p = true ∧ n.val = 0 ∧ s = false := by simpa [early_eq] using h

theorem early_no_proxy (r : Bool) (n : U64) (s : Bool) :
    delivery.early_allowed false r false n s = ok false := by simp [early_eq]

theorem early_total (c r p : Bool) (n : U64) (s : Bool) :
    ∃ b, delivery.early_allowed c r p n s = ok b := ⟨_, early_eq c r p n s⟩

theorem wire_eq (u n l : U64) :
    delivery.wire_fits u n l = ok (decide (l.val ≤ 134283264 ∧ u.val + n.val ≤ l.val)) := by
  unfold delivery.wire_fits
  by_cases hl : l.val ≤ 134283264
  · by_cases hu : u.val ≤ l.val
    · obtain ⟨diff, hd, hv, _⟩ := WP.spec_imp_exists (U64.sub_bv_spec (x := l) (y := u) (by omega))
      simp [hl, hu, hd, hv]
      omega
    · simp [hl, hu]
      omega
  · simp [hl]

theorem wire_bounded (u n l : U64) (h : delivery.wire_fits u n l = ok true) :
    u.val + n.val ≤ l.val ∧ l.val ≤ 134283264 ∧ u.val + n.val < 2^64 := by
  simp [wire_eq] at h
  omega

theorem wire_total (u n l : U64) :
    ∃ b, delivery.wire_fits u n l = ok b := ⟨_, wire_eq u n l⟩

theorem cancel_slot_eq (n t : U64) :
    delivery.cancel_slot n t = ok (decide (n.val < 256 ∧ t.val < 120000)) := by
  simp [delivery.cancel_slot]
  split_ifs <;> simp_all

theorem cancelled_heads_bounded (n t : U64)
    (h : delivery.cancel_slot n t = ok true) :
    n.val + 1 ≤ 256 ∧ t.val < 120000 ∧ n.val + 1 < 2^64 := by
  simp [cancel_slot_eq] at h
  omega

theorem cancel_slot_total (n t : U64) :
    ∃ b, delivery.cancel_slot n t = ok b := ⟨_, cancel_slot_eq n t⟩

end DeliveryProofs
