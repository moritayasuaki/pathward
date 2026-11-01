import ProxyProofs
open Aeneas Aeneas.Std RustM
open pathward PathwardProofs RulesProofs ServingProofs ResponseProofs
namespace RoutingProofs

def choice (v d s r p : Bool) : routing.Route :=
  if !v || d then .Denied else if s then .Static else if r then .Redirect else if p then .Proxy else .Missing

theorem select_eq (v d s r p : Bool) : routing.select v d s r p = ok (choice v d s r p) := by
  cases v <;> cases d <;> cases s <;> cases r <;> cases p <;> rfl

theorem denial_first (v s r p : Bool) : routing.select v true s r p = ok .Denied := by cases v <;> rfl
theorem malformed_denied (d s r p : Bool) : routing.select false d s r p = ok .Denied := rfl
theorem static_before_proxy (r p : Bool) : routing.select true false true r p = ok .Static := rfl
theorem redirect_before_proxy (p : Bool) : routing.select true false false true p = ok .Redirect := rfl
theorem proxy_contract (v d s r p : Bool) :
    routing.select v d s r p = ok .Proxy ↔ v = true ∧ d = false ∧ s = false ∧ r = false ∧ p = true := by
  cases v <;> cases d <;> cases s <;> cases r <;> cases p <;> simp [routing.select]
theorem no_proxy_after_denial (v s r p : Bool) : routing.select v true s r p ≠ ok .Proxy := by rw [denial_first]; simp
theorem no_static_fallback (r p : Bool) : routing.select true false true r p ≠ ok .Proxy := by rw [static_before_proxy]; simp

abbrev cap (r : Bool) : Nat := if r then 67108864 else 16777216
theorem body_limit_eq (l : U64) (r : Bool) : routing.body_limit l r = ok (decide (l.val ≤ cap r)) := by cases r <;> simp [routing.body_limit,cap]
theorem body_fits_eq (n l : U64) (r : Bool) : routing.body_fits n l r = ok (decide (l.val ≤ cap r ∧ n.val ≤ l.val)) := by
  simp [routing.body_fits,body_limit_eq]
  split_ifs <;> simp_all

theorem chunk_eq (u n l : U64) :
    routing.chunk_fits u n l = ok (decide (l.val ≤ 67108864 ∧ u.val + n.val ≤ l.val)) := by
  unfold routing.chunk_fits
  rw [body_fits_eq]
  by_cases h : l.val ≤ 67108864 ∧ u.val ≤ l.val
  · obtain ⟨diff, hd, hv, _⟩ := WP.spec_imp_exists (U64.sub_bv_spec (x := l) (y := u) (by omega))
    simp [h,cap,hd,hv]
    omega
  · simp [h,cap]
    omega

theorem chunk_bounded (u n l : U64) (h : routing.chunk_fits u n l = ok true) :
    u.val + n.val ≤ l.val ∧ l.val ≤ 67108864 := by
  have hp : l.val ≤ 67108864 ∧ u.val+n.val ≤ l.val := by simpa [chunk_eq] using h
  exact hp.symm

theorem request_frame_eq (n l : U64) (t d : Bool) :
    routing.request_framing n l t d = ok (decide (l.val ≤ 16777216 ∧ n.val ≤ l.val ∧ t = false ∧ d = false)) := by
  simp [routing.request_framing,body_fits_eq,cap]
  split_ifs <;> simp_all

theorem response_frame_eq (n : Option U64) (l : U64) (t d : Bool) :
    routing.response_framing n l t d = ok (match n with
      | none => decide (d = false ∧ l.val ≤ 67108864)
      | some n => decide (d = false ∧ l.val ≤ 67108864 ∧ n.val ≤ l.val ∧ t = false)) := by
  cases n <;> simp [routing.response_framing,body_limit_eq,body_fits_eq,cap] <;> split_ifs <;> simp_all

theorem no_request_transfer (n l : U64) (d : Bool) : routing.request_framing n l true d = ok false := by simp [request_frame_eq]
theorem no_response_ambiguity (n l : U64) (d : Bool) : routing.response_framing (some n) l true d = ok false := by simp [response_frame_eq]
theorem no_response_duplicate (n : Option U64) (l : U64) (t : Bool) : routing.response_framing n l t true = ok false := by cases n <;> simp [response_frame_eq]

abbrev timePolicy (b c h t : U64) : Prop :=
  100 ≤ b.val ∧ b.val ≤ 30000 ∧ b.val ≤ t.val ∧
  50 ≤ c.val ∧ c.val ≤ 10000 ∧ c.val ≤ t.val ∧
  100 ≤ h.val ∧ h.val ≤ t.val ∧ 100 ≤ t.val ∧ t.val ≤ 120000

theorem time_eq (b c h t : U64) : routing.time_limits b c h t = ok (decide (timePolicy b c h t)) := by
  simp [routing.time_limits,timePolicy]
  split_ifs <;> simp_all

theorem times_bounded (b c h t : U64) (valid : routing.time_limits b c h t = ok true) :
    b.val ≤ t.val ∧ c.val ≤ t.val ∧ h.val ≤ t.val ∧ t.val ≤ 120000 := by
  have hp : timePolicy b c h t := by simpa [time_eq,timePolicy] using valid
  rcases hp with ⟨_,_,hb,_,_,hc,_,hh,_,ht⟩
  exact ⟨hb,hc,hh,ht⟩

theorem connection_eq (l : U64) : routing.connection_limit l = ok (decide (0 < l.val ∧ l.val ≤ 3)) := by
  simp [routing.connection_limit]; split_ifs <;> simp_all

theorem service_eq (a c l : U64) :
    routing.service_admit a c l = ok (decide (0 < c.val ∧ c.val ≤ 3 ∧ 0 < l.val ∧ l.val ≤ 3 ∧ a.val < c.val ∧ a.val < l.val)) := by
  simp [routing.service_admit,connection_eq]; split_ifs <;> simp_all

theorem service_bounded (a c l : U64) (h : routing.service_admit a c l = ok true) :
    a.val + 1 ≤ c.val ∧ a.val + 1 ≤ l.val ∧ a.val + 1 ≤ 3 := by
  simp [service_eq] at h
  omega

theorem no_admission_at_live_limit (a c l : U64) (h : l.val ≤ a.val) : routing.service_admit a c l = ok false := by
  simp [service_eq,show ¬a.val < l.val by omega]
theorem no_admission_to_disabled (a c : U64) : routing.service_admit a c 0#u64 = ok false := by simp [service_eq]

abbrev subtreePolicy (p f : Slice U8) : Prop := canonical p.val = true ∧ (f.val = [47#u8] ∨ routePolicy p f true)
theorem subtree_eq (p f : Slice U8) : routing.subtree p f = ok (decide (subtreePolicy p f)) := by
  simp [routing.subtree,valid_path_eq,same_path_eq,lift,Array.to_slice,Array.make,route_eq,subtreePolicy]
  split_ifs <;> simp_all

theorem subtree_boundary (p f : Slice U8) (h : routing.subtree p f = ok true) (hf : f.val ≠ [47#u8]) :
    p.val.take f.val.length = f.val ∧ (p.val.drop f.val.length = [] ∨ (1 < f.val.length ∧ (p.val.drop f.val.length).head? = some 47#u8)) := by
  have hp : subtreePolicy p f := by
    rw [subtree_eq] at h
    injection h with hd
    exact of_decide_eq_true hd
  have hr : routePolicy p f true := hp.2.resolve_left hf
  simpa using And.intro hr.2.2.2.1 hr.2.2.2.2

def stemPolicy (p : Slice U8) : Option (Slice U8) :=
  if canonical p.val then some p
  else if 1 < p.val.length ∧ (p.val.drop (p.val.length-1)).head? = some 47#u8 ∧ canonical (p.val.take (p.val.length-1)) = true
    then some (prefixSlice p (p.val.length-1)) else none

theorem stem_eq (p : Slice U8) : routing.stem p = ok (stemPolicy p) := by
  unfold routing.stem
  rw [valid_path_eq]
  by_cases hp : canonical p.val = true
  · simp [hp,stemPolicy]
  · by_cases hl : 1 < p.val.length
    · have hc : Slice.len p > 1#usize := by simpa using hl
      obtain ⟨i, hi, hv, _⟩ := WP.spec_imp_exists (Usize.sub_bv_spec (x := Slice.len p) (y := 1#usize) (by scalar_tac))
      have hiv : i.val = p.val.length-1 := by simpa using hv
      have hlen : i.val ≤ p.val.length := by omega
      have ht : (0#usize).val < (suffixSlice p i.val).val.length := by simp [suffixSlice,hiv]; omega
      simp only [hp,hc,if_true,hi,bind_tc_ok,split_eq p i hlen]
      simp only [Bool.false_eq_true,if_false]
      have ix := index_eq (suffixSlice p i.val) 0#usize ht
      simp only [suffixSlice,hiv] at ix
      have hlast : p.val.length-1 < p.val.length := by omega
      simp [stemPolicy,hp,hl,prefixSlice,suffixSlice,hiv,ix,valid_path_eq,List.head?_eq_getElem?,List.getElem?_eq_getElem hlast]
      split_ifs <;> simp_all
    · simp [hp,hl,stemPolicy]

theorem stem_canonical (p s : Slice U8) (h : routing.stem p = ok (some s)) : canonical s.val = true := by
  rw [stem_eq] at h
  unfold stemPolicy at h
  split_ifs at h <;> simp_all [prefixSlice]
  subst s
  simp_all

theorem stem_shape (p s : Slice U8) (h : routing.stem p = ok (some s)) :
    p.val = s.val ∨ p.val = s.val ++ [47#u8] := by
  rw [stem_eq] at h
  unfold stemPolicy at h
  split_ifs at h with hc hs
  · have he : p = s := by simpa using h
    subst s
    exact Or.inl rfl
  · have he : prefixSlice p (p.val.length-1) = s := by simpa using h
    have ht : p.val.drop (p.val.length-1) = [47#u8] := by
      have hl : (p.val.drop (p.val.length-1)).length = 1 := by simp; omega
      cases hd : p.val.drop (p.val.length-1) with
      | nil => simp [hd] at hl
      | cons b tail =>
        have he : tail = [] := by simpa [hd] using hl
        have hb : b = 47#u8 := by simpa [hd] using hs.2.1
        simp [he,hb]
    right
    rw [←he]
    simpa [prefixSlice,ht] using (List.take_append_drop (p.val.length-1) p.val).symm
  · simp at h

theorem stem_input_bytes (p s : Slice U8) (h : routing.stem p = ok (some s)) :
    ∀ b ∈ p.val, allowedByte b = true := by
  have hc := canonical_all_allowed s.val (stem_canonical p s h)
  rcases stem_shape p s h with he | he
  · simpa [he] using hc
  · intro b hb
    rw [he] at hb
    rcases List.mem_append.mp hb with hb | hb
    · exact hc b hb
    · have h47 : b = 47#u8 := by simpa using hb
      subst b
      decide


theorem route_total (v d s r x : Bool) (p f : Slice U8) :
    (∃ result, routing.select v d s r x = ok result) ∧
    (∃ result, routing.stem p = ok result) ∧
    (∃ result, routing.subtree p f = ok result) :=
  ⟨⟨_,select_eq v d s r x⟩,⟨_,stem_eq p⟩,⟨_,subtree_eq p f⟩⟩

theorem limits_total (n l b c h t a : U64) (r d : Bool) (opt : Option U64) :
    (∃ result, routing.body_limit l r = ok result) ∧
    (∃ result, routing.body_fits n l r = ok result) ∧
    (∃ result, routing.chunk_fits a n l = ok result) ∧
    (∃ result, routing.time_limits b c h t = ok result) ∧
    (∃ result, routing.service_admit a c l = ok result) ∧
    (∃ result, routing.request_framing n l r d = ok result) ∧
    (∃ result, routing.response_framing opt l r d = ok result) :=
  ⟨⟨_,body_limit_eq l r⟩,⟨_,body_fits_eq n l r⟩,⟨_,chunk_eq a n l⟩,⟨_,time_eq b c h t⟩,
   ⟨_,service_eq a c l⟩,⟨_,request_frame_eq n l r d⟩,⟨_,response_frame_eq opt l r d⟩⟩
end RoutingProofs
