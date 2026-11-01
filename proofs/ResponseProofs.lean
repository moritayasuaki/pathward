import RuntimeProofs
open Aeneas Aeneas.Std RustM
open pathward PathwardProofs RulesProofs ServingProofs
namespace ResponseProofs

theorem authority_port_eq (l : U16) (e r : Bool) :
    response.authority_port l e r = ok (if e then 443#u16 else if r then 80#u16 else l) := by
  simp [response.authority_port]
  split_ifs <;> rfl

theorem authority_port_tls (l : U16) (r : Bool) :
    response.authority_port l true r = ok 443#u16 := by simp [authority_port_eq]

theorem authority_port_redirect (l : U16) :
    response.authority_port l false true = ok 80#u16 := by simp [authority_port_eq]

theorem authority_port_direct (l : U16) :
    response.authority_port l false false = ok l := by simp [authority_port_eq]

theorem authority_port_allowed_eq (p : Option U16) (e : U16) :
    response.authority_port_allowed p e = ok (decide (e ≠ 0#u16 ∧ (p = none ∨ p = some e))) := by
  cases p <;> simp [response.authority_port_allowed] <;> split_ifs <;> simp_all

theorem authority_port_contract (p : Option U16) (e : U16) :
    response.authority_port_allowed p e = ok true ↔ e ≠ 0#u16 ∧ (p = none ∨ p = some e) := by
  simp [authority_port_allowed_eq]

theorem authority_port_no_mismatch (p e : U16)
    (h : response.authority_port_allowed (some p) e = ok true) : p = e := by
  have := (authority_port_contract (some p) e).mp h
  simpa using this.2

theorem authority_port_no_zero (p : Option U16) :
    response.authority_port_allowed p 0#u16 = ok false := by simp [authority_port_allowed_eq]

theorem authority_port_total (l e : U16) (t r : Bool) (p : Option U16) :
    (∃ port, response.authority_port l t r = ok port) ∧
    (∃ b, response.authority_port_allowed p e = ok b) :=
  ⟨⟨_, authority_port_eq l t r⟩, ⟨_, authority_port_allowed_eq p e⟩⟩

theorem forwarded_port_eq (p : Option U16) (e : U16) (t : Bool) :
    response.forwarded_port p e t = ok
      (if e ≠ 0#u16 ∧ p = some e ∧ e ≠ (if t then 443#u16 else 80#u16)
       then e else 0#u16) := by
  cases p <;> cases t <;>
    simp [response.forwarded_port, authority_port_allowed_eq] <;>
    split_ifs <;> simp_all

theorem forwarded_port_trusted (p : Option U16) (e v : U16) (t : Bool)
    (h : response.forwarded_port p e t = ok v) (hv : v ≠ 0#u16) :
    v = e ∧ p = some e := by
  rw [forwarded_port_eq] at h
  split_ifs at h with gate <;> simp_all

theorem forwarded_port_omitted (e : U16) (t : Bool) :
    response.forwarded_port none e t = ok 0#u16 := by simp [forwarded_port_eq]

theorem forwarded_port_mismatch (p e : U16) (t : Bool) (h : p ≠ e) :
    response.forwarded_port (some p) e t = ok 0#u16 := by simp [forwarded_port_eq, h]

theorem forwarded_port_standard (e : U16) (t : Bool) :
    response.forwarded_port (some (if t then 443#u16 else 80#u16)) e t = ok 0#u16 := by
  cases t <;> simp [response.forwarded_port, authority_port_allowed_eq]

theorem forwarded_port_total (p : Option U16) (e : U16) (t : Bool) :
    ∃ v, response.forwarded_port p e t = ok v := ⟨_, forwarded_port_eq p e t⟩

def visibleByte (b : U8) : Bool := decide (32 ≤ b.val ∧ b.val ≤ 126)
theorem visible_loop_eq (p : Slice U8) (i : Usize) (_hi : i.val ≤ p.val.length) :
    response.visible_loop p i = ok ((p.val.drop i.val).all visibleByte) := by
  rw [response.visible_loop]
  by_cases h : i < Slice.len p
  · have hlt : i.val < p.val.length := by simpa using h
    obtain ⟨j, hj, hv⟩ := succ_exists i (by have := p.property; omega)
    simp only [h, if_pos, index_eq p i hlt, bind_tc_ok, hj]
    rw [visible_loop_eq p j (by omega), drop_head p.val i.val hlt]
    simp only [List.all_cons, hv]
    split_ifs <;> simp_all [visibleByte]
  · have hge : p.val.length ≤ i.val := by simpa using h
    simp [h, List.drop_eq_nil_of_le hge]
termination_by p.val.length - i.val

theorem visible_eq (p : Slice U8) : response.visible p = ok (p.val.all visibleByte) := by
  simpa using visible_loop_eq p 0#usize (by simp)

def hostByte (b : U8) : Bool := decide ((97 ≤ b.val ∧ b.val ≤ 122) ∨ (48 ≤ b.val ∧ b.val ≤ 57) ∨ b.val = 46 ∨ b.val = 45)
theorem host_loop_eq (p : Slice U8) (i : Usize) (_hi : i.val ≤ p.val.length) :
    response.host_bytes_loop p i = ok ((p.val.drop i.val).all hostByte) := by
  rw [response.host_bytes_loop]
  by_cases h : i < Slice.len p
  · have hlt : i.val < p.val.length := by simpa using h
    obtain ⟨j, hj, hv⟩ := succ_exists i (by have := p.property; omega)
    simp only [h, if_pos, index_eq p i hlt, bind_tc_ok, hj]
    rw [host_loop_eq p j (by omega), drop_head p.val i.val hlt]
    simp only [List.all_cons, hv]
    split_ifs <;> simp_all [hostByte, UScalar.eq_equiv]
  · have hge : p.val.length ≤ i.val := by simpa using h
    simp [h, List.drop_eq_nil_of_le hge]
termination_by p.val.length - i.val

def hostPolicy (xs : List U8) : Bool := decide (xs ≠ [] ∧ xs.length ≤ 253) && xs.all hostByte
theorem host_eq (p : Slice U8) : response.host_bytes p = ok (hostPolicy p.val) := by
  simp [response.host_bytes, host_loop_eq p 0#usize (by simp), core.slice.Slice.is_empty, hostPolicy]
  split_ifs <;> simp_all

def headerNames : List (List U8) := [
  [99#u8, 111#u8, 110#u8, 116#u8, 101#u8, 110#u8, 116#u8, 45#u8, 115#u8, 101#u8, 99#u8, 117#u8, 114#u8, 105#u8, 116#u8, 121#u8, 45#u8, 112#u8, 111#u8, 108#u8, 105#u8, 99#u8, 121#u8],
  [115#u8, 116#u8, 114#u8, 105#u8, 99#u8, 116#u8, 45#u8, 116#u8, 114#u8, 97#u8, 110#u8, 115#u8, 112#u8, 111#u8, 114#u8, 116#u8, 45#u8, 115#u8, 101#u8, 99#u8, 117#u8, 114#u8, 105#u8, 116#u8, 121#u8],
  [114#u8, 101#u8, 102#u8, 101#u8, 114#u8, 114#u8, 101#u8, 114#u8, 45#u8, 112#u8, 111#u8, 108#u8, 105#u8, 99#u8, 121#u8],
  [112#u8, 101#u8, 114#u8, 109#u8, 105#u8, 115#u8, 115#u8, 105#u8, 111#u8, 110#u8, 115#u8, 45#u8, 112#u8, 111#u8, 108#u8, 105#u8, 99#u8, 121#u8],
  [120#u8, 45#u8, 102#u8, 114#u8, 97#u8, 109#u8, 101#u8, 45#u8, 111#u8, 112#u8, 116#u8, 105#u8, 111#u8, 110#u8, 115#u8],
  [120#u8, 45#u8, 114#u8, 111#u8, 98#u8, 111#u8, 116#u8, 115#u8, 45#u8, 116#u8, 97#u8, 103#u8],
  [108#u8, 105#u8, 110#u8, 107#u8]
]
theorem header_name_eq (n : Slice U8) : response.header_name n = ok (decide (n.val ∈ headerNames)) := by
  simp [response.header_name, lift, Array.to_slice, Array.make, same_path_eq, headerNames]
  split_ifs <;> simp_all
  by_cases h : n.val = [108#u8, 105#u8, 110#u8, 107#u8] <;> simp_all

abbrev headerPolicy (n v : Slice U8) : Prop := n.val ∈ headerNames ∧ v.val ≠ [] ∧ v.val.length ≤ 4096 ∧ v.val.all visibleByte = true
theorem header_eq (n v : Slice U8) : response.header_allowed n v = ok (decide (headerPolicy n v)) := by
  simp [response.header_allowed, header_name_eq, visible_eq, core.slice.Slice.is_empty, headerPolicy]
  split_ifs <;> simp_all
  cases hv : v.val.all visibleByte <;> simp_all [List.all_eq_true]

theorem header_contract (n v : Slice U8) : response.header_allowed n v = ok true ↔ headerPolicy n v := by simp [header_eq]

theorem header_no_controls (n v : Slice U8) (h : response.header_allowed n v = ok true) :
    ∀ b ∈ v.val, 32 ≤ b.val ∧ b.val ≤ 126 := by
  have hv := (header_contract n v).mp h |>.2.2.2
  simpa [List.all_eq_true, visibleByte] using hv

abbrev redirectPolicy (h c t : Slice U8) (s : U16) : Prop :=
  (s = 301#u16 ∨ s = 308#u16) ∧ h.val = c.val ∧ hostPolicy h.val = true ∧ t.val.all visibleByte = true ∧ (requestSpec t).isSome = true

theorem redirect_eq (h c t : Slice U8) (s : U16) :
    response.redirect_allowed h c t s = ok (decide (redirectPolicy h c t s)) := by
  simp [response.redirect_allowed, same_path_eq, host_eq, visible_eq, request_path_eq, redirectPolicy, core.option.Option.is_some]
  split_ifs <;> simp_all

theorem redirect_contract (h c t : Slice U8) (s : U16) :
    response.redirect_allowed h c t s = ok true ↔ redirectPolicy h c t s := by simp [redirect_eq]

theorem redirect_fixed_host (h c t : Slice U8) (s : U16) (p : response.redirect_allowed h c t s = ok true) : h.val = c.val :=
  (redirect_contract h c t s).mp p |>.2.1

theorem redirect_no_controls (h c t : Slice U8) (s : U16) (p : response.redirect_allowed h c t s = ok true) :
    ∀ b ∈ t.val, 32 ≤ b.val ∧ b.val ≤ 126 := by
  have ht := (redirect_contract h c t s).mp p |>.2.2.2.1
  simpa [List.all_eq_true, visibleByte] using ht

def prefixSlice (p : Slice U8) (n : Nat) : Slice U8 := ⟨p.val.take n, by have := p.property; simp; omega⟩
def suffixSlice (p : Slice U8) (n : Nat) : Slice U8 := ⟨p.val.drop n, by have := p.property; simp; omega⟩
theorem split_eq (p : Slice U8) (n : Usize) (hn : n.val ≤ p.val.length) :
    core.slice.Slice.split_at p n = ok (prefixSlice p n.val, suffixSlice p n.val) := by
  simp [core.slice.Slice.split_at, prefixSlice, suffixSlice, List.splitAt_eq, hn]

abbrev routePolicy (p f : Slice U8) (pre : Bool) : Prop :=
  canonical p.val = true ∧ canonical f.val = true ∧ f.val.length ≤ p.val.length ∧
  p.val.take f.val.length = f.val ∧
  (p.val.drop f.val.length = [] ∨ (pre = true ∧ 1 < f.val.length ∧ (p.val.drop f.val.length).head? = some 47#u8))

theorem route_eq (p f : Slice U8) (pre : Bool) :
    response.route_matches p f pre = ok (decide (routePolicy p f pre)) := by
  unfold response.route_matches
  simp only [valid_path_eq, bind_tc_ok]
  by_cases hp : canonical p.val = true
  · by_cases hf : canonical f.val = true
    · by_cases hl : p.val.length < f.val.length
      · simp [hp,hf,hl,routePolicy,show ¬ f.val.length ≤ p.val.length by omega]
      · have hle : f.val.length ≤ p.val.length := by omega
        simp only [hp,hf,if_true]
        have hc : ¬ Slice.len p < Slice.len f := by simpa using hl
        rw [if_neg hc, split_eq p (Slice.len f) (by simpa using hle)]
        by_cases he : p.val.take f.val.length = f.val
        · by_cases ht : p.val.drop f.val.length = []
          · simp [prefixSlice,suffixSlice,same_path_eq,core.slice.Slice.is_empty,ht,routePolicy,hp,hf,hle,he]
          · have hi : 0 < (suffixSlice p f.val.length).val.length := by simpa [suffixSlice] using List.length_pos_iff.mpr ht
            have ix := index_eq (suffixSlice p f.val.length) 0#usize hi
            simp only [suffixSlice] at ix
            simp [prefixSlice,suffixSlice,same_path_eq,core.slice.Slice.is_empty,routePolicy,hp,hf,hle,he,ht,ix,List.head?_eq_getElem?]
            split_ifs <;> simp_all
        · simp [prefixSlice,suffixSlice,same_path_eq,he,routePolicy,hp,hf]
    · simp [hp,hf,routePolicy]
  · simp [hp,routePolicy]

theorem route_contract (p f : Slice U8) (pre : Bool) :
    response.route_matches p f pre = ok true ↔ routePolicy p f pre := by simp [route_eq]

theorem response_total (h c t : Slice U8) (s : U16) (pre : Bool) :
    (∃ b, response.redirect_allowed h c t s = ok b) ∧
    (∃ b, response.header_allowed h t = ok b) ∧
    (∃ b, response.route_matches t h pre = ok b) :=
  ⟨⟨_,redirect_eq h c t s⟩,⟨_,header_eq h t⟩,⟨_,route_eq t h pre⟩⟩
end ResponseProofs
