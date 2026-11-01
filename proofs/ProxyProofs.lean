import ReleaseProofs
open Aeneas Aeneas.Std RustM
open pathward PathwardProofs RulesProofs ServingProofs ResponseProofs
namespace ProxyProofs

abbrev modePolicy (r p d x : Bool) : Prop :=
  if x then r = false ∧ p = false ∧ d = false else r = true ∧ (p = true ∨ d = true)
theorem mode_eq (r p d x : Bool) :
    proxy.site_mode_allowed r p d x = ok (decide (modePolicy r p d x)) := by
  cases r <;> cases p <;> cases d <;> cases x <;> simp [proxy.site_mode_allowed,modePolicy]
theorem no_mixed_proxy (r p d : Bool) (h : proxy.site_mode_allowed r p d true = ok true) :
    r = false ∧ p = false ∧ d = false := by simpa [mode_eq,modePolicy] using h

def loopback4 : List U8 := [49#u8, 50#u8, 55#u8, 46#u8, 48#u8, 46#u8, 48#u8, 46#u8, 49#u8]
def loopback6 : List U8 := [58#u8, 58#u8, 49#u8]
theorem endpoint_eq (a : Slice U8) (p : U16) :
    proxy.endpoint_allowed a p = ok (decide (0 < p.val ∧ (a.val = loopback4 ∨ a.val = loopback6))) := by
  simp [proxy.endpoint_allowed,same_path_eq,lift,Array.to_slice,Array.make,loopback4,loopback6]
  split_ifs <;> simp_all
  by_cases h : a.val = [58#u8,58#u8,49#u8] <;> simp_all

theorem endpoint_contract (a : Slice U8) (p : U16) :
    proxy.endpoint_allowed a p = ok true ↔ 0 < p.val ∧ (a.val = loopback4 ∨ a.val = loopback6) := by simp [endpoint_eq]
theorem endpoint_no_zero (a : Slice U8) : proxy.endpoint_allowed a 0#u16 = ok false := by simp [endpoint_eq]

def methods : List (List U8) := [
  [71#u8, 69#u8, 84#u8],
  [72#u8, 69#u8, 65#u8, 68#u8],
  [80#u8, 79#u8, 83#u8, 84#u8],
  [80#u8, 85#u8, 84#u8],
  [80#u8, 65#u8, 84#u8, 67#u8, 72#u8],
  [68#u8, 69#u8, 76#u8, 69#u8, 84#u8, 69#u8],
  [79#u8, 80#u8, 84#u8, 73#u8, 79#u8, 78#u8, 83#u8]
]
theorem method_eq (m : Slice U8) : proxy.method_allowed m = ok (decide (m.val ∈ methods)) := by
  simp [proxy.method_allowed,same_path_eq,lift,Array.to_slice,Array.make,methods]
  split_ifs <;> simp_all
  by_cases h : m.val = [79#u8, 80#u8, 84#u8, 73#u8, 79#u8, 78#u8, 83#u8] <;> simp_all

theorem status_eq (s : U16) : proxy.status_allowed s = ok (decide (200 ≤ s.val ∧ s.val ≤ 599)) := by
  simp [proxy.status_allowed]
  split_ifs <;> simp_all

theorem request_framing_eq (n : U64) (t d : Bool) :
    proxy.request_framing n t d = ok (decide (n.val ≤ 1048576 ∧ t = false ∧ d = false)) := by
  have hc : proxy.MAX_REQUEST_BODY = ok 1048576#u64 := by unfold proxy.MAX_REQUEST_BODY; rfl
  simp [proxy.request_framing,hc]
  split_ifs <;> simp_all

theorem response_framing_eq (n : Option U64) (t d : Bool) :
    proxy.response_framing n t d = ok ((match n with | none => decide (d = false) | some n => decide (d = false ∧ n.val ≤ 8388608 ∧ t = false))) := by
  have hc : proxy.MAX_RESPONSE_BODY = ok 8388608#u64 := by unfold proxy.MAX_RESPONSE_BODY; rfl
  cases n <;> simp [proxy.response_framing,hc] <;> split_ifs <;> simp_all

theorem request_no_transfer_encoding (n : U64) (d : Bool) :
    proxy.request_framing n true d = ok false := by simp [request_framing_eq]
theorem response_no_ambiguous_length (n : U64) (d : Bool) :
    proxy.response_framing (some n) true d = ok false := by simp [response_framing_eq]
theorem response_no_duplicate_length (n : Option U64) (t : Bool) :
    proxy.response_framing n t true = ok false := by cases n <;> simp [response_framing_eq]

def targetByte (b : U8) : Bool := decide (33 ≤ b.val ∧ b.val ≤ 126 ∧ b.val ≠ 35 ∧ b.val ≠ 92)
theorem target_loop_eq (p : Slice U8) (i : Usize) (_hi : i.val ≤ p.val.length) :
    proxy.target_bytes_loop p i = ok ((p.val.drop i.val).all targetByte) := by
  rw [proxy.target_bytes_loop]
  by_cases h : i < Slice.len p
  · have hlt : i.val < p.val.length := by simpa using h
    obtain ⟨j, hj, hv⟩ := succ_exists i (by have := p.property; omega)
    simp only [h, if_pos, index_eq p i hlt, bind_tc_ok, hj]
    rw [target_loop_eq p j (by omega), drop_head p.val i.val hlt]
    simp only [List.all_cons, hv]
    split_ifs <;> simp_all [targetByte,UScalar.eq_equiv]
  · have hge : p.val.length ≤ i.val := by simpa using h
    simp [h,List.drop_eq_nil_of_le hge]
termination_by p.val.length - i.val

theorem target_bytes_eq (p : Slice U8) : proxy.target_bytes p = ok (p.val.all targetByte) := by
  simpa using target_loop_eq p 0#usize (by simp)

def targetPolicy (xs : List U8) : Bool :=
  match xs with
  | [] => false
  | b :: rest => decide (xs.length ≤ 8192 ∧ b = 47#u8 ∧ (rest = [] ∨ rest.head? ≠ some 47#u8)) && xs.all targetByte

theorem target_eq (p : Slice U8) : proxy.target_allowed p = ok (targetPolicy p.val) := by
  cases hv : p.val with
  | nil => simp [proxy.target_allowed,core.slice.Slice.is_empty,hv,targetPolicy]
  | cons b rest =>
    have h0 : (0#usize).val < p.val.length := by simp [hv]
    simp only [proxy.target_allowed,core.slice.Slice.is_empty]
    rw [index_eq p 0#usize h0]
    cases rest with
    | nil =>
      simp [targetPolicy,target_bytes_eq,hv,UScalar.eq_equiv]
      split_ifs <;> simp_all
    | cons b1 tail =>
      have h1 : (1#usize).val < p.val.length := by simp [hv]
      simp [targetPolicy,target_bytes_eq,hv,UScalar.eq_equiv,index_eq p 1#usize h1]
      split_ifs <;> simp_all

def hopNames : List (List U8) := [
  [99#u8, 111#u8, 110#u8, 110#u8, 101#u8, 99#u8, 116#u8, 105#u8, 111#u8, 110#u8],
  [107#u8, 101#u8, 101#u8, 112#u8, 45#u8, 97#u8, 108#u8, 105#u8, 118#u8, 101#u8],
  [112#u8, 114#u8, 111#u8, 120#u8, 121#u8, 45#u8, 97#u8, 117#u8, 116#u8, 104#u8, 101#u8, 110#u8, 116#u8, 105#u8, 99#u8, 97#u8, 116#u8, 101#u8],
  [112#u8, 114#u8, 111#u8, 120#u8, 121#u8, 45#u8, 97#u8, 117#u8, 116#u8, 104#u8, 111#u8, 114#u8, 105#u8, 122#u8, 97#u8, 116#u8, 105#u8, 111#u8, 110#u8],
  [112#u8, 114#u8, 111#u8, 120#u8, 121#u8, 45#u8, 99#u8, 111#u8, 110#u8, 110#u8, 101#u8, 99#u8, 116#u8, 105#u8, 111#u8, 110#u8],
  [116#u8, 101#u8],
  [116#u8, 114#u8, 97#u8, 105#u8, 108#u8, 101#u8, 114#u8],
  [116#u8, 114#u8, 97#u8, 110#u8, 115#u8, 102#u8, 101#u8, 114#u8, 45#u8, 101#u8, 110#u8, 99#u8, 111#u8, 100#u8, 105#u8, 110#u8, 103#u8],
  [117#u8, 112#u8, 103#u8, 114#u8, 97#u8, 100#u8, 101#u8]
]
theorem hop_eq (n : Slice U8) : proxy.hop_header n = ok (decide (n.val ∈ hopNames)) := by
  simp [proxy.hop_header,same_path_eq,lift,Array.to_slice,Array.make,hopNames]
  split_ifs <;> simp_all
  by_cases h : n.val = [117#u8, 112#u8, 103#u8, 114#u8, 97#u8, 100#u8, 101#u8] <;> simp_all

def forwardingNames : List (List U8) := [
  [102#u8, 111#u8, 114#u8, 119#u8, 97#u8, 114#u8, 100#u8, 101#u8, 100#u8],
  [120#u8, 45#u8, 114#u8, 101#u8, 97#u8, 108#u8, 45#u8, 105#u8, 112#u8],
  [120#u8, 45#u8, 111#u8, 114#u8, 105#u8, 103#u8, 105#u8, 110#u8, 97#u8, 108#u8, 45#u8, 117#u8, 114#u8, 108#u8],
  [120#u8, 45#u8, 114#u8, 101#u8, 119#u8, 114#u8, 105#u8, 116#u8, 101#u8, 45#u8, 117#u8, 114#u8, 108#u8],
  [112#u8, 114#u8, 111#u8, 120#u8, 121#u8]
]
def forwardingPrefix : List U8 := [120#u8, 45#u8, 102#u8, 111#u8, 114#u8, 119#u8, 97#u8, 114#u8, 100#u8, 101#u8, 100#u8, 45#u8]
abbrev forwardingPolicy (xs : List U8) : Prop :=
  xs ∈ forwardingNames ∨ (12 ≤ xs.length ∧ xs.take 12 = forwardingPrefix)
theorem forwarding_eq (n : Slice U8) : proxy.forwarding_header n = ok (decide (forwardingPolicy n.val)) := by
  unfold proxy.forwarding_header
  by_cases hl : 12 ≤ n.val.length
  · rw [split_eq n 12#usize (by simpa using hl)]
    simp [same_path_eq,lift,Array.to_slice,Array.make,prefixSlice,suffixSlice,forwardingPolicy,forwardingNames,forwardingPrefix,hl]
    split_ifs <;> simp_all
    by_cases h : n.val.take 12 = [120#u8, 45#u8, 102#u8, 111#u8, 114#u8, 119#u8, 97#u8, 114#u8, 100#u8, 101#u8, 100#u8, 45#u8] <;> simp_all
  · simp [same_path_eq,lift,Array.to_slice,Array.make,forwardingPolicy,forwardingNames,forwardingPrefix,hl]
    split_ifs <;> simp_all

def hostName : List U8 := [104#u8, 111#u8, 115#u8, 116#u8]
def lengthName : List U8 := [99#u8, 111#u8, 110#u8, 116#u8, 101#u8, 110#u8, 116#u8, 45#u8, 108#u8, 101#u8, 110#u8, 103#u8, 116#u8, 104#u8]
def serverName : List U8 := [115#u8, 101#u8, 114#u8, 118#u8, 101#u8, 114#u8]
def altName : List U8 := [97#u8, 108#u8, 116#u8, 45#u8, 115#u8, 118#u8, 99#u8]
def hstsName : List U8 := [115#u8, 116#u8, 114#u8, 105#u8, 99#u8, 116#u8, 45#u8, 116#u8, 114#u8, 97#u8, 110#u8, 115#u8, 112#u8, 111#u8, 114#u8, 116#u8, 45#u8, 115#u8, 101#u8, 99#u8, 117#u8, 114#u8, 105#u8, 116#u8, 121#u8]
abbrev requestHeaderPolicy (n v : Slice U8) : Prop :=
  v.val.length ≤ 4096 ∧ v.val.all visibleByte = true ∧ n.val ∉ hopNames ∧ n.val ≠ hostName ∧ n.val ≠ lengthName ∧ ¬ forwardingPolicy n.val
abbrev responseHeaderPolicy (n v : Slice U8) (e : Bool) : Prop :=
  v.val.length ≤ 4096 ∧ v.val.all visibleByte = true ∧ n.val ∉ hopNames ∧ n.val ≠ lengthName ∧ n.val ≠ serverName ∧ n.val ≠ altName ∧ (e = true ∨ n.val ≠ hstsName)

theorem request_header_eq (n v : Slice U8) :
    proxy.request_header n v = ok (decide (requestHeaderPolicy n v)) := by
  simp [proxy.request_header,visible_eq,hop_eq,same_path_eq,forwarding_eq,lift,Array.to_slice,Array.make,requestHeaderPolicy,hostName,lengthName]
  split_ifs <;> simp_all

theorem response_header_eq (n v : Slice U8) (e : Bool) :
    proxy.response_header n v e = ok (decide (responseHeaderPolicy n v e)) := by
  simp [proxy.response_header,visible_eq,hop_eq,same_path_eq,lift,Array.to_slice,Array.make,responseHeaderPolicy,lengthName,serverName,altName,hstsName]
  split_ifs <;> simp_all
  by_cases h : n.val = hstsName <;> simp_all [hstsName]

theorem no_forwarded_identity (n v : Slice U8) (h : forwardingPolicy n.val) :
    proxy.request_header n v = ok false := by simp [request_header_eq,requestHeaderPolicy,h]

theorem no_hop_request (n v : Slice U8) (h : n.val ∈ hopNames) :
    proxy.request_header n v = ok false := by simp [request_header_eq,requestHeaderPolicy,h]

theorem no_hop_response (n v : Slice U8) (e : Bool) (h : n.val ∈ hopNames) :
    proxy.response_header n v e = ok false := by simp [response_header_eq,responseHeaderPolicy,h]

theorem no_unencrypted_hsts (n v : Slice U8) (h : n.val = hstsName) :
    proxy.response_header n v false = ok false := by simp [response_header_eq,responseHeaderPolicy,h]

theorem request_header_no_controls (n v : Slice U8) (h : proxy.request_header n v = ok true) :
    ∀ b ∈ v.val, 32 ≤ b.val ∧ b.val ≤ 126 := by
  have hp : requestHeaderPolicy n v := by
    rw [request_header_eq] at h
    injection h with hd
    exact of_decide_eq_true hd
  have hv := hp.2.1
  simpa [List.all_eq_true,visibleByte] using hv

theorem response_header_no_controls (n v : Slice U8) (e : Bool) (h : proxy.response_header n v e = ok true) :
    ∀ b ∈ v.val, 32 ≤ b.val ∧ b.val ≤ 126 := by
  have hp : responseHeaderPolicy n v e := by simpa [response_header_eq,responseHeaderPolicy] using h
  have hv := hp.2.1
  simpa [List.all_eq_true,visibleByte] using hv

theorem target_contract (p : Slice U8) :
    proxy.target_allowed p = ok true ↔ targetPolicy p.val = true := by rw [target_eq]; simp

theorem target_bounded (p : Slice U8) (h : proxy.target_allowed p = ok true) :
    p.val.length ≤ 8192 ∧ p.val.head? = some 47#u8 := by
  have hp := (target_contract p).mp h
  cases hv : p.val with
  | nil => simp [hv,targetPolicy] at hp
  | cons b rest =>
    simp [hv,targetPolicy] at hp
    simpa [hv] using And.intro hp.1 hp.2.1

theorem target_no_controls (p : Slice U8) (h : proxy.target_allowed p = ok true) :
    ∀ b ∈ p.val, 33 ≤ b.val ∧ b.val ≤ 126 ∧ b.val ≠ 35 ∧ b.val ≠ 92 := by
  have hp := (target_contract p).mp h
  cases hv : p.val with
  | nil => simp [hv,targetPolicy] at hp
  | cons b rest =>
    simp [hv,targetPolicy] at hp
    simpa [hv,targetByte] using And.intro hp.2.2.2.1 hp.2.2.2.2

theorem proxy_total (r p d x t e : Bool) (a n v : Slice U8) (port s : U16) (len : U64) (opt : Option U64) :
    (∃ b, proxy.site_mode_allowed r p d x = ok b) ∧
    (∃ b, proxy.endpoint_allowed a port = ok b) ∧
    (∃ b, proxy.method_allowed a = ok b) ∧
    (∃ b, proxy.status_allowed s = ok b) ∧
    (∃ b, proxy.request_framing len t d = ok b) ∧
    (∃ b, proxy.response_framing opt t d = ok b) ∧
    (∃ b, proxy.target_allowed a = ok b) ∧
    (∃ b, proxy.request_header n v = ok b) ∧
    (∃ b, proxy.response_header n v e = ok b) :=
  ⟨⟨_, mode_eq r p d x⟩, ⟨_, endpoint_eq a port⟩, ⟨_, method_eq a⟩, ⟨_, status_eq s⟩,
   ⟨_, request_framing_eq len t d⟩, ⟨_, response_framing_eq opt t d⟩, ⟨_, target_eq a⟩,
   ⟨_, request_header_eq n v⟩, ⟨_, response_header_eq n v e⟩⟩

end ProxyProofs
