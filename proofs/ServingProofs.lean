import RulesProofs

open Aeneas Aeneas.Std RustM
open pathward PathwardProofs RulesProofs

namespace ServingProofs

def pathCount : List U8 → Nat
  | [] => 0
  | b :: rest => if b = 63#u8 then 0 else 1 + pathCount rest

theorem pathCount_le (xs : List U8) : pathCount xs ≤ xs.length := by
  induction xs with
  | nil => simp [pathCount]
  | cons b rest ih => simp only [pathCount, List.length_cons]; split_ifs <;> omega

theorem path_loop_spec (p : Slice U8) (i : Usize) (hi : i.val ≤ p.val.length) :
    ∃ n, serving.path_length_loop p i = ok n ∧
      n.val = i.val + pathCount (p.val.drop i.val) ∧ n.val ≤ p.val.length := by
  rw [serving.path_length_loop]
  by_cases h : i < Slice.len p
  · have hlt : i.val < p.val.length := by simpa using h
    simp only [h, if_pos, index_eq p i hlt, bind_tc_ok]
    by_cases he : p.val[i.val] = 63#u8
    · refine ⟨i, by simp [he], ?_, hi⟩
      rw [drop_head p.val i.val hlt]
      simp [pathCount, he]
    · simp only [he, if_false]
      obtain ⟨j, hj, hv⟩ := succ_exists i (by have := p.property; omega)
      rw [hj]
      simp only [bind_tc_ok]
      obtain ⟨n, hn, hnval, hnle⟩ := path_loop_spec p j (by omega)
      refine ⟨n, hn, ?_, hnle⟩
      have hc : pathCount (p.val.drop i.val) =
          1 + pathCount (p.val.drop (i.val + 1)) := by
        rw [drop_head p.val i.val hlt]
        simp only [pathCount, he, if_false]
      rw [hv] at hnval
      omega
  · have hge : p.val.length ≤ i.val := by simpa using h
    simp [h, List.drop_eq_nil_of_le hge, pathCount]
    omega
termination_by p.val.length - i.val

theorem path_length_spec (p : Slice U8) :
    ∃ n, serving.path_length p = ok n ∧ n.val = pathCount p.val ∧ n.val ≤ p.val.length := by
  simpa using path_loop_spec p 0#usize (by simp)

def queryByte (b : U8) : Bool := decide (33 ≤ b.val ∧ b.val ≤ 126 ∧ b.val ≠ 35)

theorem query_loop_eq (p : Slice U8) (i : Usize) (_hi : i.val ≤ p.val.length) :
    serving.query_bytes_loop p i = ok ((p.val.drop i.val).all queryByte) := by
  rw [serving.query_bytes_loop]
  by_cases h : i < Slice.len p
  · have hlt : i.val < p.val.length := by simpa using h
    obtain ⟨j, hj, hv⟩ := succ_exists i (by have := p.property; omega)
    simp only [h, if_pos, index_eq p i hlt, bind_tc_ok, hj]
    rw [query_loop_eq p j (by omega), drop_head p.val i.val hlt]
    simp only [List.all_cons, hv]
    split_ifs <;> simp_all [queryByte, UScalar.eq_equiv]
  · have hge : p.val.length ≤ i.val := by simpa using h
    simp [h, List.drop_eq_nil_of_le hge]
termination_by p.val.length - i.val

theorem query_bytes_eq (p : Slice U8) :
    serving.query_bytes p = ok (p.val.all queryByte) := by
  simpa using query_loop_eq p 0#usize (by simp)

def pathPart (p : Slice U8) : Slice U8 :=
  ⟨p.val.take (pathCount p.val), by have := p.property; simp; omega⟩

def queryPart (p : Slice U8) : Slice U8 :=
  ⟨p.val.drop (pathCount p.val), by have := p.property; simp; omega⟩

theorem split_parts (p : Slice U8) (n : Usize) (hn : n.val = pathCount p.val) :
    core.slice.Slice.split_at p n = ok (pathPart p, queryPart p) := by
  have h : n ≤ p.length := by have := pathCount_le p.val; simpa [hn] using this
  simp [core.slice.Slice.split_at, pathPart, queryPart, List.splitAt_eq, hn, pathCount_le]

def requestSpec (p : Slice U8) : Option (Slice U8) :=
  if p.val.length ≤ 8192 ∧ canonical (pathPart p).val = true ∧
      (queryPart p).val.all queryByte = true then some (pathPart p) else none

theorem request_path_eq (p : Slice U8) : serving.request_path p = ok (requestSpec p) := by
  obtain ⟨n, hn, hnval, _⟩ := path_length_spec p
  unfold serving.request_path
  simp only [hn, bind_tc_ok, split_parts p n hnval, valid_path_eq, query_bytes_eq]
  simp [requestSpec]
  split_ifs <;> simp_all
  all_goals omega

theorem request_path_contract (p out : Slice U8) :
    serving.request_path p = ok (some out) ↔
      out = pathPart p ∧ p.val.length ≤ 8192 ∧ canonical out.val = true ∧
      (queryPart p).val.all queryByte = true := by
  rw [request_path_eq]
  unfold requestSpec
  split_ifs <;> simp_all
  aesop

theorem request_path_total (p : Slice U8) :
    ∃ result, serving.request_path p = ok result := ⟨_, request_path_eq p⟩

/-- The path is a literal prefix of the input bytes, ending at the first '?'. -/
theorem request_path_unchanged (p out : Slice U8)
    (h : serving.request_path p = ok (some out)) :
    out.val = p.val.take (pathCount p.val) ∧ ∃ rest, p.val = out.val ++ rest := by
  have he := ((request_path_contract p out).mp h).1
  subst out
  refine ⟨rfl, p.val.drop (pathCount p.val), ?_⟩
  simp [pathPart]

def getBytes : List U8 := [71#u8, 69#u8, 84#u8]
def headBytes : List U8 := [72#u8, 69#u8, 65#u8, 68#u8]

def lookupResult (p : Slice U8) (rs : Slice rules.Publication) : Option (Slice U8) :=
  if rs.val.length ≤ 4096 ∧ canonical p.val = true then lookupSpec p.val rs.val else none

def grantResult (send : Bool) (t : Slice U8) (rs : Slice rules.Publication) : Option serving.Grant := do
  let p ← requestSpec t
  let file ← lookupResult p rs
  some ⟨file, send⟩

def authorizeResult (m h c t : Slice U8) (rs : Slice rules.Publication) : Option serving.Grant :=
  if m.val = getBytes then
    if h.val = c.val then grantResult true t rs else none
  else if m.val = headBytes then
    if h.val = c.val then grantResult false t rs else none
  else none

theorem authorize_eq (m h c t : Slice U8) (rs : Slice rules.Publication) :
    serving.authorize m h c t rs = ok (authorizeResult m h c t rs) := by
  unfold serving.authorize
  simp [lift, Array.to_slice, Array.make, same_path_eq, request_path_eq, lookup_eq,
    authorizeResult, grantResult, lookupResult, getBytes, headBytes]
  split_ifs <;> try (split <;> simp_all)
  all_goals try (split <;> simp_all)
  all_goals rfl

theorem authorize_total (m h c t : Slice U8) (rs : Slice rules.Publication) :
    ∃ result, serving.authorize m h c t rs = ok result := ⟨_, authorize_eq m h c t rs⟩

theorem authorize_contract (m h c t : Slice U8) (rs : Slice rules.Publication) (g : serving.Grant) :
    serving.authorize m h c t rs = ok (some g) ↔
      (m.val = getBytes ∨ m.val = headBytes) ∧ h.val = c.val ∧
      g.send_body = (m.val == getBytes) ∧
      ∃ p, serving.request_path t = ok (some p) ∧ rules.lookup p rs = ok (some g.target) := by
  rw [authorize_eq]
  simp only [request_path_eq, lookup_eq]
  unfold authorizeResult grantResult
  cases hp : requestSpec t <;> simp [hp, lookupResult] at *
  all_goals split_ifs <;> simp_all [getBytes, headBytes]
  all_goals (cases g; simp_all [Option.bind_eq_some_iff]; aesop)

theorem deny_wrong_host (m h c t : Slice U8) (rs : Slice rules.Publication)
    (hne : h.val ≠ c.val) : serving.authorize m h c t rs = ok none := by
  simp [authorize_eq, authorizeResult, hne]

theorem deny_wrong_method (m h c t : Slice U8) (rs : Slice rules.Publication)
    (hg : m.val ≠ getBytes) (hh : m.val ≠ headBytes) :
    serving.authorize m h c t rs = ok none := by
  simp [authorize_eq, authorizeResult, hg, hh]

theorem head_has_no_body (m h c t : Slice U8) (rs : Slice rules.Publication) (g : serving.Grant)
    (hm : m.val = headBytes) (hg : serving.authorize m h c t rs = ok (some g)) :
    g.send_body = false := by
  have hc := (authorize_contract m h c t rs g).mp hg
  simpa [hm, headBytes, getBytes] using hc.2.2.1

theorem granted_target_safe (m h c t : Slice U8) (rs : Slice rules.Publication) (g : serving.Grant)
    (hg : serving.authorize m h c t rs = ok (some g)) :
    targetCanonical g.target.val = true ∧
      ∃ p, serving.request_path t = ok (some p) ∧
        canonical p.val = true ∧ ∃ r ∈ rs.val, p.val = r.path.val ∧ r.target = g.target := by
  obtain ⟨_, _, _, p, hp, hl⟩ := (authorize_contract m h c t rs g).mp hg
  have hs := lookup_safe p g.target rs hl
  exact ⟨hs.2.1, p, hp, hs.1, hs.2.2⟩

abbrev filePolicy (p o : serving.FileFacts) : Prop :=
  p.regular = true ∧ o.regular = true ∧ p.links = 1#u64 ∧ o.links = 1#u64 ∧
  p.size.val ≤ 1073741824 ∧ o.size.val ≤ 1073741824 ∧
  p.device = o.device ∧ p.inode = o.inode ∧ p.size = o.size

theorem file_allowed_eq (p o : serving.FileFacts) :
    serving.file_allowed p o = ok (decide (filePolicy p o)) := by
  have hc : serving.MAX_FILE_BYTES = ok 1073741824#u64 := by
    unfold serving.MAX_FILE_BYTES
    rfl
  unfold serving.file_allowed
  simp [hc, filePolicy]
  split_ifs <;> simp_all

theorem file_allowed_contract (p o : serving.FileFacts) :
    serving.file_allowed p o = ok true ↔ filePolicy p o := by
  simp [file_allowed_eq]

theorem file_allowed_total (p o : serving.FileFacts) :
    ∃ result, serving.file_allowed p o = ok result := ⟨_, file_allowed_eq p o⟩

theorem file_identity_preserved (p o : serving.FileFacts)
    (h : serving.file_allowed p o = ok true) :
    p.device = o.device ∧ p.inode = o.inode ∧ p.size = o.size := by
  have hp := (file_allowed_contract p o).mp h
  exact hp.2.2.2.2.2.2

end ServingProofs
