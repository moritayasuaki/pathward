import Generated.Pathward

open Aeneas Aeneas.Std RustM

namespace PathwardProofs

open pathward

def nameByte (b : U8) : Bool :=
  decide ((97 ≤ b.val ∧ b.val ≤ 122) ∨ (65 ≤ b.val ∧ b.val ≤ 90) ∨
    (48 ≤ b.val ∧ b.val ≤ 57) ∨ b.val = 95 ∨ b.val = 45 ∨ b.val = 43)

theorem name_byte_eq (b : U8) : name_byte b = ok (nameByte b) := by
  unfold name_byte
  split_ifs <;> simp_all [nameByte, UScalar.eq_equiv]
  all_goals apply Bool.eq_iff_iff.mpr; simp_all; omega

def next (s : State) (b : U8) : State :=
  match s with
  | .Start => if b = 47#u8 then .Root else .Reject
  | .Root | .Separator => if nameByte b then .Segment else .Reject
  | .Segment => if nameByte b then .Segment else if b = 46#u8 then .Dot
      else if b = 47#u8 then .Separator else .Reject
  | .Dot => if nameByte b then .Segment else if b = 46#u8 then .Dot else .Reject
  | .Reject => .Reject

def accepts : State → Bool
  | .Root | .Segment | .Separator => true
  | _ => false

def run (s : State) (bytes : List U8) : State := bytes.foldl next s

theorem step_eq (s : State) (b : U8) : step s b = ok (next s b) := by
  cases s <;> simp [step, next, name_byte_eq, State.Insts.CoreCmpPartialEqState.eq, State.read_discriminant] <;> split_ifs <;> rfl

theorem accepting_eq (s : State) : accepting s = ok (accepts s) := by
  cases s <;> rfl

theorem index_eq {α : Type} (xs : Slice α) (i : Usize) (h : i.val < xs.val.length) :
    Slice.index_usize xs i = ok xs.val[i.val] := by
  simp [Slice.index_usize, List.getElem?_eq_getElem h]

theorem succ_exists (i : Usize) (h : i.val < Usize.max) :
    ∃ j, (i + 1#usize : RustM Usize) = ok j ∧ j.val = i.val + 1 := by
  obtain ⟨j, hj, hv, _⟩ := WP.spec_imp_exists
    (Usize.add_bv_spec (x := i) (y := 1#usize) (by scalar_tac))
  exact ⟨j, hj, by simpa using hv⟩

theorem drop_head {α : Type} (xs : List α) (i : Nat) (h : i < xs.length) :
    xs.drop i = xs[i] :: xs.drop (i + 1) := by
  exact List.drop_eq_getElem_cons h

theorem valid_loop_eq (p : Slice U8) (s : State) (i : Usize)
    (_hi : i.val ≤ p.val.length) :
    valid_path_loop p s i = ok (run s (p.val.drop i.val)) := by
  rw [valid_path_loop]
  by_cases h : i < Slice.len p
  · have hlt : i.val < p.val.length := by simpa using h
    obtain ⟨j, hj, hv⟩ := succ_exists i (by have := p.property; omega)
    simp only [h, if_pos, index_eq p i hlt, step_eq, bind_tc_ok, hj]
    rw [valid_loop_eq p (next s p.val[i.val]) j (by omega)]
    rw [drop_head p.val i.val hlt]
    simp only [run, List.foldl_cons, hv]
  · have hge : p.val.length ≤ i.val := by simpa using h
    simp [h, run, List.drop_eq_nil_of_le hge]
termination_by p.val.length - i.val

def canonical (bytes : List U8) : Bool :=
  decide (bytes.length ≤ 4096) && accepts (run .Start bytes)

theorem valid_path_eq (p : Slice U8) : valid_path p = ok (canonical p.val) := by
  unfold valid_path
  rw [valid_loop_eq p .Start 0#usize (by simp)]
  simp [canonical, accepting_eq]
  split_ifs <;> simp_all

theorem same_loop_eq (p q : Slice U8) (i : Usize)
    (hlen : p.val.length = q.val.length) (_hi : i.val ≤ p.val.length) :
    same_path_loop p q i = ok (p.val.drop i.val == q.val.drop i.val) := by
  rw [same_path_loop]
  by_cases h : i < Slice.len p
  · have hp : i.val < p.val.length := by simpa using h
    have hq : i.val < q.val.length := by omega
    obtain ⟨j, hj, hv⟩ := succ_exists i (by have := p.property; omega)
    simp only [h, if_pos, index_eq p i hp, index_eq q i hq, bind_tc_ok]
    rw [drop_head p.val i.val hp, drop_head q.val i.val hq]
    by_cases heq : p.val[i.val] = q.val[i.val]
    · simp only [heq, bne_self_eq_false, Bool.false_eq_true, if_false, hj, bind_tc_ok]
      rw [same_loop_eq p q j hlen (by omega)]
      simp only [hv, List.cons_beq_cons, beq_self_eq_true, Bool.true_and]
    · simp only [bne_iff_ne, List.cons_beq_cons, beq_eq_false_iff_ne.mpr heq, Bool.false_and]
      rw [if_pos heq]
  · have hp : p.val.length ≤ i.val := by simpa using h
    have hq : q.val.length ≤ i.val := by omega
    simp [h, List.drop_eq_nil_of_le hp, List.drop_eq_nil_of_le hq]
termination_by p.val.length - i.val

theorem same_path_eq (p q : Slice U8) : same_path p q = ok (p.val == q.val) := by
  unfold same_path
  by_cases h : p.val.length = q.val.length
  · simp [h, same_loop_eq p q 0#usize h (by simp)]
  · have hne : p.val ≠ q.val := by intro he; exact h (congrArg List.length he)
    simp [h, hne]

theorem listed_eq (p : Slice U8) (pub : Slice (Slice U8)) (i : Usize)
    (_hi : i.val ≤ pub.val.length) :
    listed p pub i = ok ((pub.val.drop i.val).any (fun entry => p.val == entry.val)) := by
  rw [listed]
  by_cases h : i < Slice.len pub
  · have hlt : i.val < pub.val.length := by simpa using h
    obtain ⟨j, hj, hv⟩ := succ_exists i (by have := pub.property; omega)
    simp only [h, if_pos, index_eq pub i hlt, same_path_eq, bind_tc_ok]
    rw [drop_head pub.val i.val hlt]
    by_cases heq : p.val == pub.val[i.val].val
    · simp only [heq, if_true, List.any_cons, Bool.true_or]
    · simp only [heq, Bool.false_eq_true, if_false, hj, bind_tc_ok]
      rw [listed_eq p pub j (by omega)]
      simp only [List.any_cons, Bool.eq_false_of_not_eq_true heq, Bool.false_or, hv]
  · have hge : pub.val.length ≤ i.val := by simpa using h
    simp [h, List.drop_eq_nil_of_le hge]
termination_by pub.val.length - i.val

theorem is_public_eq (p : Slice U8) (pub : Slice (Slice U8)) :
    is_public p pub = ok (decide (pub.val.length ≤ 4096) && canonical p.val &&
      pub.val.any (fun entry => p.val == entry.val)) := by
  unfold is_public
  rw [valid_path_eq, listed_eq p pub 0#usize (by simp)]
  simp
  split_ifs <;> simp_all

/-- Complete authorization contract, including both positive and negative cases. -/
theorem authorization_iff (p : Slice U8) (pub : Slice (Slice U8)) :
    is_public p pub = ok true ↔ pub.val.length ≤ 4096 ∧ canonical p.val = true ∧
      ∃ entry ∈ pub.val, p.val = entry.val := by
  rw [is_public_eq]
  simp [Bool.and_assoc]

/-- Equality with `ok` proves termination and absence of modeled Rust panics. -/
theorem authorization_total (p : Slice U8) (pub : Slice (Slice U8)) :
    ∃ decision, is_public p pub = ok decision := by
  exact ⟨_, is_public_eq p pub⟩

theorem deny_unlisted (p : Slice U8) (pub : Slice (Slice U8))
    (h : ∀ entry ∈ pub.val, p.val ≠ entry.val) : is_public p pub = ok false := by
  rw [is_public_eq]
  have hn : pub.val.any (fun entry => p.val == entry.val) = false := by
    simpa using h
  simp [hn]

theorem deny_invalid (p : Slice U8) (pub : Slice (Slice U8))
    (h : canonical p.val = false) : is_public p pub = ok false := by
  simp [is_public_eq, h]

@[simp] theorem run_nil (s : State) : run s [] = s := rfl
@[simp] theorem run_cons (s : State) (b : U8) (xs : List U8) :
    run s (b :: xs) = run (next s b) xs := rfl

theorem run_append (s : State) (xs ys : List U8) :
    run s (xs ++ ys) = run (run s xs) ys := by
  simp only [run, List.foldl_append]

@[simp] theorem run_reject (xs : List U8) : run .Reject xs = .Reject := by
  induction xs with
  | nil => rfl
  | cons b xs ih => simpa [next] using ih

def allowedByte (b : U8) : Bool := nameByte b || b == 46#u8 || b == 47#u8

theorem disallowed_rejects (s : State) (b : U8) (h : allowedByte b = false) :
    next s b = .Reject := by
  simp only [allowedByte, Bool.or_eq_false_iff, beq_eq_false_iff_ne] at h
  rcases h with ⟨⟨hn, hd⟩, hs⟩
  cases s <;> simp [next, hn, hd, hs]

theorem run_all_allowed (s : State) (xs : List U8)
    (h : accepts (run s xs) = true) : ∀ b ∈ xs, allowedByte b = true := by
  induction xs generalizing s with
  | nil => simp
  | cons b xs ih =>
    have hb : allowedByte b = true := by
      by_contra hn
      have hf : allowedByte b = false := Bool.eq_false_of_not_eq_true hn
      simp [disallowed_rejects s b hf, accepts] at h
    have ht := ih (next s b) (by simpa using h)
    simp only [List.mem_cons, forall_eq_or_imp]
    exact ⟨hb, ht⟩

theorem canonical_all_allowed (xs : List U8) (h : canonical xs = true) :
    ∀ b ∈ xs, allowedByte b = true := by
  simp only [canonical, Bool.and_eq_true_iff, decide_eq_true_eq] at h
  exact run_all_allowed .Start xs h.2

theorem canonical_rooted (xs : List U8) (h : canonical xs = true) :
    ∃ rest, xs = 47#u8 :: rest := by
  cases xs with
  | nil => simp [canonical, accepts] at h
  | cons b xs =>
    by_cases hb : b = 47#u8
    · exact ⟨xs, by rw [hb]⟩
    · simp [canonical, next, hb, accepts] at h

theorem slash_dot_rejects (s : State) : next (next s 47#u8) 46#u8 = .Reject := by
  cases s <;> rfl

theorem double_slash_rejects (s : State) : next (next s 47#u8) 47#u8 = .Reject := by
  cases s <;> rfl

/-- Covers dotfiles, `/.`, and `/..` at every component boundary. -/
theorem no_hidden_or_traversal (before after : List U8) :
    canonical (before ++ 47#u8 :: 46#u8 :: after) = false := by
  simp [canonical, run_append, slash_dot_rejects, accepts]

theorem no_empty_component (before after : List U8) :
    canonical (before ++ 47#u8 :: 47#u8 :: after) = false := by
  simp [canonical, run_append, double_slash_rejects, accepts]

theorem no_trailing_dot (before : List U8) : canonical (before ++ [46#u8]) = false := by
  simp only [canonical, run_append, run_cons, run_nil]
  generalize run State.Start before = s
  cases s <;> simp [next, nameByte, accepts]

theorem allowed_ascii (b : U8) (h : allowedByte b = true) :
    33 ≤ b.val ∧ b.val ≤ 126 ∧ b.val ≠ 37 ∧ b.val ≠ 92 ∧
      b.val ≠ 63 ∧ b.val ≠ 35 := by
  simp [allowedByte, nameByte, UScalar.eq_equiv] at h
  omega

/-- No percent escapes, backslashes, controls, non-ASCII, query or fragment bytes. -/
theorem published_bytes_safe (p : Slice U8) (pub : Slice (Slice U8))
    (h : is_public p pub = ok true) (b : U8) (hb : b ∈ p.val) :
    33 ≤ b.val ∧ b.val ≤ 126 ∧ b.val ≠ 37 ∧ b.val ≠ 92 ∧
      b.val ≠ 63 ∧ b.val ≠ 35 := by
  exact allowed_ascii b (canonical_all_allowed p.val ((authorization_iff p pub).mp h).2.1 b hb)

theorem published_rooted (p : Slice U8) (pub : Slice (Slice U8))
    (h : is_public p pub = ok true) : ∃ rest, p.val = 47#u8 :: rest := by
  exact canonical_rooted p.val ((authorization_iff p pub).mp h).2.1

theorem published_no_traversal (p : Slice U8) (pub : Slice (Slice U8))
    (h : is_public p pub = ok true) :
    ∀ before after, p.val ≠ before ++ 47#u8 :: 46#u8 :: after := by
  intro before after heq
  have hc := ((authorization_iff p pub).mp h).2.1
  rw [heq, no_hidden_or_traversal] at hc
  contradiction

theorem next_not_start (s : State) (b : U8) : next s b ≠ .Start := by
  cases s <;> simp [next] <;> split_ifs <;> simp_all

theorem run_not_start (xs : List U8) (s : State) (h : s ≠ .Start) : run s xs ≠ .Start := by
  induction xs generalizing s with
  | nil => exact h
  | cons b xs ih => exact ih (next s b) (next_not_start s b)

theorem directory_suffix_allowed (xs : List U8)
    (h : run .Start xs = .Segment) (bound : xs.length < 4096) :
    canonical (xs ++ [47#u8]) = true := by
  simp [canonical, run_append, h, next, nameByte, accepts]
  omega

end PathwardProofs
