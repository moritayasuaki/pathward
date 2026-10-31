import TlsProofs
open Aeneas Aeneas.Std RustM
open pathward
namespace RuntimeProofs

abbrev commitPolicy (c e : U64) (p i s d : Bool) : Prop :=
  p = true ∧ i = true ∧ s = true ∧ d = false ∧ c = e ∧ c.val < 18446744073709551615

theorem commit_contract (c e : U64) (p i s d : Bool) :
    ∃ next, runtime.commit_generation c e p i s d = ok next ∧
      next.val = if commitPolicy c e p i s d then c.val + 1 else c.val := by
  unfold runtime.commit_generation
  by_cases hp : p = true <;> by_cases hi : i = true <;>
    by_cases hs : s = true <;> by_cases hd : d = true <;>
    by_cases he : c = e <;> by_cases hm : c.val < 18446744073709551615
  all_goals simp_all [commitPolicy, core.num.U64.MAX, U64.rMax]
  · obtain ⟨v, hv, hvv, _⟩ := WP.spec_imp_exists (U64.add_bv_spec (x := e) (y := 1#u64) (by scalar_tac))
    exact ⟨v, hv, by simpa using hvv⟩
  · have hn : ¬ e.val < 18446744073709551615 := by omega
    exact ⟨e, by simp [hn], by simp [hn]⟩

theorem commit_total (c e : U64) (p i s d : Bool) :
    ∃ next, runtime.commit_generation c e p i s d = ok next := by
  obtain ⟨n, hn, _⟩ := commit_contract c e p i s d
  exact ⟨n, hn⟩

theorem failed_retains (c e : U64) (p i s d : Bool)
    (h : ¬ commitPolicy c e p i s d) : runtime.commit_generation c e p i s d = ok c := by
  obtain ⟨n, hn, hv⟩ := commit_contract c e p i s d
  have he : n = c := by apply UScalar.eq_of_val_eq; simpa [h] using hv
  simpa [he] using hn

theorem draining_retains (c e : U64) (p i s : Bool) :
    runtime.commit_generation c e p i s true = ok c := by
  apply failed_retains; simp [commitPolicy]

theorem stale_retains (c e : U64) (p i s d : Bool) (h : c ≠ e) :
    runtime.commit_generation c e p i s d = ok c := by
  apply failed_retains; simp [commitPolicy, h]

theorem identity_mismatch_retains (c e : U64) (p s d : Bool) :
    runtime.commit_generation c e p false s d = ok c := by
  apply failed_retains; simp [commitPolicy]

theorem unsafe_storage_retains (c e : U64) (p i d : Bool) :
    runtime.commit_generation c e p i false d = ok c := by
  apply failed_retains; simp [commitPolicy]

theorem unprepared_retains (c e : U64) (i s d : Bool) :
    runtime.commit_generation c e false i s d = ok c := by
  apply failed_retains; simp [commitPolicy]

theorem exhausted_retains (e : U64) (p i s d : Bool) :
    runtime.commit_generation 18446744073709551615#u64 e p i s d = ok 18446744073709551615#u64 := by
  apply failed_retains; simp [commitPolicy]

theorem ready_eq (d s t c : Bool) :
    runtime.ready d s t c = ok (decide (d = false ∧ s = true ∧ (t = false ∨ c = true))) := by
  cases d <;> cases s <;> cases t <;> cases c <;> rfl

theorem ready_contract (d s t c : Bool) :
    runtime.ready d s t c = ok true ↔ d = false ∧ s = true ∧ (t = false ∨ c = true) := by
  simp [ready_eq]

theorem no_ready_while_draining (s t c : Bool) : runtime.ready true s t c = ok false := by
  simp [ready_eq]

theorem no_ready_without_tls_certificate (d s : Bool) : runtime.ready d s true false = ok false := by
  simp [ready_eq]

end RuntimeProofs
