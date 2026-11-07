import Generated.Pathward
open Aeneas Aeneas.Std RustM pathward
namespace AuthorityProofs

theorem sealed_resource_iff (c p e : Bool) :
    bootstrap.sealed_resource_allowed c p e = ok true ↔
    c = true ∧ p = true ∧ e = true := by
  cases c <;> cases p <;> cases e <;> simp [bootstrap.sealed_resource_allowed]
theorem noncanonical_resource_denied (p e : Bool) :
    bootstrap.sealed_resource_allowed false p e = ok false := rfl
theorem unpinned_authority_resource_denied (c e : Bool) :
    bootstrap.sealed_resource_allowed c false e = ok false := by cases c <;> rfl
theorem changed_authority_resource_denied (c p : Bool) :
    bootstrap.sealed_resource_allowed c p false = ok false := by cases c <;> cases p <;> rfl

theorem license_text_iff (t n e : Bool) :
    bootstrap.license_text_allowed t n e = ok true ↔ t = true ∧ n = true ∧ e = true := by
  cases t <;> cases n <;> cases e <;> simp [bootstrap.license_text_allowed]
theorem outside_license_tree_denied (n e : Bool) :
    bootstrap.license_text_allowed false n e = ok false := rfl
theorem unknown_license_text_name_denied (t e : Bool) :
    bootstrap.license_text_allowed t false e = ok false := by cases t <;> rfl
theorem non_text_license_exception_denied (t n : Bool) :
    bootstrap.license_text_allowed t n false = ok false := by cases t <;> cases n <;> rfl

end AuthorityProofs
