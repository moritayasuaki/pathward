import CutoverProofs
open Aeneas Aeneas.Std RustM pathward
namespace RecoveryProofs
open recovery

theorem new_iff (p r c t n o : Bool) :
    select p r c t n o = ok Selection.New ↔
      p = true ∧ r = true ∧ c = true ∧ t = true ∧ n = true := by
  cases p <;> cases r <;> cases c <;> cases t <;> cases n <;> cases o <;> simp [select]

theorem old_iff (p r c t n o : Bool) :
    select p r c t n o = ok Selection.Old ↔
      p = true ∧ o = true ∧ ¬(r = true ∧ c = true ∧ t = true ∧ n = true) := by
  cases p <;> cases r <;> cases c <;> cases t <;> cases n <;> cases o <;> simp [select]

theorem invalid_plan_holds (r c t n o : Bool) :
    select false r c t n o = ok Selection.Hold := rfl

theorem torn_record_uses_old (c t n : Bool) :
    select true false c t n true = ok Selection.Old := rfl

theorem pending_record_uses_old (r t n : Bool) :
    select true r false t n true = ok Selection.Old := by cases r <;> rfl

theorem stale_commit_uses_old (r c n : Bool) :
    select true r c false n true = ok Selection.Old := by cases r <;> cases c <;> rfl

theorem invalid_candidate_uses_old (r c t : Bool) :
    select true r c t false true = ok Selection.Old := by cases r <;> cases c <;> cases t <;> rfl

theorem neither_verified_holds (p r c t : Bool) :
    select p r c t false false = ok Selection.Hold := by cases p <;> cases r <;> cases c <;> cases t <;> rfl

theorem new_requires_bound_commit (p r c t n o : Bool)
    (h : select p r c t n o = ok Selection.New) :
    p = true ∧ r = true ∧ c = true ∧ t = true ∧ n = true := (new_iff ..).mp h

theorem old_requires_verified_plan (p r c t n o : Bool)
    (h : select p r c t n o = ok Selection.Old) : p = true ∧ o = true := by
  have g := (old_iff ..).mp h
  exact ⟨g.1, g.2.1⟩

theorem verified_old_has_selection (r c t n : Bool) :
    select true r c t n true = ok Selection.Old ∨ select true r c t n true = ok Selection.New := by
  cases r <;> cases c <;> cases t <;> cases n <;> simp [select]

theorem start_iff (chosen requested : Selection) (boot plan : Bool) :
    start_allowed chosen requested boot plan = ok true ↔
      boot = true ∧ plan = true ∧ chosen ≠ Selection.Hold ∧ chosen = requested := by
  cases chosen <;> cases requested <;> cases boot <;> cases plan <;>
    simp [start_allowed, core.cmp.PartialEq.ne.trait_default, core.cmp.PartialEq.ne.default,
      Selection.Insts.CoreCmpPartialEqSelection.eq, Selection.read_discriminant]

theorem mutually_exclusive_start (chosen : Selection) (boot plan : Bool)
    (old : start_allowed chosen Selection.Old boot plan = ok true) :
    start_allowed chosen Selection.New boot plan ≠ ok true := by
  have h := (start_iff ..).mp old
  intro other
  have g := (start_iff ..).mp other
  cases h.2.2.2.symm.trans g.2.2.2

theorem previous_boot_permit_denied (chosen requested : Selection) (plan : Bool) :
    start_allowed chosen requested false plan = ok false := rfl

theorem previous_plan_permit_denied (chosen requested : Selection) (boot : Bool) :
    start_allowed chosen requested boot false = ok false := by cases boot <;> rfl

theorem stop_requires_durable_guard (plan guard old : Bool)
    (h : stop_old_allowed plan guard old = ok true) : plan = true ∧ guard = true ∧ old = true := by
  cases plan <;> cases guard <;> cases old <;> simp_all [stop_old_allowed]

theorem trial_cannot_survive_reboot (plan timer : Bool) (elapsed : U64) :
    trial_allowed false plan timer elapsed = ok false := rfl

theorem trial_cannot_extend_deadline (boot plan timer : Bool) (elapsed : U64)
    (h : 900000000000 ≤ elapsed.val) : trial_allowed boot plan timer elapsed = ok false := by
  cases boot <;> cases plan <;> cases timer <;> simp [trial_allowed, Nat.not_lt.mpr h]

theorem fallback_requires_verified_failure (selected boot plan failed old : Bool)
    (h : fallback_allowed selected boot plan failed old = ok true) :
    selected = true ∧ boot = true ∧ plan = true ∧ failed = true ∧ old = true := by
  cases selected <;> cases boot <;> cases plan <;> cases failed <;> cases old <;>
    simp_all [fallback_allowed]

/-- Storage model. `invalid` represents a missing/torn/checksum-invalid record.
The classification and fsync/rename semantics are premises, not filesystem proofs. -/
inductive Record | pending | committed | stale | invalid
  deriving DecidableEq

def bootChoice (record : Record) (newValid : Bool) : RustM Selection :=
  select true (decide (record ≠ .invalid)) (decide (record = .committed ∨ record = .stale))
    (decide (record ≠ .stale)) newValid true

structure Disk where
  durable : Record
  visible : Record
  temporary : Record
  fileSynced : Bool

def stage (disk : Disk) (value : Record) : Disk :=
  {disk with temporary := value, fileSynced := false}
def syncFile (disk : Disk) : Disk := {disk with fileSynced := true}
def rename (disk : Disk) : Disk :=
  if disk.fileSynced then {disk with visible := disk.temporary} else disk
def syncDirectory (disk : Disk) : Disk := {disk with durable := disk.visible}

/-- An unsynced directory can recover its prior or renamed name. Media damage
may instead make the record invalid. The independent sealed plan is retained. -/
def CrashOutcome (disk : Disk) (recovered : Record) : Prop :=
  recovered = disk.durable ∨ recovered = disk.visible ∨ recovered = .invalid

theorem boot_choice_new_iff (record : Record) (newValid : Bool) :
    bootChoice record newValid = ok Selection.New ↔ record = .committed ∧ newValid = true := by
  cases record <;> cases newValid <;> simp [bootChoice, select]

theorem boot_choice_old_unless_checked_commit (record : Record) (newValid : Bool)
    (notCommitted : record ≠ .committed) : bootChoice record newValid = ok Selection.Old := by
  cases record <;> simp_all [bootChoice, select]

theorem temporary_never_becomes_recovery_record (disk : Disk) (value recovered : Record) :
    CrashOutcome (stage disk value) recovered ↔ CrashOutcome disk recovered := by rfl

theorem file_sync_alone_never_promotes (disk : Disk) (recovered : Record) :
    CrashOutcome (syncFile disk) recovered ↔ CrashOutcome disk recovered := by rfl

theorem unsynced_temporary_cannot_rename (disk : Disk) (value : Record) :
    rename (stage disk value) = stage disk value := by simp [rename, stage]

theorem no_committed_name_no_promotion (disk : Disk) (recovered : Record) (newValid : Bool)
    (crash : CrashOutcome disk recovered) (old : disk.durable ≠ .committed)
    (visible : disk.visible ≠ .committed) : bootChoice recovered newValid = ok Selection.Old := by
  apply boot_choice_old_unless_checked_commit
  rcases crash with h | h | h <;> simp_all

theorem renamed_commit_recovers_only_verified_target (disk : Disk) (recovered : Record)
    (newValid : Bool) (crash : CrashOutcome disk recovered)
    (selected : bootChoice recovered newValid = ok Selection.New) :
    recovered = .committed ∧ newValid = true ∧
      (disk.durable = .committed ∨ disk.visible = .committed) := by
  have h := (boot_choice_new_iff ..).mp selected
  rcases crash with old | visible | invalid
  · exact ⟨h.1, h.2, Or.inl (old ▸ h.1)⟩
  · exact ⟨h.1, h.2, Or.inr (visible ▸ h.1)⟩
  · simp_all

theorem directory_sync_agrees_on_committed_record (disk : Disk)
    (committed : disk.visible = .committed) :
    (syncDirectory disk).durable = .committed ∧ (syncDirectory disk).visible = .committed := by
  simp [syncDirectory, committed]

theorem torn_record_falls_back_after_any_write (newValid : Bool) :
    bootChoice .invalid newValid = ok Selection.Old := rfl

end RecoveryProofs
