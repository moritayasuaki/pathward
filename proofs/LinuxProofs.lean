import PlatformProofs
import Generated.GuardPaths

open Aeneas Aeneas.Std RustM pathward
namespace LinuxProofs

/- The emitted paths include normal returns and unwinds. A guard in an
   unsuccessful PoisonError is disposed of by the pinned standard library.
   This automaton tracks the two guards acquired by the caller. -/
inductive Held where | neither | generation | both

def scopeValid : Held → Bool → List PoolMir.Event → Bool
  | .neither, _, [.returned] | .neither, _, [.unwind] => true
  | .neither, false, .takeGeneration :: tail => scopeValid .generation false tail
  | .generation, false, .takeHealth :: tail => scopeValid .both false tail
  | .both, false, .invoke :: tail => scopeValid .both true tail
  | .both, called, .dropHealth :: tail => scopeValid .generation called tail
  | .generation, called, .dropGeneration :: tail => scopeValid .neither called tail
  | _, _, _ => false

theorem all_emitted_guard_paths_are_scoped (p : List PoolMir.Event) (member : p ∈ PoolMir.paths) :
    scopeValid .neither false p = true := by
  have checked : PoolMir.paths.all (scopeValid .neither false) = true := by decide
  exact List.all_eq_true.mp checked p member

theorem callback_returns_or_unwinds_through_both_drops (p : List PoolMir.Event)
    (emitted : p ∈ PoolMir.paths) (called : .invoke ∈ p) :
    ∃ last, (last = PoolMir.Event.returned ∨ last = .unwind) ∧
      p = [.takeGeneration, .takeHealth, .invoke, .dropHealth, .dropGeneration, last] := by
  simp only [PoolMir.paths, List.mem_cons, List.not_mem_nil, or_false] at emitted
  rcases emitted with h | h | h | h | h | h | h <;> subst p <;> simp_all

open PlatformProofs in
/-- The release/acquire edge publishes the whole health record. The actor
    reading it may differ from the one that published the revision. -/
theorem acquire_after_publication_observes_complete_record (s : LockedState) (publisher reader : Nat)
    (free : s.guards = .free) (revision now : U64) (status : U16) (h : upstream.PoolHealth)
    (published : upstream.publish_health s.health revision now status = ok h) :
    (do let record ← upstream.publish_health s.health revision now status
        let acquired := lockRun s [(publisher, .publish record), (reader, .takeGeneration), (reader, .takeHealth)]
        ok (acquired.guards, acquired.health, acquired.retired)) = ok (.both reader, h, s.retired) := by
  simp [published, lockRun, lockStep, free]

/- Linux boot time advances by both active and suspended time in one boot. -/
structure Clocks where
  active : U128
  suspended : Nat

def boot (c : Clocks) := c.active.val + c.suspended
def sleepFor (c : Clocks) (ns : Nat) : Clocks := {c with suspended := c.suspended + ns}
theorem sleep_advances_health_clock (c : Clocks) (ns : Nat) :
    boot (sleepFor c ns) = boot c + ns := by simp [boot, sleepFor, Nat.add_assoc]

theorem resume_expiry_preserves_writer {W} (writer : upstream.FirstWriter W) (state : W)
    (m : Slice U32) (i : Usize) (g : upstream.FirstWriteGate) (sent : Bool)
    (c : Clocks) (ns : Nat) (raw : U128) (sample : raw.val = boot (sleepFor c ns))
    (adapter : upstream.pool_tick (some raw) = ok g.now)
    (expired : g.health.at.val + 5000000000 ≤ boot c + ns) :
    upstream.guarded_first_write writer m i g sent state = ok (none, sent, state) := by
  apply UpstreamProofs.unusable_health_preserves_writer
  left
  have value := PlatformProofs.tick_value raw
  rw [adapter] at value
  have tick : g.now.val = min raw.val 18446744073709551615 := by simpa using value
  by_cases fits : raw.val < 18446744073709551615
  · rw [Nat.min_eq_left (Nat.le_of_lt fits)] at tick
    rw [sleep_advances_health_clock] at sample
    unfold UpstreamProofs.FreshAt
    omega
  · rw [Nat.min_eq_right (Nat.le_of_not_gt fits)] at tick
    have invalid : g.now = core.num.U64.MAX := by
      apply UScalar.eq_of_val_eq; simpa [core.num.U64.MAX, U64.rMax] using tick
    exact fun fresh => fresh.2.2.1 invalid

inductive HealthEvent where
  | probe (expected start finish : U64) (status : U16)
  | dialFailure (tick : U64)

/-- Newest event first. These are the two ways the adapter can publish a member record. -/
inductive HealthHistory (initial : upstream.PoolHealth) : List HealthEvent → upstream.PoolHealth → Prop where
  | empty : HealthHistory initial [] initial
  | checked (prev : HealthHistory initial events old)
      (out : upstream.publish_probe old expected start finish status = ok next) :
      HealthHistory initial (.probe expected start finish status :: events) next
  | failed (prev : HealthHistory initial events old)
      (out : upstream.publish_health old old.revision tick 0#u16 = ok next) :
      HealthHistory initial (.dialFailure tick :: events) next

theorem healthy_record_has_probe {old next : upstream.PoolHealth} {events : List HealthEvent}
    (history : HealthHistory old events next) (healthy : 200 ≤ next.status.val) :
    next = old ∨ ∃ expected start finish status, HealthEvent.probe expected start finish status ∈ events ∧
      UpstreamProofs.WithinTTL start finish ∧ next.at = start ∧ next.status = status := by
  induction history with
  | empty => exact Or.inl rfl
  | checked prev out ih =>
    rcases UpstreamProofs.probe_publication_cases _ _ _ _ _ _ out with same | ⟨window, _, _, time, code⟩
    · subst_vars
      rcases ih healthy with same | ⟨e,s,f,n,mem,rest⟩
      · exact Or.inl same
      · exact Or.inr ⟨e,s,f,n,List.mem_cons_of_mem _ mem,rest⟩
    · exact Or.inr ⟨_,_,_,_,List.mem_cons_self,window,time,code⟩
  | failed prev out ih =>
    rcases UpstreamProofs.publication_cases _ _ _ _ _ out with same | ⟨_,_,_,code⟩
    · subst_vars
      rcases ih healthy with same | ⟨e,s,f,n,mem,rest⟩
      · exact Or.inl same
      · exact Or.inr ⟨e,s,f,n,List.mem_cons_of_mem _ mem,rest⟩
    · simp [code] at healthy

theorem first_effect_after_expiry_requires_recheck {W} (writer : upstream.FirstWriter W) (state : W)
    (m : Slice U32) (i : Usize) (g : upstream.FirstWriteGate) (sent spent : Bool)
    (io : upstream.FirstIo) (state' : W) (initial : upstream.PoolHealth) (events : List HealthEvent)
    (history : HealthHistory initial events g.health) (expired : initial.at.val + 5000000000 ≤ g.now.val)
    (effect : upstream.guarded_first_write writer m i g sent state = ok (some io, spent, state')) :
    ∃ expected start finish status, HealthEvent.probe expected start finish status ∈ events ∧
      UpstreamProofs.WithinTTL start finish ∧ UpstreamProofs.WithinTTL start g.now ∧
      200 ≤ status.val ∧ status.val < 300 := by
  obtain ⟨_, fresh, code, _⟩ := UpstreamProofs.effect_targets_registered_healthy_peer
    writer m i g sent state io spent state' effect
  rcases healthy_record_has_probe history code.1 with same | ⟨e,s,f,n,mem,window,time,status⟩
  · rw [same] at fresh
    unfold UpstreamProofs.FreshAt at fresh
    omega
  · exact ⟨e,s,f,n,mem,window,time ▸ fresh.2.2,status ▸ code⟩

theorem instant_delta_within_kernel_brackets (lo₀ read₀ hi₀ lo₁ read₁ hi₁ origin : Nat)
    (a : lo₀ ≤ read₀) (b : read₀ ≤ hi₀) (c : lo₁ ≤ read₁) (d : read₁ ≤ hi₁)
    (originBound : origin ≤ lo₀) (ordered : hi₀ ≤ lo₁) :
    lo₁ - hi₀ ≤ (read₁-origin) - (read₀-origin) ∧
      (read₁-origin) - (read₀-origin) ≤ hi₁ - lo₀ := by omega

theorem first_report_retains_errno {E} (e : E) :
    upstream.first_write_report (.Err e) = ok (.Failed, some e) ∧
    upstream.first_write_report (E := E) (.Ok none) = ok (.Wait, none) := by exact ⟨rfl, rfl⟩

theorem first_report_retains_partial_count (E : Type) (n : Usize) :
    upstream.first_write_report (E := E) (.Ok (some n)) = ok (.Written n, none) := by rfl

def reportedWriter {E : Type} (report : core.result.Result (Option Usize) E) :
    upstream.FirstWriter (Option E) := ⟨fun _ => upstream.first_write_report report⟩

/-- For the record used by an actual first-write effect, this is the exact
    budget left between its clock read and a later observation of socket I/O. -/
theorem fresh_at_io_iff_delay_fits {W} (writer : upstream.FirstWriter W) (state : W)
    (m : Slice U32) (i : Usize) (g : upstream.FirstWriteGate) (sent spent : Bool)
    (event : upstream.FirstIo) (state' : W) (ioTime : U64)
    (out : upstream.guarded_first_write writer m i g sent state = ok (some event, spent, state'))
    (ordered : g.now.val ≤ ioTime.val) (finite : ioTime ≠ core.num.U64.MAX) :
    UpstreamProofs.FreshAt g.health ioTime ↔
      ioTime.val - g.now.val < 5000000000 - (g.now.val - g.health.at.val) := by
  obtain ⟨_, fresh, _⟩ := UpstreamProofs.effect_targets_registered_healthy_peer
    writer m i g sent state event spent state' out
  obtain ⟨live, current, _, observed, young⟩ := fresh
  have elapsed : ioTime.val - g.health.at.val =
      (g.now.val - g.health.at.val) + (ioTime.val - g.now.val) := by omega
  have budget := Nat.sub_add_cancel (Nat.le_of_lt young)
  constructor
  · intro stillFresh
    have short := stillFresh.2.2.2.2
    omega
  · intro inBudget
    exact ⟨live, current, finite, Nat.le_trans observed ordered, by omega⟩

theorem resampling_at_expiry_skips_write {W} (writer : upstream.FirstWriter W) (state : W)
    (m : Slice U32) (i : Usize) (g : upstream.FirstWriteGate) (later : U64) (sent : Bool)
    (expired : g.health.at.val + 5000000000 ≤ later.val) :
    upstream.guarded_first_write writer m i {g with now := later} sent state = ok (none, sent, state) := by
  apply UpstreamProofs.unusable_health_preserves_writer
  left
  change ¬ UpstreamProofs.FreshAt g.health later
  unfold UpstreamProofs.FreshAt
  omega

/-- A no-progress first attempt must face the restored clock on its next turn. -/
theorem wait_then_resume_expiry_preserves_grant {W} (writer : upstream.FirstWriter W) (state next : W)
    (m : Slice U32) (i : Usize) (g : upstream.FirstWriteGate) (later : U64)
    (permit : UpstreamProofs.MayWrite m i g false) (waited : writer.write_once state = ok (.Wait, next))
    (expired : g.health.at.val + 5000000000 ≤ later.val) :
    (do let (_, spent, w) ← upstream.guarded_first_write writer m i g false state
        upstream.guarded_first_write writer m i {g with now := later} spent w) = ok (none, false, next) := by
  rw [UpstreamProofs.allowed_executes_one_write writer m i g false state permit, waited]
  exact resampling_at_expiry_skips_write writer next m i g later false expired

/-- A concrete eligible member can produce a positive effect from a saved
    sample, even when re-evaluation exactly five seconds later denies it. -/
theorem saved_sample_can_write_at_expiry :
    ∃ (m : Slice U32) (g : upstream.FirstWriteGate) (later : U64),
      g.now.val + 5000000000 = later.val ∧
      upstream.fresh_health g.health later = ok false ∧
      upstream.guarded_first_write (reportedWriter (E := Unit) (.Ok (some 1#usize)))
        m 0#usize g false none = ok (some (.Written 1#usize), true, none) ∧
      upstream.guarded_first_write (reportedWriter (E := Unit) (.Ok (some 1#usize)))
        m 0#usize {g with now := later} false none = ok (none, false, none) := by
  let m : Slice U32 := ⟨[8080#u32], by simp; scalar_tac⟩
  let g : upstream.FirstWriteGate := ⟨8080#u32, ⟨1#u64, 0#u64, 204#u16⟩, 0#u64, false, false⟩
  have permit : UpstreamProofs.MayWrite m 0#usize g false := by
    simp [m, g, UpstreamProofs.MayWrite, UpstreamProofs.FreshAt, UpstreamProofs.memberAt,
      Slice.len, core.num.U64.MAX, U64.rMax]
  refine ⟨m, g, 5000000000#u64, by decide, ?_, ?_, ?_⟩
  · apply PlatformProofs.expired_sample_stays_expired g.health 5000000000#u64 <;> decide
  · exact UpstreamProofs.positive_write_spends_grant _ _ _ _ false none permit 1#usize (by decide) none rfl
  · exact resampling_at_expiry_skips_write _ none _ _ g _ false (by decide)

theorem fatal_first_report_spends_grant_with_original_cause {E : Type} (e : E)
    (m : Slice U32) (i : Usize) (g : upstream.FirstWriteGate) (permit : UpstreamProofs.MayWrite m i g false) :
    upstream.guarded_first_write (reportedWriter (.Err e)) m i g false none = ok (some .Failed, true, some e) := by
  apply UpstreamProofs.empty_or_failed_write_is_terminal _ m i g false none permit
  exact Or.inr rfl

theorem retryable_first_report_requires_live_generation {E : Type}
    (m : Slice U32) (i : Usize) (g : upstream.FirstWriteGate) (permit : UpstreamProofs.MayWrite m i g false) :
    (do let (_, spent, next) ← upstream.guarded_first_write (reportedWriter (E := E) (.Ok none)) m i g false none
        let retired ← upstream.retire_pool g.retired
        upstream.guarded_first_write (reportedWriter (E := E) (.Ok none)) m i {g with retired} spent next) =
      ok (none, false, none) := by
  apply UpstreamProofs.wait_then_retirement_cannot_write _ m i g false none permit
  rfl

/-- Socket identity is an observation in the model. The adapter owns a single
    TcpStream, and the Linux fixture independently measures its SO_COOKIE. -/
inductive SocketState (E : Type) where
  | live (rest : Slice U8)
  | stopped (reason : Option E) (rest : Slice U8)
  | wrongSocket

abbrev Report (E : Type) := U64 × core.result.Result (Option Usize) E

def socketStep {E} (id : U64) (state : SocketState E) (event : Report E) : RustM (SocketState E) :=
  match state with
  | .live buf =>
    if event.1 ≠ id then ok .wrongSocket else match event.2 with
    | .Err e => ok (.stopped (some e) buf)
    | .Ok count => do
      let rest ← upstream.remaining_after_write buf count
      match rest with
      | some bytes => ok (.live bytes)
      | none => ok (.stopped none buf)
  | other => ok other

def socketRun {E} (id : U64) (state : SocketState E) : List (Report E) → RustM (SocketState E)
  | [] => ok state
  | e :: es => do
    let next ← socketStep id state e
    socketRun id next es

theorem stopped_preserves_errno_and_suffix {E} (id : U64) (why : Option E) (buf : Slice U8)
    (tail : List (Report E)) : socketRun id (.stopped why buf) tail = ok (.stopped why buf) := by
  induction tail with
  | nil => rfl
  | cons _ _ ih => simpa [socketRun, socketStep] using ih

theorem foreign_socket_is_rejected {E} (id other : U64) (different : other ≠ id) (buf : Slice U8)
    (result : core.result.Result (Option Usize) E) :
    socketStep id (.live buf) (other, result) = ok .wrongSocket := by simp [socketStep, different]

theorem retryable_report_keeps_socket_cursor {E} (id : U64) (buf : Slice U8) (tail : List (Report E)) :
    socketRun id (.live buf) ((id, .Ok none) :: tail) = socketRun id (.live buf) tail := by
  simp [socketRun, socketStep, PlatformProofs.wait_keeps_every_byte]

theorem fatal_after_partial_preserves_exact_unaccepted_suffix {E} (id : U64) (buf rest : Slice U8)
    (n : Usize) (positive : 0 < n.val)
    (accepted : upstream.remaining_after_write buf (some n) = ok (some rest))
    (e : E) (tail : List (Report E)) :
    socketRun id (.live buf) ((id, .Ok (some n)) :: (id, .Err e) :: tail) = ok (.stopped (some e) rest) ∧
    buf.val.take n.val ++ rest.val = buf.val := by
  constructor
  · simp [socketRun, socketStep, accepted, stopped_preserves_errno_and_suffix]
  · rw [PlatformProofs.positive_count_uses_suffix buf n positive] at accepted
    exact PlatformProofs.accepted_prefix_and_suffix _ _ _ accepted

/- One distinguished first writer and any number of other shared file
   descriptions. The second component counts time actually spent in managed
   sleep. A killed coordinator leaves the closed byte on the same inode. -/
inductive Fence where
  | awake (mine : Bool) (others : Nat)
  | exclusive
  | orphaned
  deriving DecidableEq

inductive PowerEvent where
  | takeMine | dropMine | takeOther | dropOther | write | close
  | sleep (elapsed : Nat)
  | reopen | loseManager
  deriving DecidableEq

def powerStep : Fence × Nat → PowerEvent → Option (Fence × Nat)
  | (.awake false n, t), .takeMine => some (.awake true n, t)
  | (.awake true n, t), .dropMine => some (.awake false n, t)
  | (.awake b n, t), .takeOther => some (.awake b (n+1), t)
  | (.awake b (n+1), t), .dropOther => some (.awake b n, t)
  | (.awake true n, t), .write => some (.awake true n, t)
  | (.awake false 0, t), .close => some (.exclusive, t)
  | (.exclusive, t), .sleep ns => some (.exclusive, t+ns)
  | (.exclusive, t), .reopen => some (.awake false 0, t)
  | (.exclusive, t), .loseManager => some (.orphaned, t)
  | _, _ => none

def powerRun (s : Fence × Nat) : List PowerEvent → Option (Fence × Nat)
  | [] => some s
  | e :: tail => (powerStep s e).bind (fun next => powerRun next tail)

theorem awake_marker_exact (n : U64) (b : U8) :
    upstream.sleep_fence_awake n b = ok (decide (n = 1#u64 ∧ b = 65#u8)) := by
  by_cases h : n = 1#u64 <;> simp [upstream.sleep_fence_awake, h]

theorem closing_requires_all_readers_released (f : Fence) (t : Nat) (s : Fence × Nat) :
    powerStep (f, t) .close = some s ↔ f = .awake false 0 ∧ s = (.exclusive, t) := by
  cases f with
  | awake b n => cases b <;> cases n <;> simp [powerStep, eq_comm]
  | exclusive | orphaned => simp [powerStep]

theorem orphaned_fence_cannot_write_or_restart (t : Nat) (e : PowerEvent) (tail : List PowerEvent) :
    powerRun (.orphaned, t) (e :: tail) = none := by
  cases e <;> rfl

theorem held_step_preserves_suspended_time {n t : Nat} {e : PowerEvent} {out : Fence × Nat}
    (keep : e ≠ .dropMine) (step : powerStep (.awake true n, t) e = some out) :
    ∃ k, out = (.awake true k, t) := by
  cases e <;> cases n <;> simp_all [powerStep] <;> exact ⟨_, step.symm⟩

/-- Between the last clock read and this writer's release, other actors may
    run. No successful sequence can add any suspended time to its sample. -/
theorem held_lease_excludes_sleep (t : Nat) (events : List PowerEvent) (n : Nat) (out : Fence × Nat)
    (keep : .dropMine ∉ events) (ran : powerRun (.awake true n, t) events = some out) :
    ∃ k, out = (.awake true k, t) := by
  induction events generalizing n with
  | nil =>
    simp only [powerRun, Option.some.injEq] at ran
    exact ⟨n, ran.symm⟩
  | cons e es ih =>
    have head : e ≠ .dropMine := by intro h; subst e; exact keep (by simp)
    have tail : .dropMine ∉ es := fun member => keep (List.mem_cons_of_mem _ member)
    cases one : powerStep (.awake true n, t) e with
    | none => simp [powerRun, one] at ran
    | some next =>
      obtain ⟨k, rfl⟩ := held_step_preserves_suspended_time head one
      exact ih k tail (by simpa [powerRun, one] using ran)

/-- The acquired writer cannot even enter a zero-duration sleep transition. -/
theorem held_lease_forbids_sleep_event (t ns : Nat) (events : List PowerEvent)
    (n : Nat) (out : Fence × Nat) (keep : .dropMine ∉ events)
    (ran : powerRun (.awake true n, t) events = some out) : .sleep ns ∉ events := by
  induction events generalizing n with
  | nil => simp
  | cons e es ih =>
    have head : e ≠ .dropMine := by intro h; subst e; exact keep (by simp)
    have tail : .dropMine ∉ es := fun member => keep (List.mem_cons_of_mem _ member)
    cases one : powerStep (.awake true n, t) e with
    | none => simp [powerRun, one] at ran
    | some next =>
      have different : PowerEvent.sleep ns ≠ e := by
        intro h; subst e; simp [powerStep] at one
      obtain ⟨k, rfl⟩ := held_step_preserves_suspended_time head one
      exact fun member => (List.mem_cons.mp member).elim different
        (ih k tail (by simpa [powerRun, one] using ran))

theorem sleep_wins_expired_first_write_is_inert {W} (writer : upstream.FirstWriter W)
    (state : W) (m : Slice U32) (i : Usize) (g : upstream.FirstWriteGate) (sent : Bool)
    (t ns active : Nat) (later : U64) (clock : later.val = active + (t + ns))
    (expired : g.health.at.val + 5000000000 ≤ active + (t + ns)) :
    powerRun (.awake false 0, t) [.close, .sleep ns, .reopen, .takeMine] =
      some (.awake true 0, t + ns) ∧
    upstream.guarded_first_write writer m i {g with now := later} sent state =
      ok (none, sent, state) := by
  exact ⟨rfl, resampling_at_expiry_skips_write writer state m i g later sent (by omega)⟩

/-- A request admitted after a completed sleep uses its post-resume clock
    sample. Link that position to the generated dispatch and probe history. -/
theorem coordinated_resume_effect_requires_recheck {W} (writer : upstream.FirstWriter W)
    (state next : W) (m : Slice U32) (i : Usize) (g : upstream.FirstWriteGate)
    (old : upstream.PoolHealth) (events : List HealthEvent) (sent spent : Bool) (io : upstream.FirstIo)
    (t ns active : Nat)
    (sample : g.now.val = active + (t + ns)) (expired : old.at.val + 5000000000 ≤ active + (t + ns))
    (history : HealthHistory old events g.health)
    (effect : upstream.guarded_first_write writer m i g sent state = ok (some io, spent, next)) :
    powerRun (.awake false 0, t) [.close, .sleep ns, .reopen, .takeMine, .write] =
      some (.awake true 0, t + ns) ∧
    ∃ expected start finish status, HealthEvent.probe expected start finish status ∈ events ∧
      UpstreamProofs.WithinTTL start finish ∧ UpstreamProofs.WithinTTL start g.now ∧
      200 ≤ status.val ∧ status.val < 300 := by
  exact ⟨rfl, first_effect_after_expiry_requires_recheck writer state m i g sent spent io next
    old events history (by omega) effect⟩

/-- The OS supplies the gap in userspace execution. After a full TTL asleep,
    every successful dispatch needs a probe that actually began after wake. -/
theorem long_sleep_requires_post_resume_probe {W} (writer : upstream.FirstWriter W)
    (state next : W) (m : Slice U32) (i : Usize) (g : upstream.FirstWriteGate)
    (old : upstream.PoolHealth) (events : List HealthEvent) (sent spent : Bool) (io : upstream.FirstIo)
    (before resumed : U64) (prior : old.at.val ≤ before.val)
    (elapsed : before.val + 5000000000 ≤ resumed.val) (ordered : resumed.val ≤ g.now.val)
    (quiescent : ∀ e s f code, HealthEvent.probe e s f code ∈ events →
      s.val ≤ before.val ∨ resumed.val ≤ s.val)
    (history : HealthHistory old events g.health)
    (effect : upstream.guarded_first_write writer m i g sent state = ok (some io, spent, next)) :
    ∃ e s f code, HealthEvent.probe e s f code ∈ events ∧ resumed.val ≤ s.val ∧
      UpstreamProofs.WithinTTL s f ∧ UpstreamProofs.WithinTTL s g.now ∧
      200 ≤ code.val ∧ code.val < 300 := by
  obtain ⟨e, s, f, code, mem, timely, fresh, status⟩ :=
    first_effect_after_expiry_requires_recheck writer state m i g sent spent io next old events
      history (by omega) effect
  have age := fresh.2.2
  have start := quiescent e s f code mem
  exact ⟨e, s, f, code, mem, by omega, timely, fresh, status⟩

end LinuxProofs
