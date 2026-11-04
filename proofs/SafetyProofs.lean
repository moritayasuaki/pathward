import DeliveryProofs
import RuntimeProofs
open Aeneas Aeneas.Std RustM
open pathward PathwardProofs RulesProofs ServingProofs DeliveryProofs
namespace SafetyProofs

/-- Removing declarations from valid compiled tables cannot introduce a mapping. -/
theorem lookup_subset (old new oldOut newOut : Slice rules.Publication)
    (ho : rules.compile old = ok (some oldOut))
    (hn : rules.compile new = ok (some newOut))
    (subset : ∀ r ∈ new.val, r ∈ old.val)
    (p target : Slice U8) (h : rules.lookup p newOut = ok (some target)) :
    rules.lookup p oldOut = ok (some target) := by
  obtain ⟨r, hr, hp, ht⟩ := (compiled_lookup_iff p target new newOut hn).mp h
  exact (compiled_lookup_iff p target old oldOut ho).mpr ⟨r, subset r hr, hp, ht⟩

/-- Restricting publication declarations preserves both target and GET/HEAD mode. -/
theorem authorization_subset (old new oldOut newOut : Slice rules.Publication)
    (ho : rules.compile old = ok (some oldOut))
    (hn : rules.compile new = ok (some newOut))
    (subset : ∀ r ∈ new.val, r ∈ old.val)
    (m host site target : Slice U8) (grant : serving.Grant)
    (h : serving.authorize m host site target newOut = ok (some grant)) :
    serving.authorize m host site target oldOut = ok (some grant) := by
  obtain ⟨hm, hh, hb, p, hp, hl⟩ := (authorize_contract m host site target newOut grant).mp h
  exact (authorize_contract m host site target oldOut grant).mpr
    ⟨hm, hh, hb, p, hp, lookup_subset old new oldOut newOut ho hn subset p grant.target hl⟩

/-- An absent URL has no target, regardless of the remaining valid declarations. -/
theorem revoked_lookup (rs out : Slice rules.Publication)
    (hc : rules.compile rs = ok (some out)) (p : Slice U8)
    (absent : ∀ r ∈ rs.val, p.val ≠ r.path.val) :
    rules.lookup p out = ok none := by
  obtain ⟨result, h⟩ := lookup_total p out
  cases result with
  | none => exact h
  | some target =>
    obtain ⟨r, hr, hp, _⟩ := (compiled_lookup_iff p target rs out hc).mp h
    exact False.elim (absent r hr hp)

/-- The raw-target adapter cannot recover a deleted publication through a query. -/
theorem revoked_authorization (rs out : Slice rules.Publication)
    (hc : rules.compile rs = ok (some out)) (m host site target p : Slice U8)
    (path : serving.request_path target = ok (some p))
    (absent : ∀ r ∈ rs.val, p.val ≠ r.path.val) (grant : serving.Grant) :
    serving.authorize m host site target out ≠ ok (some grant) := by
  intro h
  obtain ⟨_, _, _, q, hq, hl⟩ := (authorize_contract m host site target out grant).mp h
  have eq : q = p := by rw [path] at hq; simpa using hq.symm
  subst q
  rw [revoked_lookup rs out hc p absent] at hl
  simp at hl

/-- Two sequential writers using one old generation cannot both commit changes. -/
theorem stale_after_success (current next : U64)
    (room : current.val < 18446744073709551615)
    (first : runtime.commit_generation current current true true true false = ok next)
    (prepared identity storage draining : Bool) :
    runtime.commit_generation next current prepared identity storage draining = ok next := by
  obtain ⟨n, hn, hv⟩ := RuntimeProofs.commit_contract current current true true true false
  have he : n = next := by rw [first] at hn; simpa using hn.symm
  subst n
  have advanced : next.val = current.val + 1 := by simpa [RuntimeProofs.commitPolicy, room] using hv
  apply RuntimeProofs.stale_retains
  intro same
  have : next.val = current.val := congrArg UScalar.val same
  omega

/-- Lower configured/live caps cannot enable an admission at unchanged occupancy. -/
theorem service_tightening (active oldConfig oldLive newConfig newLive : U64)
    (hc : newConfig.val ≤ oldConfig.val) (hl : newLive.val ≤ oldLive.val)
    (vc : oldConfig.val ≤ 64) (vl : oldLive.val ≤ 64)
    (h : routing.service_admit active newConfig newLive = ok true) :
    routing.service_admit active oldConfig oldLive = ok true := by
  simp [RoutingProofs.service_eq] at h ⊢
  omega

/-- Reducing a deadline budget cannot make an expired phase live again. -/
theorem deadline_tightening (elapsed small large : U64) (draining : Bool)
    (le : small.val ≤ large.val) (valid : large.val ≤ 120000)
    (h : delivery.phase_live elapsed small draining = ok true) :
    delivery.phase_live elapsed large draining = ok true := by
  simp [phase_eq] at h ⊢
  rcases h with ⟨hd, hs, _, he⟩
  exact ⟨hd, by omega, valid, by omega⟩

/-- Additional early-data risk or removed grants cannot turn a refusal into permission. -/
theorem early_restriction (read published newRead newPublished sensitive newSensitive : Bool)
    (body newBody : U64)
    (hr : newRead = true → read = true)
    (hp : newPublished = true → published = true)
    (hs : sensitive = true → newSensitive = true)
    (hb : body.val ≤ newBody.val)
    (h : delivery.early_allowed false newRead newPublished newBody newSensitive = ok true) :
    delivery.early_allowed false read published body sensitive = ok true := by
  obtain ⟨r, p, n, s⟩ := early_only_published_reads newRead newPublished newBody newSensitive h
  have clean : sensitive = false := by cases sensitive <;> simp_all
  simp [early_eq, hr r, hp p, clean, show body.val = 0 by omega]

/-- A trace records calls to the extracted gate and the actual byte-counter update. -/
inductive WireRun (limit : U64) : U64 → List U64 → U64 → Prop
  | nil (used) : WireRun limit used [] used
  | step (used chunk next final : U64) (rest : List U64)
      (accepted : delivery.wire_fits used chunk limit = ok true)
      (advanced : next.val = used.val + chunk.val)
      (tail : WireRun limit next rest final) : WireRun limit used (chunk :: rest) final

/-- Arbitrarily fragmented input is charged for the sum of every accepted fragment. -/
theorem wire_run_accounting (limit first final : U64) (chunks : List U64)
    (run : WireRun limit first chunks final) :
    final.val = first.val + (chunks.map (fun n => n.val)).sum := by
  induction run with
  | nil => simp
  | step used chunk next final rest accepted advanced tail ih =>
    simp only [List.map_cons, List.sum_cons]
    omega

/-- Every finite accepted sequence stays within the cap and below machine overflow. -/
theorem wire_run_bounded (limit first final : U64) (chunks : List U64)
    (cap : limit.val ≤ 134283264) (initial : first.val ≤ limit.val)
    (run : WireRun limit first chunks final) :
    first.val + (chunks.map (fun n => n.val)).sum ≤ limit.val ∧
    first.val + (chunks.map (fun n => n.val)).sum < 2^64 := by
  have finalBound : final.val ≤ limit.val := by
    induction run with
    | nil => exact initial
    | step used chunk next final rest accepted advanced tail ih =>
      exact ih (by have := wire_bounded used chunk limit accepted; omega)
  have := wire_run_accounting limit first final chunks run
  omega

end SafetyProofs
