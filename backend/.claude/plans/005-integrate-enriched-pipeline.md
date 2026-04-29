# Plan: Integrate Enriched Pipeline into seed_resolver and agent_nodes

## Problem

The new enriched pipeline modules (`patch_evidence.py`, `candidate_generator.py`) are built and tested but **not wired into the main pipeline**. Currently:

- `seed_resolver.resolve_seed_references()` calls `resolve_all_seed_sources()` but only uses the flat `references` list to produce `SeedReference` objects
- `agent_nodes.resolve_seeds_node` stores only `seed_references` (url + source + authority_score)
- `agent_nodes.build_initial_frontier_node` re-does reference matching from scratch using `match_reference_url()` on each `SeedReference.url`
- **Fix commits extracted from OSV/GitHub Advisory** (e.g., explicit commit SHAs with repo hints) are completely lost — they never become candidates

## Goal

Wire `normalize_seed_to_evidence()` and `generate_candidates()` into the seed resolution flow so that:
1. Fix commit evidence from structured sources becomes downloadable `PatchCandidate` objects
2. The enriched data flows through `AgentState` to `build_initial_frontier_node`
3. Existing behavior is preserved — the old `SeedReference` path still works alongside the new one

## Changes

### 1. `app/cve/seed_resolver.py` — Add enriched resolution

Add a new function `resolve_seed_enriched()` that:
- Calls `resolve_all_seed_sources()` (same as today)
- Calls `normalize_seed_to_evidence()` on the raw `SeedSourceResult` list
- Calls `generate_candidates()` on the evidence list
- Returns a `SeedResolutionResult` dataclass containing:
  - `references: list[SeedReference]` (existing)
  - `evidence: list[PatchEvidence]` (new)
  - `candidates: list[PatchCandidate]` (new)
  - `source_results: list[SeedSourceResult]` (for tracing)

Update `resolve_seed_references()` to delegate to `resolve_seed_enriched()` and return only `result.references` — preserving backward compatibility.

### 2. `app/cve/agent_state.py` — Add state fields

Add two new optional fields to `AgentState`:
- `patch_evidence: list[PatchEvidence]` (default `[]`)
- `patch_candidates: list[PatchCandidate]` (default `[]`)

Update `build_initial_agent_state()` to initialize both as empty lists.

### 3. `app/cve/agent_nodes.py` — Update resolve_seeds_node

Update `resolve_seeds_node` to:
- Call `resolve_seed_enriched()` instead of `resolve_seed_references()`
- Store `result.evidence` in `state["patch_evidence"]`
- Store `result.candidates` in `state["patch_candidates"]`
- Continue storing `result.references` in `state["seed_references"]`

### 4. `app/cve/agent_nodes.py` — Update build_initial_frontier_node

After the existing `SeedReference` → `match_reference_url` loop, add a second pass that:
- Iterates over `state["patch_candidates"]` where `candidate.downloadable is True`
- For each candidate, builds a `candidate_record` and calls `upsert_candidate_artifact()`
- Merges into `direct_candidates` (deduped by `canonical_key`)

This ensures fix commits from OSV/GitHub Advisory that have explicit SHAs + repo hints become direct candidates even if their URLs weren't in the flat reference list.

### 5. Tests

- Add `tests/test_seed_resolver_enriched.py` — unit test for `resolve_seed_enriched()` verifying it returns evidence and candidates alongside references
- Update existing test assertions if needed (the current test asserts `references == [list of strings]` which is already wrong for `SeedReference` objects — this is a pre-existing issue)

## Files Modified

1. `app/cve/seed_resolver.py` — add `SeedResolutionResult`, `resolve_seed_enriched()`
2. `app/cve/agent_state.py` — add `patch_evidence`, `patch_candidates` fields
3. `app/cve/agent_nodes.py` — update `resolve_seeds_node`, `build_initial_frontier_node`
4. `tests/test_seed_resolver_enriched.py` — new test file

## Risks

- **Low**: Adding new fields to `AgentState` is backward-compatible (TypedDict with `total=False`)
- **Low**: `resolve_seed_references()` return type unchanged — callers unaffected
- **Medium**: `build_initial_frontier_node` dedup logic must handle candidates from both old and new paths without double-counting
