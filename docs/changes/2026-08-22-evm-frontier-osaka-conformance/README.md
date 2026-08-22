# Change: Establish Frontier-Osaka EVM conformance

- **Status**: Accepted
- **Date**: 2026-08-22
- **Tier**: Full
- **Tracking PR**: [#600](https://github.com/DTVMStack/DTVM/pull/600)

## Overview

Extend DTVM's revision-aware EVM execution and conformance evidence from
Frontier-Cancun through Prague and Osaka. The result must support every
mainnet EVM revision exposed by EVMC from `EVMC_FRONTIER` through
`EVMC_OSAKA`, run the same explicit revision in interpreter and multipass
modes, and validate the result against a pinned official fixture release.

This change is complete only when the evidence supports the following scoped
claim:

> DTVM supports the EVM execution semantics of every Ethereum mainnet revision
> from Frontier through Osaka under the EVMC execution boundary, validated in
> interpreter and multipass modes against the applicable EEST v5.4.0 develop
> state-test cases.

The claim covers VM execution, revision-gated opcodes, precompile calls handled
by the test execution environment, transaction admission rules represented by
state fixtures, and gas accounting observable at the EVMC boundary. It does
not claim that DTVM is a full Ethereum consensus or networking client.

## Motivation

The current continuous-integration state-test job filters only Cancun. DTVM
already has partial Prague and Osaka code and imported tests, but partial code
presence is not evidence of conformance. Unknown state-test fork labels can
also fall back to the Cancun default, which can produce false-green results.
For a contemporary systems evaluation, DTVM needs reproducible evidence for
all mainnet EVM revisions through the current Osaka revision.

The frozen external oracle is:

- Repository: `ethereum/execution-spec-tests`
- Release: `v5.4.0` (final Osaka release)
- Asset: `fixtures_develop.tar.gz`
- URL: `https://github.com/ethereum/execution-spec-tests/releases/download/v5.4.0/fixtures_develop.tar.gz`
- SHA-256: `3e2b02d49fe903eda4fd8caca5cbf0d139c470e97e1de9a85299b1b034f97099`

The release's `fixtures_stable.tar.gz` asset is not sufficient for this
change: inspection of its state-test `post` keys found Prague but no Osaka
cases. The pinned `fixtures_develop.tar.gz` asset from the same immutable final
Osaka release contains both Prague and Osaka cases. "Develop" is the upstream
asset name, not a mutable branch or URL in this design.

Mutable `latest` or branch-qualified fixture URLs are not valid evidence for
the final PR or paper artifact.

## Goals

1. Recognize and propagate every mainnet EVMC revision from Frontier through
   Osaka without silently substituting Cancun.
2. Complete Prague and Osaka VM-visible opcode, gas, transaction, and
   precompile-boundary behavior required by applicable EEST v5.4.0 fixtures.
3. Produce separate interpreter and multipass conformance results from the
   same pinned fixture archive.
4. Report exact loaded, applicable, executed, passed, failed, errored, and
   excluded case counts per revision and mode.
5. Keep every exclusion outside the DTVM EVMC boundary explicit and auditable;
   no DTVM-caused failure may be reclassified as a skip.

## Non-Goals

- Ethereum consensus, fork choice, validator, P2P, or PeerDAS implementation.
- Full execution-client block processing outside the EVMC VM boundary,
  including client-owned system-call scheduling or networking behavior.
- Performance claims or benchmark results.
- Importing generated fixture archives into Git history.
- Refactoring unrelated interpreter, compiler, runtime, or test code.

## Impact

### Affected Modules

- `evm`: revision-gated opcode and gas semantics; current default revision.
- `tests`: fork parsing, fixture admission, state transitions, mocked execution
  environment, precompile boundaries, result accounting, and regressions.
- `compiler`: propagation of the requested revision through multipass analysis,
  instruction tables, lowering, and fallback.
- `runtime`: preservation of the requested revision in modules and instances.
- `vm-interface`: EVMC revision propagation, module cache identity, and
  interpreter/multipass parity.
- `cli`: explicit `prague` and `osaka` selection and current-mainnet default.
- CI scripts and workflows: pinned fixtures and the Frontier-Osaka matrix.

### Affected Contracts

- A recognized state-test fork label maps to exactly one `evmc_revision`.
- An unrecognized or unsupported fork label fails before execution; it never
  returns `DEFAULT_REVISION`.
- The revision received at the EVMC entry is the revision used for instruction
  availability, gas tables, precompile rules, interpreter execution,
  multipass analysis/lowering, cache identity, and fallback.
- The CLI accepts both `prague` and `osaka` explicitly.
- `DEFAULT_REVISION` advances from Cancun to Osaka. Callers that require
  historical behavior must continue to pass an explicit revision.
- Fixture acquisition verifies the pinned SHA-256 before extraction.

### Compatibility

No EVMC ABI or public C API shape changes. Advancing the default revision is an
intentional behavior change for callers that omit the revision; explicit
historical revisions remain supported. Tests and documentation that rely on
Cancun defaults must name Cancun explicitly.

## Design

### Revision Selection and Propagation

Use one fail-closed fork parser for canonical fixture names and documented
transition aliases. Keep the parser separate from `DEFAULT_REVISION` so an
unknown label cannot acquire valid-looking Cancun or Osaka semantics. Carry
the parsed revision through the existing EVMC/runtime/module/instance path and
use it for interpreter and multipass instruction tables, analyzer decisions,
gas metering, fallback, and cache keys.

### Prague and Osaka Semantics

Treat the pinned fixtures as the behavioral oracle. For each first failing
boundary, add a focused regression that fails for the missing semantic rule,
then make the smallest production change that passes it. Cover, as exercised
by applicable fixtures:

- Prague transaction-type and authorization-list activation boundaries;
- Prague calldata floor, blob schedule, delegation, and precompile behavior;
- Osaka `CLZ` availability and result semantics;
- Osaka transaction gas-limit and `MODEXP` gas changes;
- Osaka revision-gated precompile behavior; and
- exact pre-fork rejection or legacy behavior at every activation boundary.

Precompile behavior supplied by the state-test host must be identified as test
environment support in the evidence report. The production EVMC VM continues
to honor its existing host boundary; the paper must not recast host-provided
behavior as an internal DTVM implementation.

### Fixture Runner and Evidence

Download the pinned develop archive outside the source tree, verify its digest,
and run each mainnet revision independently through `evmone-statetest` with
DTVM loaded as the external EVMC VM. This keeps execution-client state
transition and precompile responsibilities in the test driver while testing
DTVM's VM-visible execution and gas behavior at the EVMC boundary. The
repository's lightweight state-test host remains useful for focused regression
tests, but is not the full-conformance oracle. The runner must fail when a
requested revision has no discovered cases, when a fork label is unknown, or
when accounting does not satisfy:

`loaded = applicable + explicitly_out_of_scope`

and

`applicable = passed + failed + errored`.

A DTVM limitation is a failure, not an exclusion. An exclusion is permitted
only when the fixture requires behavior outside the documented EVMC VM
boundary; every exclusion records its fixture identifier and reason.

Run the identical applicable case set in interpreter and multipass modes. A
mode-specific pass list is invalid evidence. Persist a machine-readable
manifest containing release, asset digest, DTVM commit, mode, revision, case
identifiers, result classification, and aggregate counts.

### CI

Replace the Cancun-only, mutable-fixture state-test job with pinned acquisition
and an explicit Frontier-Osaka revision matrix. Preserve existing interpreter,
multipass release/debug, gas-register, evmone unit, fallback, and performance
regression jobs. CI may cache the archive by its digest but must verify the
digest on every restoration.

## Implementation Plan

### Phase 1: Fail-closed revision coverage

- [x] Add failing tests for Osaka mapping, unknown-fork rejection, CLI Prague
  selection, and explicit default semantics.
- [x] Implement one canonical mapping and propagate Osaka through all existing
  state-test selection paths.
- [x] Advance and document the default revision after explicit-revision tests
  protect historical execution.

### Phase 2: Prague and Osaka behavior

- [ ] Run the pinned fixture corpus in interpreter mode and classify the first
  failing semantic boundaries without suppressing cases.
- [ ] Add one focused failing regression per missing rule and implement the
  minimal fix.
- [ ] Repeat the same case set in multipass mode and repair only genuine
  revision-propagation or lowering differences.

### Phase 3: Reproducible evidence and CI

- [ ] Pin the fixture URL and SHA-256 in the runner and workflow.
- [ ] Add fail-closed result accounting and a machine-readable manifest.
- [ ] Run the complete Frontier-Osaka matrix in both modes and record exact
  per-revision counts.
- [ ] Run all existing DTVM EVM CI-equivalent build, format, unit, fallback,
  differential, and performance-regression gates.
- [ ] Update module specifications, the PR title/body, and the release note to
  match the verified behavior and evidence.

### Commit Strategy

Use as many Conventional Commits as needed to keep each change independently
reviewable and reversible. Prefer one logical commit for each completed test
and implementation boundary or CI/evidence unit. Every implementation commit
must leave the branch buildable and include or reference the regression that
proves its behavior. There is no fixed maximum commit count for PR #600.

## Verification Gates

The implementation is complete only when all conditions hold:

1. The pinned archive digest matches the value above.
2. Every mainnet revision from Frontier through Osaka discovers applicable
   fixture cases in both interpreter and multipass modes.
3. Every applicable case passes in both modes: zero failures and zero errors.
4. There are zero unexplained skips; every out-of-scope fixture is listed with
   a boundary-based reason and excluded before the applicable denominator.
5. Focused activation-boundary tests pass immediately before and at Prague and
   Osaka for every implemented rule.
6. Existing Cancun and historical-fork tests remain green with explicit
   revisions.
7. Formatting, `git diff --check`, commit lint, builds, unit tests, fallback,
   differential tests, and existing performance-regression gates pass.
8. The evidence manifest is reproducible from documented commands at the PR
   head commit.

## Compatibility Notes

The default moves to Osaka so an unspecified revision follows the current
mainnet EVM revision represented by the frozen oracle. Consumers that need
Cancun or another historical fork must request it explicitly. Unknown textual
fork names become hard errors rather than inheriting a default.

## Risks

- **Scope inflation in PR #600**: Group work into logical Conventional Commits
  aligned with the implementation phases; do not impose an artificial commit
  limit or mix unrelated refactoring into the branch.
- **False-green coverage**: Fail on unknown forks, empty selections, accounting
  mismatches, digest mismatches, and DTVM-caused skips.
- **Fixture drift**: Use the immutable v5.4.0 URL and SHA-256, never `latest`.
- **Host/VM claim confusion**: Tag host-provided precompile behavior in the
  evidence manifest and retain the EVMC-boundary wording in the paper.
- **Interpreter/JIT divergence**: Execute the identical fixture identifiers in
  both modes and treat any result mismatch as a failure.
- **Default-revision compatibility**: Protect every historical revision with
  explicit-revision regressions and document the behavior change.
