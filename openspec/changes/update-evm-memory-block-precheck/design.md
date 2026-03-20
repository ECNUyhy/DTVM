## Context

Week 1 established that the main P1.2 bottleneck is the conservative memory-check structure generated in the EVM frontend rather than the total absence of direct pointer access.

Week 2 added:

- compile-time memory summary instrumentation
- block / PC-level memory analysis
- direct-memory vs helper-sensitive block classification
- real sample evidence showing that the safest first optimization target is a pure direct-memory basic block

Current representative findings:

- `mcopy.evm.hex` contains a direct-only block with:
  - `direct_ops = 2`
  - `helper_barrier = 0`
  - `expand_calls = 2`
  - `need_expand_cfg = 2`
- `simple_erc20.evm.hex` contains several real-world direct-only blocks with similar shape
- `log_all.evm.hex` is helper-heavy and should not be first-wave scope

## Goals

- Reduce repeated `expandMemoryIR()`-generated per-op checks inside a narrow class of straight-line direct-memory blocks
- Keep semantics stable and reviewable
- Avoid broad architectural changes

## Non-Goals

- Whole-function memory analysis
- Loop-aware hoisting
- Helper-family optimization
- Runtime API changes

## Proposed Design

### 1. Eligibility

Only consider blocks that are:

- single basic-block regions already identified by the existing decode/block machinery
- free of helper barriers
- composed only of supported direct-memory ops
- able to resolve each covered direct-memory address to a compile-time constant in a local abstract stack scan
- sufficiently dense to justify a precheck (`direct_ops >= 2`)

### 2. Precheck summary

For an eligible block, compute:

- block entry PC
- count and family of direct ops
- maximum required size across covered ops
- whether all covered ops can safely reuse one prechecked memory-size state

The summary should remain frontend-only and compile-time only.

### 3. Code generation strategy

For the first prototype:

1. Emit one block-local overflow / max-required-size computation
2. Emit one block-local `expandMemoryIR()`-equivalent precheck sequence
3. Mark covered direct-memory ops so they reuse the prechecked state instead of each emitting a fresh `NeedExpand` CFG

The first implementation should remain conservative:

- if the block shape does not match exactly, fall back to the original per-op path
- if any helper-sensitive opcode appears, fall back immediately
- if any covered address becomes dynamic / unknown in the local scan, fall back immediately

Current prototype note:

- the implemented Week 2 prototype is narrower than the long-term direct-memory goal
- it currently covers constant-address `MLOAD` / `MSTORE` / `MSTORE8`
- `MCOPY` and dynamic-address straight-line patterns still fall back to the original path

### 4. Gas and correctness constraints

The prototype must preserve:

- overflow traps
- memory expansion gas charging behavior
- aligned memory growth behavior
- helper semantics on non-covered blocks

This means the prototype cannot simply “skip checks”; it must replace repeated checks with a semantically equivalent block-local precheck for the covered pattern.

## Validation Plan

### Functional checks

- asm samples:
  - `mcopy.evm.hex`
  - `log_all.evm.hex`
  - `simple_erc20.evm.hex`

### Structural checks

Use existing block-level instrumentation to confirm:

- lower `need_expand_cfg` on covered blocks
- unchanged helper-mixed block behavior
- no unexpected `reload_mem_size` increase

### Benchmark checks

Target:

- `grow_memory_with_mload`
- `grow_memory_with_mstore`

## Risks

### Risk 1: Incorrect gas / growth semantics

Mitigation:

- keep prototype scope small
- reuse existing `expandMemoryIR()` logic shape as much as possible
- compare against the original path with instrumentation and tests

### Risk 2: Over-generalizing block eligibility

Mitigation:

- first prototype only covers pure direct-memory blocks
- helper-heavy blocks stay on the old path

### Risk 3: Review and merge risk

Mitigation:

- keep the first patch small and local
- avoid runtime / backend changes
- retain instrumentation to explain the optimization boundary
