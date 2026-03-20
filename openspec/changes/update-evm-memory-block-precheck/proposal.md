# Update EVM JIT Block-Local Memory Precheck

## Summary
Introduce a minimal block-local memory precheck optimization for EVM multipass JIT. The first iteration only targets a very narrow subset of pure direct-memory basic blocks: constant-address `MLOAD` / `MSTORE` / `MSTORE8` straight-line blocks with at least two covered ops. The goal is to reduce repeated frontend-generated memory expansion checks without changing runtime helper semantics.

## Motivation
Week 1 and Week 2 analysis confirmed that the primary P1.2 bottleneck is not the absence of direct pointer access, but the conservative memory-check structure generated in the EVM frontend:

- `handleMLoad()`, `handleMStore()`, `handleMStore8()`, and `handleMCopy()` each independently generate `expandMemoryIR(...)`
- `expandMemoryIR(...)` creates per-op CFG for:
  - overflow guard
  - `NeedExpand` compare
  - `ExpandBB / ContinueBB`
  - memory expansion gas charging
- block-level instrumentation now shows that some blocks contain multiple direct memory ops with:
  - `helper_barrier = 0`
  - `direct_only_candidate = 1`
  - dense `expand_calls` / `need_expand_cfg`

The analysis also shows that helper-heavy blocks (`LOG*`, `KECCAK256`, `*COPY`, `CALL*`, `CREATE*`) should not be the first optimization target because they introduce `reloadMemorySizeFromInstance()` pressure and harder state-consistency constraints.

## Goals
- Add a minimal block-local precheck path for a small class of pure direct-memory blocks
- Preserve EVM execution semantics, gas charging order, and memory growth behavior
- Reuse existing `EVMAnalyzer` / visitor block boundaries rather than introducing a new CFG pass
- Validate the prototype on `memory_grow_mload` / `memory_grow_mstore`-relevant patterns and existing asm samples
- Produce benchmark- and paper-friendly evidence for P1.2

## Non-Goals
- Cross-block or loop-level hoisting in the first iteration
- Helper-family optimization (`LOG*`, `KECCAK256`, `*COPY`, `CALL*`, `CREATE*`)
- Runtime `expandMemory*()` redesign
- Guard page implementation
- Aggressive `MemoryBaseVar` caching
- Backend/x86 lowering changes

## Why
The current evidence supports a constrained first prototype:

1. The most stable first-wave candidates are pure direct-memory blocks with multiple direct ops and no helper barrier.
2. These blocks are common enough to matter:
   - `mcopy.evm.hex`
   - several `simple_erc20.evm.hex` blocks
3. They isolate the core P1.2 issue:
   - repeated frontend-generated `NeedExpand` CFG
   - repeated `getMemoryDataPointer()` in the same straight-line region
4. This scope is small enough to be:
   - code-reviewable
   - benchmarkable
   - explainable in a paper story

## What Changes
This proposal introduces a small-scope optimization prototype in the EVM multipass frontend:

### Core behavior
1. Detect a narrow class of pure direct-memory blocks
2. Compute a block-local maximum required memory size for that class
3. Emit a single block-local precheck / pre-expand sequence before the eligible direct memory ops
4. Avoid emitting redundant per-op `NeedExpand` CFG for the covered ops

### Eligible first-wave block shape
- Basic block scope only
- `helper_barrier = 0`
- direct memory family limited to:
  - `MLOAD`
  - `MSTORE`
  - `MSTORE8`
- each covered direct-memory address must be compile-time constant in the local abstract stack scan
- at least two direct memory ops

### Expected impact
- Reduce repeated `expandMemoryIR()`-generated CFG in straight-line memory-heavy code
- Improve `memory_grow_*`-style benchmark behavior
- Provide concrete before/after data for P1.2 engineering and paper material

## Impact
- Affected specs:
  - `evm-jit`
- Affected code:
  - `src/action/evm_bytecode_visitor.h`
  - `src/compiler/evm_frontend/evm_mir_compiler.h`
  - `src/compiler/evm_frontend/evm_mir_compiler.cpp`
  - related benchmark / validation notes under `yhy_notes/P1.2_memory/`

## Approval Gate Note
This change moves beyond analysis-only instrumentation into real optimization behavior. It should be approved before implementation proceeds.
