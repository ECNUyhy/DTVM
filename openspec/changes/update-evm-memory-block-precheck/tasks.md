## 1. Implementation

- [x] 1.1 Define the exact first-wave eligible block pattern for block-local precheck
  - Implemented as a conservative constant-address pure direct-memory block pattern
- [x] 1.2 Add a builder-side block summary structure for prototype eligibility and max required size computation
- [x] 1.3 Implement a minimal block-local precheck / pre-expand path for eligible pure direct-memory blocks
  - Current prototype only covers constant-address `MLOAD` / `MSTORE` / `MSTORE8`
- [x] 1.4 Preserve memory expansion gas semantics and overflow handling for the covered cases
  - Verified on covered asm samples by comparing execution output
- [x] 1.5 Keep helper-mixed blocks on the original path

## 2. Validation

- [x] 2.1 Verify asm sample behavior on:
  - `tests/evm_asm/mcopy.evm.hex`
  - `tests/evm_asm/log_all.evm.hex`
  - `tests/evm_asm/simple_erc20.evm.hex`
- [x] 2.2 Re-run block-level instrumentation and compare:
  - `expand_calls`
  - `need_expand_cfg`
  - `get_mem_ptr`
  - `reload_mem_size`
- [x] 2.3 Run target memory benchmarks or equivalent benchmark entry points for:
  - `grow_memory_with_mload`
  - `grow_memory_with_mstore`
  - Structural validation completed; current prototype does not yet cover these dynamic-address patterns

## 3. Documentation

- [x] 3.1 Update `yhy_notes/P1.2_memory/week2_work.md` with:
  - exact code changes
  - verification commands
  - before/after analysis
  - residual risks
- [x] 3.2 Summarize the first prototype scope and why helper-heavy cases remain excluded
