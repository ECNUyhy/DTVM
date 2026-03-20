## ADDED Requirements

### Requirement: Block-local memory precheck for eligible direct-memory blocks
The EVM multipass JIT frontend SHALL support a minimal block-local memory precheck path for a constrained class of pure direct-memory basic blocks.

#### Scenario: Eligible pure direct-memory block
- **WHEN** a basic block contains at least two direct memory operations
- **AND** the block contains no helper-sensitive opcode barrier
- **AND** the covered operations are within the supported first-wave set
- **THEN** the frontend SHALL be allowed to emit one block-local precheck sequence instead of redundant per-op expansion-check CFG

#### Scenario: Non-eligible block falls back to original path
- **WHEN** a block contains helper-sensitive opcodes
- **OR** the block shape does not match the supported first-wave pattern
- **THEN** the frontend SHALL retain the original per-op memory expansion path

### Requirement: Block-local precheck must preserve memory semantics
The block-local precheck optimization SHALL preserve overflow handling, memory expansion gas charging, and aligned memory growth semantics for covered blocks.

#### Scenario: Covered block preserves overflow and gas behavior
- **WHEN** a block-local precheck is applied
- **THEN** overflow conditions SHALL still trap as before
- **AND** memory expansion gas SHALL be charged consistently with the original semantics
- **AND** memory growth alignment SHALL remain unchanged

### Requirement: Block-local optimization must remain observable in diagnostics
The frontend SHALL preserve enough diagnostic output to compare covered and uncovered blocks during development builds.

#### Scenario: Development logging for covered blocks
- **WHEN** multipass JIT logging is enabled in a development build
- **THEN** block-level diagnostics SHALL remain available to compare direct-memory block coverage and expansion-check density before and after optimization
