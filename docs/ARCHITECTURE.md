# NexaPack Architecture

## Design principles
- Independent architecture (not a UPX fork or rename).
- Modular: codec, format handler, runtime stub, planner, protection each have
  explicit interfaces and can be swapped.
- CLI and GUI share one core library; no duplicated compression logic.
- No default temporary executable extraction; runtime reconstructs the image in
  memory.
- Versioned, explicitly-serialized on-disk metadata (no compiler struct packing).

## Module status
See `AGENTS.md` for the per-module status list.

## Phase gates
The project follows the directive's Phase 0–Phase 10 roadmap with strict test
gates before advancing to the next phase.
