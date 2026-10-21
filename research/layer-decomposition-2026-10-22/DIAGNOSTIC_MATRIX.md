# Prototype diagnostic matrix

PASS is scoped evidence; UNKNOWN means not proved, not an observed failure.
The historical six-proof validator is unchanged. Coverage is global; cycle checks cover the enumerated graph only.

| Pair | capture_bounds | upvalue_mappings | child_headers | control_flow | coverage | cycle_checks |
| --- | --- | --- | --- | --- | --- | --- |
| 137→747 | PASS | PASS | UNKNOWN | FAIL | FAIL | PASS |
| 237→572 | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | FAIL | PASS |
| 664→258 | PASS | PASS | PASS | PASS | FAIL | PASS |
| 664→379 | PASS | PASS | PASS | PASS | FAIL | PASS |
| 664→506 | PASS | UNKNOWN | UNKNOWN | UNKNOWN | FAIL | PASS |
| 664→567 | PASS | PASS | PASS | PASS | FAIL | PASS |
| 664→663 | PASS | PASS | PASS | PASS | FAIL | PASS |
| 704→288 | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | FAIL | PASS |

## 137→747

- capture_bounds: **PASS** — local indices fit allocation hint, or descriptor empty. Scope: descriptor and proposed frame only; allocation fit is not ownership.
- upvalue_mappings: **PASS** — empty capture list. Scope: descriptor schema.
- child_headers: **UNKNOWN** — layout hypothesis/source mask alone does not prove live selection/cache identity. Scope: candidate bytes.
- control_flow: **FAIL** — projected normal prefix refuted at29 under reviewed contracts. Scope: guarded prefix; no unconditional activation claim.
- coverage: **FAIL** — 35 expected nodes absent from candidate root reachability. Scope: global candidate graph, not a local claim that this edge is invalid.
- cycle_checks: **PASS** — no cycles in enumerated candidates. Scope: enumerated graph only; unseen links are unknown.

## 237→572

- capture_bounds: **UNKNOWN** — enclosing capture bounds missing. Scope: descriptor and proposed frame only; allocation fit is not ownership.
- upvalue_mappings: **UNKNOWN** — no observed owner-to-capture binding. Scope: descriptor schema.
- child_headers: **UNKNOWN** — layout hypothesis/source mask alone does not prove live selection/cache identity. Scope: candidate bytes.
- control_flow: **UNKNOWN** — site not reached before recorded frontier. Scope: guarded prefix; no unconditional activation claim.
- coverage: **FAIL** — 35 expected nodes absent from candidate root reachability. Scope: global candidate graph, not a local claim that this edge is invalid.
- cycle_checks: **PASS** — no cycles in enumerated candidates. Scope: enumerated graph only; unseen links are unknown.

## 664→258

- capture_bounds: **PASS** — local indices fit allocation hint, or descriptor empty. Scope: descriptor and proposed frame only; allocation fit is not ownership.
- upvalue_mappings: **PASS** — capture ordinals map to recorded frame cells. Scope: guarded binding.
- child_headers: **PASS** — child header read with path-local key at guarded constructor transfer. Scope: guarded prefix.
- control_flow: **PASS** — source transfer observed. Scope: guarded prefix; no unconditional activation claim.
- coverage: **FAIL** — 35 expected nodes absent from candidate root reachability. Scope: global candidate graph, not a local claim that this edge is invalid.
- cycle_checks: **PASS** — no cycles in enumerated candidates. Scope: enumerated graph only; unseen links are unknown.

## 664→379

- capture_bounds: **PASS** — local indices fit allocation hint, or descriptor empty. Scope: descriptor and proposed frame only; allocation fit is not ownership.
- upvalue_mappings: **PASS** — capture ordinals map to recorded frame cells. Scope: guarded binding.
- child_headers: **PASS** — child header read with path-local key at guarded constructor transfer. Scope: guarded prefix.
- control_flow: **PASS** — source transfer observed. Scope: guarded prefix; no unconditional activation claim.
- coverage: **FAIL** — 35 expected nodes absent from candidate root reachability. Scope: global candidate graph, not a local claim that this edge is invalid.
- cycle_checks: **PASS** — no cycles in enumerated candidates. Scope: enumerated graph only; unseen links are unknown.

## 664→506

- capture_bounds: **PASS** — local indices fit allocation hint, or descriptor empty. Scope: descriptor and proposed frame only; allocation fit is not ownership.
- upvalue_mappings: **UNKNOWN** — no observed owner-to-capture binding. Scope: descriptor schema.
- child_headers: **UNKNOWN** — layout hypothesis/source mask alone does not prove live selection/cache identity. Scope: candidate bytes.
- control_flow: **UNKNOWN** — site not reached before recorded frontier. Scope: guarded prefix; no unconditional activation claim.
- coverage: **FAIL** — 35 expected nodes absent from candidate root reachability. Scope: global candidate graph, not a local claim that this edge is invalid.
- cycle_checks: **PASS** — no cycles in enumerated candidates. Scope: enumerated graph only; unseen links are unknown.

## 664→567

- capture_bounds: **PASS** — local indices fit allocation hint, or descriptor empty. Scope: descriptor and proposed frame only; allocation fit is not ownership.
- upvalue_mappings: **PASS** — capture ordinals map to recorded frame cells. Scope: guarded binding.
- child_headers: **PASS** — child header read with path-local key at guarded constructor transfer. Scope: guarded prefix.
- control_flow: **PASS** — source transfer observed. Scope: guarded prefix; no unconditional activation claim.
- coverage: **FAIL** — 35 expected nodes absent from candidate root reachability. Scope: global candidate graph, not a local claim that this edge is invalid.
- cycle_checks: **PASS** — no cycles in enumerated candidates. Scope: enumerated graph only; unseen links are unknown.

## 664→663

- capture_bounds: **PASS** — local indices fit allocation hint, or descriptor empty. Scope: descriptor and proposed frame only; allocation fit is not ownership.
- upvalue_mappings: **PASS** — capture ordinals map to recorded frame cells. Scope: guarded binding.
- child_headers: **PASS** — child header read with path-local key at guarded constructor transfer. Scope: guarded prefix.
- control_flow: **PASS** — source transfer observed. Scope: guarded prefix; no unconditional activation claim.
- coverage: **FAIL** — 35 expected nodes absent from candidate root reachability. Scope: global candidate graph, not a local claim that this edge is invalid.
- cycle_checks: **PASS** — no cycles in enumerated candidates. Scope: enumerated graph only; unseen links are unknown.

## 704→288

- capture_bounds: **UNKNOWN** — enclosing capture bounds missing. Scope: descriptor and proposed frame only; allocation fit is not ownership.
- upvalue_mappings: **UNKNOWN** — no observed owner-to-capture binding. Scope: descriptor schema.
- child_headers: **UNKNOWN** — layout hypothesis/source mask alone does not prove live selection/cache identity. Scope: candidate bytes.
- control_flow: **UNKNOWN** — site not reached before recorded frontier. Scope: guarded prefix; no unconditional activation claim.
- coverage: **FAIL** — 35 expected nodes absent from candidate root reachability. Scope: global candidate graph, not a local claim that this edge is invalid.
- cycle_checks: **PASS** — no cycles in enumerated candidates. Scope: enumerated graph only; unseen links are unknown.
