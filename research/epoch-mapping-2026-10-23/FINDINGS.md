# Phase33: register-space and epoch mapping audit

Baseline: 4a7ba56. Reproduce: `python tools/epoch_mapper.py`.
Full regenerated evidence: ignored output/phase33/epoch-mapping.json plus fresh
Phase32, Phase31, upstream and forward-prefix evidence below output/phase33/.
Tracked summary.json contains pinned hashes, source offsets, mappings and gates.

## Result

No unconditional positive bridge to root V@981 was established. All 2,048
candidates and 19 UNDERCONSTRAINED gates remain; verified_hierarchy is null
and the promotion patch is false/empty. Phase32's no-meeting result concerns
an incomplete graph; it does not imply a globally absent route or the existence
of a hidden permutation. No register-index transformation is assumed to exist.

## Pinned factory subscript inventory

The lexical field interval for factory4890 is [7929,71878). The source hash is
checked before its tokens are inspected. Strings/comments do not participate
in the subscript scan. There are 1,195 register-table t[...] occurrences and
36 distinct subscript expressions:

| Syntactic category | Occurrences | Interpretation |
| --- | ---: | --- |
| Stream-derived index | 952 | Direct operand stream reads, sometimes with PC lookahead |
| Scalar index | 180 | Named slot/cursor; reaching definitions still required |
| Affine window index | 63 | T+1, T+2, T+3, I+T-1 |
| Unclassified expression | 0 | Within this lexical recognizer only |

No explicit XOR/rotation appears inside these recorded subscripts. A scalar
subscript may still have a computed or unknown definition; this inventory is
not a semantic proof that all indirect permutations are absent. Stream-role
changes and instruction normalization are not automatically transformations of
the register table or identities between separate activation frames.

The source initializes local V from W[1], y from W[2], and allocates the local
register table via the source-bound table.create helper. Four V and four y
assignment candidates read from t[operand-stream[PC]]; all eight source offsets
are retained in the report. Their existence does not prove their execution,
their numeric inputs, or their connection to the missing V@981 definition.

## A proven finite argument translation, already represented

Source alias evidence resolves K to table.move under the retained native/context
identity premises. Source93 reads the fused lookahead to determine its call
window, and source157/73 copies positional arguments to the callee's slots.
For the reviewed516 call162 into544:

    caller slot r = 24+k
    callee slot q = 31+k
    q = r+7, for 0 <= k < 2

The exact data bindings are:

| Caller definition | Callee parameter definition |
| --- | --- |
| frame516:r24@161:23:0 | frame544:r31@49:0:0 |
| frame516:r25@159:21:0 | frame544:r32@49:0:1 |

This maps argument values across two distinct frames; it does not alias their
storage or identify either frame's VM state V. It is a finite integer slot rule,
not a claim that every register globally satisfies q=r+7. The previous SSA graphs
already contain these argument dependencies. The new tool validates the exact
entry-node dependencies before adding redundant, explicitly guarded copy edges.

The finite affine fitter independently finds a=1,b=7 mod2**32 for these two
pairs. A unique fit inside a hypothesized family is not evidence that the entire
program implements that family. The rotate-left/XOR family is inconsistent for
these two pairs. Other bit permutations and nonlinear transformations remain
outside that fitter's scope. No global paired observations are available; the
global affine and rotate/XOR queries therefore remain UNDERCONSTRAINED.

The affine solver eliminates b using a reference pair: a*(x-x0) == y-y0 mod M,
M=2**width. With g=gcd(x-x0,M), a solution requires g to divide y-y0. Dividing
by g leaves an invertible coefficient modulo M/g. These moduli are powers of
two, so their residue classes intersect exactly by agreement modulo the smaller
period. Requiring odd a enforces permutation of the modular domain. This
preserves all coefficient families rather than selecting one convenient model.
For rotate/XOR, each fixed rotation determines its key from the first pair;
all remaining pairs must agree. No source-derived values are supplied to empty
observation sets, and neither fitter authorizes a new storage/epoch identity.

For258 at516 call131, the inputs are immediate/lazy constant arguments mapped
to callee20..21. No parent-register permutation can be inferred from that call.
Later helper invocations and unvisited epochs are not generalized from call162.

## State-word mixer versus register addresses

The source contains this payload-key mixer:

    masked = (V XOR ((V >> 29) AND 7)) AND 0x1fffffff

For every29-bit masked output, its exact inverse family is:

    V = (masked XOR high) OR (high << 29), 0 <= high < 8

Writing V=(high<<29)|low gives masked=low XOR high. The eight high-bit
choices produce eight distinct uint32 values; no one is chosen by default.
This is key material, not a register address. Without a same-activation transfer
from V@981 to an observed mixer output, the inverse cannot filter its candidates.

## Controlled intersection

The before/after reaching_meet queries cover three544 sinks and one258 sink.
All remain no_meeting_in_recorded_graph after the finite call-slot translation.
The known translation supplies no new missing dependency. The unvisited V@981
endpoint stays explicitly unconnected; no projection edge from the earlier
header4179906283, advanced8521 frame, or captured root107 is fabricated.
This is not a proof that the real execution has an empty intersection domain.

Remaining requirements are same-activation root arrival, intervening state-word
writes, source-backed control-flow continuation, and cache/code-epoch/alias
identity at the already refuted guarded route (notably516/30 and258/71).
Those facts must precede any global numeric filter or hierarchy promotion.

## Tools, tests and execution scope

tools/epoch_mapper.py adds exact modular-affine congruence fitting (including
noninvertible differences), bounded rotate/XOR hypothesis checking, finite
integer slot translations, the mixer inverse family, pinned lexical inventory,
and controlled SSA intersection audits. No Lua expression is evaluated.

tools/test_phase33.py exercises arithmetic against exhaustive small domains,
wraparound, conflicting samples, non-permutations, ambiguous bit patterns,
the eight inverse states, slot bounds, immutable inputs, pinned source checks,
and freshly regenerated mapping/lock integration.

All work is local static Python metadata analysis. No network, payload, Lua,
factory, __index or application execution, dependency installation or input
mutation. Demo/ESP code is untouched. Roblox runtime checks were not performed.

## Verification

All378 tests passed in370.328s:355 retained tests plus23 new Phase33 tests.
An additional exhaustive check passed131,072 four-bit two-observation affine
cases (permutation enabled and disabled). Fresh standalone regeneration,
Python compilation, `luac -p AdnHub.lua`, `luac -p Loader.lua`, and working/
staged whitespace checks passed. Changes are committed locally; no push.
