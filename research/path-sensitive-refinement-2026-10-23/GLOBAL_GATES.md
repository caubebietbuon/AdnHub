# Phase31 global gate matrix

All19 remain UNDERCONSTRAINED. Missing evidence is unknown, not false.
Local helper/route coverage does not supply these global requirements.

| Global gate | Status | Unproved requirements |
| --- | --- | --- |
| activation:arguments_valid/incoming_arity_and_values | UNDERCONSTRAINED | actual663-invocation, incoming-argument-values |
| activation:arguments_valid/incoming_type_predicates | UNDERCONSTRAINED | incoming-argument-values, incoming-type-proof |
| activation:callee_identity/call_time_callee_value | UNDERCONSTRAINED | actual663-invocation, call-target-identity |
| activation:capture_cells_at_call/call_time_storage_and_values | UNDERCONSTRAINED | actual663-invocation, capture-reaching-definitions |
| activation:live_template_cache_identity/live_shared_cache_identity | UNDERCONSTRAINED | actual663-invocation, live-template-identity, complete-cache-effects |
| activation:normal_constructor_continuation/plain_context_binding | UNDERCONSTRAINED | live-context-identity |
| activation:reachable_call/incoming_call_witness | UNDERCONSTRAINED | actual663-invocation, call-target-identity |
| activation:reachable_call/incoming_path_predicates | UNDERCONSTRAINED | actual663-invocation, entry-control-predicates |
| lifetime:all_alias_writes_covered/escaping_and_future_alias_writes | UNDERCONSTRAINED | complete-alias-effects, complete-path-coverage |
| lifetime:call_time_capture_values_accounted_for/all_reaching_call_definitions | UNDERCONSTRAINED | actual663-invocation, capture-reaching-definitions, complete-path-coverage |
| lifetime:close_or_rebind_paths_covered/all_exit_reachability | UNDERCONSTRAINED | complete-path-coverage, exit-outcome-proof |
| lifetime:escape_effects_covered/all_call_outcomes | UNDERCONSTRAINED | complete-path-coverage, callee-results-and-effects |
| lifetime:storage_identity_at_call/close_rebase_at_call | UNDERCONSTRAINED | actual663-invocation, all-close-rebind-effects |
| structural:ancestry_unconditional/all_lexical_owners | UNDERCONSTRAINED | complete-owner-inventory, unique-owner-proof |
| structural:child_header_verified/template_at_invocation | UNDERCONSTRAINED | actual663-invocation, live-template-identity |
| structural:control_flow_verified/entry_call_path | UNDERCONSTRAINED | actual663-invocation, entry-control-predicates |
| tree:complete_node_coverage/full_reachable_inventory | UNDERCONSTRAINED | complete-owner-inventory, complete-path-coverage |
| tree:cycle_free_verified_edges/all_verified_edges_complete | UNDERCONSTRAINED | complete-owner-inventory, complete-path-coverage, verified-edge-inventory |
| tree:unique_incoming_owner/all_owners_excluded | UNDERCONSTRAINED | complete-owner-inventory, unique-owner-proof |
