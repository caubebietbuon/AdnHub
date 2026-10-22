# Automated gate-certificate queries

Both positive and negative queries being SAT means the evidence formula is underconstrained. These are logical valuations, not runtime witnesses.

| Gate | Result | Positive query | Negative query |
| --- | --- | --- | --- |
| activation:arguments_valid/incoming_arity_and_values | UNDERCONSTRAINED | SAT | SAT |
| activation:arguments_valid/incoming_type_predicates | UNDERCONSTRAINED | SAT | SAT |
| activation:callee_identity/call_time_callee_value | UNDERCONSTRAINED | SAT | SAT |
| activation:capture_cells_at_call/call_time_storage_and_values | UNDERCONSTRAINED | SAT | SAT |
| activation:live_template_cache_identity/live_shared_cache_identity | UNDERCONSTRAINED | SAT | SAT |
| activation:normal_constructor_continuation/plain_context_binding | UNDERCONSTRAINED | SAT | SAT |
| activation:reachable_call/incoming_call_witness | UNDERCONSTRAINED | SAT | SAT |
| activation:reachable_call/incoming_path_predicates | UNDERCONSTRAINED | SAT | SAT |
| lifetime:all_alias_writes_covered/escaping_and_future_alias_writes | UNDERCONSTRAINED | SAT | SAT |
| lifetime:call_time_capture_values_accounted_for/all_reaching_call_definitions | UNDERCONSTRAINED | SAT | SAT |
| lifetime:close_or_rebind_paths_covered/all_exit_reachability | UNDERCONSTRAINED | SAT | SAT |
| lifetime:escape_effects_covered/all_call_outcomes | UNDERCONSTRAINED | SAT | SAT |
| lifetime:storage_identity_at_call/close_rebase_at_call | UNDERCONSTRAINED | SAT | SAT |
| structural:ancestry_unconditional/all_lexical_owners | UNDERCONSTRAINED | SAT | SAT |
| structural:child_header_verified/template_at_invocation | UNDERCONSTRAINED | SAT | SAT |
| structural:control_flow_verified/entry_call_path | UNDERCONSTRAINED | SAT | SAT |
| tree:complete_node_coverage/full_reachable_inventory | UNDERCONSTRAINED | SAT | SAT |
| tree:cycle_free_verified_edges/all_verified_edges_complete | UNDERCONSTRAINED | SAT | SAT |
| tree:unique_incoming_owner/all_owners_excluded | UNDERCONSTRAINED | SAT | SAT |

Candidate-specific query, conditional on the projected path:
- call:8521:activates:663: REFUTED_CERTIFICATE; observed body 516.
