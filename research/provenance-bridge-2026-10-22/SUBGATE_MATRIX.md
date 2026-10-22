# Phase 26 closure663 sub-gate matrix

All statuses below are local observations or open proof obligations. None discharges a parent gate.

| Parent gate | Sub-gate | Status | Required predicate |
| --- | --- | --- | --- |
| structural:child_header_verified | cached_header_structure | established_local_evidence |  |
| structural:child_header_verified | template_at_invocation | open | structural:child_header_verified/template_at_invocation |
| structural:control_flow_verified | construction_visit | established_local_evidence |  |
| structural:control_flow_verified | entry_call_path | open | structural:control_flow_verified/entry_call_path |
| structural:ancestry_unconditional | capture_descriptor_identity | established_local_evidence |  |
| structural:ancestry_unconditional | all_lexical_owners | open | structural:ancestry_unconditional/all_lexical_owners |
| activation:reachable_call | incoming_call_witness | open | activation:reachable_call/incoming_call_witness |
| activation:reachable_call | incoming_path_predicates | open | activation:reachable_call/incoming_path_predicates |
| activation:callee_identity | closure_destination_definition | established_local_evidence |  |
| activation:callee_identity | call_time_callee_value | open | activation:callee_identity/call_time_callee_value |
| activation:arguments_valid | incoming_arity_and_values | open | activation:arguments_valid/incoming_arity_and_values |
| activation:arguments_valid | incoming_type_predicates | open | activation:arguments_valid/incoming_type_predicates |
| activation:capture_cells_at_call | capture_cell_addresses | established_local_evidence |  |
| activation:capture_cells_at_call | call_time_storage_and_values | open | activation:capture_cells_at_call/call_time_storage_and_values |
| activation:live_template_cache_identity | cached_header_agrees | established_local_evidence |  |
| activation:live_template_cache_identity | live_shared_cache_identity | open | activation:live_template_cache_identity/live_shared_cache_identity |
| activation:normal_constructor_continuation | alias_only_constructor_source | established_local_evidence |  |
| activation:normal_constructor_continuation | plain_context_binding | open | activation:normal_constructor_continuation/plain_context_binding |
| lifetime:cell_creation_order_verified | definitions_before_capture | established_local_evidence |  |
| lifetime:cell_creation_order_verified | open_cell_reuse_and_order | open | lifetime:cell_creation_order_verified/open_cell_reuse_and_order |
| lifetime:all_alias_writes_covered | prefix_direct_writes | established_local_evidence |  |
| lifetime:all_alias_writes_covered | escaping_and_future_alias_writes | open | lifetime:all_alias_writes_covered/escaping_and_future_alias_writes |
| lifetime:call_time_capture_values_accounted_for | frontier_capture_values | established_local_evidence |  |
| lifetime:call_time_capture_values_accounted_for | all_reaching_call_definitions | open | lifetime:call_time_capture_values_accounted_for/all_reaching_call_definitions |
| lifetime:close_or_rebind_paths_covered | source_close_contract | established_local_evidence |  |
| lifetime:close_or_rebind_paths_covered | all_exit_reachability | open | lifetime:close_or_rebind_paths_covered/all_exit_reachability |
| lifetime:storage_identity_at_call | address_binding | established_local_evidence |  |
| lifetime:storage_identity_at_call | close_rebase_at_call | open | lifetime:storage_identity_at_call/close_rebase_at_call |
| lifetime:escape_effects_covered | fused_call_result_and_effect_boundary | established_local_evidence |  |
| lifetime:escape_effects_covered | all_call_outcomes | open | lifetime:escape_effects_covered/all_call_outcomes |
| tree:unique_incoming_owner | observed_owner_occurrences | established_local_evidence |  |
| tree:unique_incoming_owner | all_owners_excluded | open | tree:unique_incoming_owner/all_owners_excluded |
| tree:complete_node_coverage | sampled_frame_inventory | established_local_evidence |  |
| tree:complete_node_coverage | full_reachable_inventory | open | tree:complete_node_coverage/full_reachable_inventory |
| tree:cycle_free_verified_edges | enumerated_graph_cycle_audit | established_local_evidence |  |
| tree:cycle_free_verified_edges | all_verified_edges_complete | open | tree:cycle_free_verified_edges/all_verified_edges_complete |
