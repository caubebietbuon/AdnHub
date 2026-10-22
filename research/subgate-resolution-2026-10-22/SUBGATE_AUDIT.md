# Phase 27 open sub-gate audit

One proof is conditional on the construction model. None is an unconditional activation/lifetime proof.

| Predicate | Status | Still required | Rejected inference |
| --- | --- | --- | --- |
| activation:arguments_valid/incoming_arity_and_values | open_with_diagnostics | actual incoming argument tuple | the outgoing206490123 tuple belongs to a different call |
| activation:arguments_valid/incoming_type_predicates | open_with_diagnostics | source requirements for the incoming values | symbolic argument copies are not numeric/default-value proofs |
| activation:callee_identity/call_time_callee_value | open_with_diagnostics | callee reaching definition at a663 invocation | under the reviewed assertion binding, context109 is not the root85 closure value |
| activation:capture_cells_at_call/call_time_storage_and_values | open_with_diagnostics | all capture storage/value definitions reaching that invocation | frontier159/105 snapshots cannot freeze future alias values |
| activation:live_template_cache_identity/live_shared_cache_identity | open_with_diagnostics | object identity and cache effects through invocation | post-fill backing is not the saved pre-fill template |
| activation:normal_constructor_continuation/plain_context_binding | open_with_diagnostics | actual constructor decoder-context binding | alias-only source does not prove an arbitrary context object plain |
| activation:reachable_call/incoming_call_witness | open_with_diagnostics | a reachable callee resolved to663 | the root assertion frontier is not a663 call under the reviewed binding |
| activation:reachable_call/incoming_path_predicates | open_with_diagnostics | all predicates for that incoming call | falsey standard-assert case has no normal successor |
| lifetime:all_alias_writes_covered/escaping_and_future_alias_writes | open_with_diagnostics | complete escaping writer/path coverage | zero direct prefix writes does not exclude alias writes |
| lifetime:call_time_capture_values_accounted_for/all_reaching_call_definitions | open_with_diagnostics | all incoming-call definitions and epoch conditions | a sampled prefix is not the all-path reaching-definition set |
| lifetime:cell_creation_order_verified/open_cell_reuse_and_order | conditionally_proved_in_construction_model | guarded construction prefix without hidden map effects | allocation order can be proved locally without proving the full lifetime |
| lifetime:close_or_rebind_paths_covered/all_exit_reachability | open_with_diagnostics | all normal/error/nonreturn exit paths | candidate return sites are not reached-exit witnesses |
| lifetime:escape_effects_covered/all_call_outcomes | open_with_diagnostics | callee results/effects for all reachable outcomes | a normal continuation alone does not cover errors or nonreturn |
| lifetime:storage_identity_at_call/close_rebase_at_call | open_with_diagnostics | close/rebind history up to invocation | source closing preserves the same cell object and changes storage |
| structural:ancestry_unconditional/all_lexical_owners | open_with_diagnostics | complete lexical owner inventory | one observed owner cannot exclude all others |
| structural:child_header_verified/template_at_invocation | open_with_diagnostics | incoming invocation and template/cache identity | byte hash equality does not identify a live cache object |
| structural:control_flow_verified/entry_call_path | open_with_diagnostics | entry-reaching path in the same code epoch | constructor visitation is not invocation |
| tree:complete_node_coverage/full_reachable_inventory | open_with_diagnostics | complete reachable prototype inventory | hypothetical frame samples are not coverage proof |
| tree:cycle_free_verified_edges/all_verified_edges_complete | open_with_diagnostics | complete verified-edge graph | acyclic sampled edges do not prove completeness |
| tree:unique_incoming_owner/all_owners_excluded | open_with_diagnostics | global unique-parent evidence | shared descriptors/factories do not exclude competing ownership |
