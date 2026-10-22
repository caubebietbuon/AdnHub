"""Phase21 typed directory correction and closure scope/lifetime obligations.

Offline data transformations only. No Lua, factories, __index, application calls
or networking. Repairing an analyst's reader selection is not a payload repair.
"""
import argparse
import json
from pathlib import Path
import struct
import tempfile

import obligation_resolver as phase14
from interblock_auditor import DIRECTORY_XOR, cluster_audit
from lazy_tracer import PRIMITIVES, inspect_reference, tag_path
from reader_tracer import custom_uint, parse_loader
from scope_tracer import instruction
from string_resolver import read_length_payload
from symbolic_resolver import PROOFS


PATCH_HEAD = 'if o==125 then local f,xJ,WJ=i[W],_(H[W],(Y(_(V,(Y(v(V,29),7))),536870911))),b[5];local bJ=_(WJ[f],306486104);WJ[f]=bJ;WJ,f=b[4],bJ+1;bJ=J(WJ,f);'
PATCH_TAIL = 'f,bJ=xJ*16843009,wJ+hJ;local jJ=bJ-hJ%4;for hJ=wJ,jJ-1,4 do M(WJ,hJ,(_(r(WJ,hJ),f)));end;for f=jJ,bJ-1,1 do L(WJ,f,(_(J(WJ,f),xJ)));end;'
CLOSE_CELL = 'xJ[6]=xJ;xJ[4]=t[f];xJ[5]=4;k[f]=nil;'
LENGTH_LEAVES = {24,55,95,98}


def source_contract(source):
    """Pin the 228/125 reader order and close-cell storage reassignment."""
    start = source.index(PATCH_HEAD)
    finish = source.index(PATCH_TAIL,start)
    if finish-start > 1500: raise ValueError('Unexpected patch reader span')
    return {'evidence':[{'offset':source.index(text),'text':text} for text in (PATCH_HEAD,PATCH_TAIL,CLOSE_CELL)],
            'directory_written_before_length_read':True,
            'payload_mask_starts_after_length_prefix':True,
            'payload_mask_changes_length_prefix':False,
            'close_cell_layout':{'slot6':'same cell object','slot4':'frame value at close','slot5':4},
            'close_semantics':'rebase shared cell storage; not deletion of all aliases',
            'actual_close_event_proved':False}


def raw_prefix(backing, position):
    """Counterfactual length read: does not claim the tag uses this format."""
    if type(position) is not int or not 0 <= position < len(backing):
        return {'status':'outside_backing','position':position}
    try:
        length, begin = custom_uint(backing,position+1)
    except ValueError as error:
        return {'status':'truncated_prefix','position':position,'error':str(error)}
    return {'status':'bounded' if length<=len(backing)-begin and length<=1048576 else 'length_out_of_bounds',
            'position':position,'length':length,'prefix_begin':position+1,
            'prefix_end':begin,'prefix_hex':backing[position+1:begin].hex(),
            'available_payload_bytes':len(backing)-begin,
            'scope':'raw patch-handler read; not a tag-based constant reader selection'}


def typed_probe(backing, entries, reference):
    """Select a reviewed reader by tag before interpreting payload shape."""
    if type(reference) is not int or not 1<=reference<=len(entries):
        raise ValueError('Reference outside directory')
    position = entries[reference-1]['value']
    if type(position) is not int or not 0<=position<len(backing):
        return {'reference_id':reference,'position':position,'status':'outside_backing'}
    leaf,_ = tag_path(backing[position])
    result = {'reference_id':reference,'position':position,'tag':backing[position],'leaf_state':leaf,
              'length_prefix_applicable':leaf in LENGTH_LEAVES,'byte_edits':[]}
    if leaf in PRIMITIVES:
        _,fmt,_ = PRIMITIVES[leaf]
        observation = inspect_reference(backing,entries,reference)
        return {**result,'status':'primitive_reader_selected', 'fixed_width':struct.calcsize(fmt),
                'observation':observation,'correction':'select primitive reader; do not repair a nonexistent length field'}
    if leaf in LENGTH_LEAVES:
        return {**result,'status':'length_reader_selected','prefix':raw_prefix(backing,position)}
    return {**result,'status':'unmodeled_reader_family','correction':'no speculative schema or byte edits'}


def copy_payload_patch(backing, directory_value, key):
    """Model only the source's bounded XOR write on an independent byte copy.

    This is not an activation model. Source writes its directory before a failed
    read; this transactional analysis returns no partial result on failure.
    No prefix is shortened, clamped, guessed, or included in the XOR span.
    """
    if type(key) is not int or not 0<=key<=255: raise ValueError('Expected byte key')
    if type(directory_value) is not int or not 0<=directory_value<=0xffffffff:
        raise ValueError('Expected uint32 directory value')
    position = directory_value ^ DIRECTORY_XOR
    payload, begin = read_length_payload(backing,position)
    result = bytearray(backing)
    result[begin:begin+len(payload)] = bytes(value^key for value in payload)
    if result[:begin] != backing[:begin] or result[begin+len(payload):] != backing[begin+len(payload):]:
        raise ValueError('XOR escaped its reviewed payload span')
    return bytes(result),position,{'write_range_half_open':[begin,begin+len(payload)],
        'prefix_preserved':True,'activation_proved':False,'input_mutated':False}


def directory_audit(backing, entries, reference):
    value = entries[reference-1]['value']
    parity = []
    for toggles in range(3):
        position = value ^ (DIRECTORY_XOR if toggles%2 else 0)
        view = list(entries)
        view[reference-1] = {'value':position}
        parity.append({'hypothetical_toggle_count':toggles,'position':position,
                       'typed_view':typed_probe(backing,view,reference),'raw_patch_prefix':raw_prefix(backing,position)})
    attempts = []
    for name,before in (('unchanged_directory',value),('hypothetical_prior_toggle',value^DIRECTORY_XOR)):
        try:
            _,after,proof = copy_payload_patch(backing,before,0)
            attempts.append({'context':name,'normal_patch_length_contract':True,'after':after,**proof})
        except ValueError as error:
            attempts.append({'context':name,'normal_patch_length_contract':False,'error':str(error),
                             'key_independent_failure':True})
    return {'reference_id':reference,'parity_cases':parity,'patch_attempts':attempts,
            'interpretation_correction':parity[0]['typed_view'],
            'byte_repair_supported':False,'byte_edits':[],
            'state_equations_unblocked':False,
            'reason':'reader selection and source patch preconditions are separate; no independent replacement-length proof'}


def lifetime_audit(bindings, trace, candidates, criteria):
    """Right-censored register intervals and frame-scoped captured body edges.

    Containment of construction steps does not imply lexical function nesting.
    A copied body reference is not an invocation or a parent-child prototype.
    """
    children = (567,258,379,663)
    rows, intervals, body_edges = [], [], []
    for child in children:
        binding = next(row for row in bindings if row['child']==child)
        definitions = [(step,event,write) for step,event in enumerate(trace)
                       for write in event.get('register_writes',[]) if type(write['value']) is dict
                       and write['value'].get('symbolic_closure')==child
                       and write['value'].get('creation_pc')==binding['pc']]
        creations = [row for row in definitions if row[1]['pc']==binding['pc']]
        if len(creations)!=1: raise ValueError('Ambiguous closure construction')
        start,event,write = creations[0]
        register = write['register']
        overwrites = [(step,later) for step,later in enumerate(trace) if step>start
                      and any(w['register']==register for w in later.get('register_writes',[]))]
        end = overwrites[0][0] if overwrites else len(trace)
        intervals.append({'child':child,'body_register':register,'start_step':start,'end_step_exclusive':end,
                          'end_reason':'observed register overwrite' if overwrites else 'right-censored at analysis frontier',
                          'register_interval_is_cell_lifetime':False})
        live = {}
        for earlier in trace[:start]:
            for definition in earlier.get('register_writes',[]): live[definition['register']] = definition['value']
        capture_cells = []
        for ordinal,capture in enumerate(binding['captures'],1):
            identity = capture.get('cell_identity')
            if identity is None: continue
            parts = identity.split(':')
            if len(parts)!=4 or parts[0]!='frame' or parts[2]!='register': raise ValueError('Unreviewed cell identity')
            frame,slot = int(parts[1]),int(parts[3])
            # Equal-numbered registers in another frame are not the same cell.
            value = live.get(slot) if frame==binding['parent'] else None
            capture_cells.append({'ordinal':ordinal,'cell':identity,'frame':frame,'register':slot})
            if type(value) is dict and type(value.get('symbolic_closure')) is int:
                body_edges.append({'holder':child,'target_body':value['symbolic_closure'],
                    'capture_ordinal':ordinal,'cell':identity,'holder_creation_pc':binding['pc'],
                    'relation':'captures cell containing a closure body on guarded construction path',
                    'is_lexical_parent_edge':False,'is_activation_edge':False})
        existing = next(row for row in criteria if row['child']==child)
        proof = {name:existing['proofs'].get(name) is True for name in PROOFS}
        candidate = next((row for row in candidates if row['owner']==child),None)
        rows.append({'child':child,'constructing_frame':binding['parent'],'construction_pc':binding['pc'],
                     'capture_cells':capture_cells,'criteria':proof,
                     'failed_or_unproved':[key for key,value in proof.items() if not value],
                     'child_entry_frontier':candidate['analysis']['pc'] if candidate else None,
                     'activation_verified':False,'close_reachability_verified':False,
                     'all_alias_effects_verified':False,'lifetime_verified':False,'promotion_admissible':False})
    return {'closures':rows,'body_register_intervals':intervals,'captured_body_edges':body_edges,
            'scope_conclusion':'all four constructed in guarded root664 frame; body aliases do not prove lexical nesting',
            'formal_promotion_patch':{'applicable':False,'operations':[]},'verified_hierarchy':None}


def run(source, data, output):
    target = output/'reader-scope-proofs.json'
    if output.resolve() in (source.resolve(),data.resolve()) or target.resolve() in (source.resolve(),data.resolve()):
        raise ValueError('Output aliases input')
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        report = phase14.run(source,data,root/'phase14',include_analysis_arrays=True)
        from reconstructor import run as reconstruct
        reconstruct(source,data,root/'backing',[664])
        backing = (root/'backing/record-664.backing-postfill.bin').read_bytes()
    contracts = source_contract(source.read_text(encoding='ascii'))
    loader = parse_loader(data.read_bytes())
    entries = loader['lookup_entries']
    if entries[100]['value'] != 134543: raise ValueError('Reviewed reference101 position changed')
    if instruction(report['analysis_arrays']['664'],978,228)!=(125,101,53,109):
        raise ValueError('Reviewed patch978 slot changed')
    trace = report['root_analysis']['trace']
    result = {'source_sha256':report['source_sha256'],'data_sha256':report['data_sha256'],
              'source_contract':contracts,'directory101':directory_audit(backing,entries,101),
              'shared_V_result':{'key_relation':'key74 = key101 XOR49 under same uint32 V and byte-key contracts',
                  'new_keys_promoted':[],'unblocked':False,'reason':'patch978 reader fails before its payload XOR'},
              'cluster':lifetime_audit(report['guarded_closure_bindings'],trace,report['candidate_entry_analyses'],
                                      report['structural_hierarchy_candidates']),
              'root107':cluster_audit(report['guarded_closure_bindings'],report['capture_frame_constraints'],
                                      trace,report['candidate_entry_analyses']),
              'frontier_call':report['fused_call_frontier'],'verified_hierarchy':None,
              'network_requests':0,'factory_invocations':0,'application_calls_executed':0,'input_byte_edits':0}
    output.mkdir(parents=True,exist_ok=True)
    target.write_text(json.dumps(result,indent=2,allow_nan=False)+'\n',encoding='utf-8')
    return result


if __name__=='__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=Path('output/stage1-vm-source.lua.txt'))
    parser.add_argument('--data',type=Path,default=Path('output/stage1-vm-data.bin'))
    parser.add_argument('--output',type=Path,default=Path('output/phase21'))
    args = parser.parse_args()
    result = run(args.source,args.data,args.output)
    print('Corrected reader:',result['directory101']['interpretation_correction']['status'])
    print('Payload byte repairs:',result['input_byte_edits'])
