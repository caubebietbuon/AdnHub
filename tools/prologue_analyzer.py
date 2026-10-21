"""Restricted abstract interpretation of numeric initialization transforms.

No calls, Lua, factory invocation, lazy reads or application opcodes permitted.
Unknown registers stay unknown; an unsupported operation is a hard boundary.
"""
from copy import deepcopy

MASK29 = (1 << 29) - 1


def mix(word):
    return (word ^ ((word >> 29) & 7)) & MASK29


def analyze(streams, entry, first_word, second_word, budget=10000, numeric_constant=None, text_constant=None,
            symbolic_environment=False, branch_decisions=None, snapshot_pcs=(), symbolic_field_reads=False,
            patch_observer=None, track_register_writes=False, closure_builder=None, source_transfer=None):
    arrays = deepcopy(streams)
    class Registers(dict):
        event = None
        def __setitem__(self, register, value):
            super().__setitem__(register, value)
            if track_register_writes and self.event is not None:
                self.event.setdefault("register_writes", []).append({"register": register, "value": value})
    registers, trace, patches = Registers(), [], []
    heap = {}
    pc = entry
    variant = 157
    branch_decisions = branch_decisions or {}
    limit = min(len(values) for values in arrays.values())
    for _ in range(budget):
        if not 1 <= pc <= limit:
            return {"trace": trace, "patches": patches, "stop": "PC outside reviewed arrays", "pc": pc, "arrays": arrays, "heap": heap}
        ix = pc - 1
        names = {157: ("O", "j", "Z", "B"), 163: ("j", "B", "Z", "O"),
                 228: ("B", "j", "Z", "O")}.get(variant)
        if names is None:
            return {"trace": trace, "patches": patches, "stop": "unreviewed dispatch variant", "pc": pc, "arrays": arrays, "heap": heap}
        op, a, b, c = [arrays[k][ix] for k in names]
        event = {"pc": pc, "variant": variant, "opcode": op, "operand1": a, "H": b, "operand3": c}
        registers.event = event
        if track_register_writes:
            event["state_words_before"] = [first_word, second_word]
        if pc in snapshot_pcs:
            event["registers_before"] = dict(registers)
            event["state_words_before"] = [first_word, second_word]
        trace.append(event)
        if source_transfer:
            transfer = source_transfer(variant, op, a, b, c, registers, event)
            if transfer:
                if type(transfer) is dict and "next_pc" in transfer:
                    destination = transfer["next_pc"]
                    if type(destination) is not int or not 1 <= destination <= limit + 1:
                        raise ValueError("Source transfer target outside reviewed arrays")
                    pc = destination
                    continue
                advance = transfer.get("advance", 1) if type(transfer) is dict else 1
                if type(advance) is not int or not 1 <= advance <= 4:
                    raise ValueError("Source transfer advance outside reviewed range")
                pc += advance
                continue
        closure_patterns = {157: (132, c, b, a), 163: (38, b, a, c), 228: (82, b, c, a)}
        if symbolic_environment and symbolic_field_reads and closure_builder and variant in closure_patterns:
            expected, child, descriptor, destination = closure_patterns[variant]
            if op == expected:
                closure = closure_builder(child, descriptor, pc, variant, dict(registers))
                if closure is None:
                    event["closure_proof_boundary"] = {"child": child, "descriptor": descriptor}
                    break
                registers[destination] = closure
                event["symbolic_closure_creation"] = {"child": child, "descriptor": descriptor, "destination": destination}
                pc += 1
                continue
        if variant == 228:
            if op == 148 and symbolic_environment and symbolic_field_reads:
                table = registers.get(a)
                identity = table.get("fresh_plain_table") if type(table) is dict else None
                if identity not in heap or not 0 <= b <= 10000 or not 0 <= c <= 100000: break
                values = [registers.get(a + 1 + offset) for offset in range(b)]
                for offset, value in enumerate(values): heap[identity][c + 1 + offset] = value
                event["fresh_table_move"] = {"table_id": identity, "source_register_range": [a + 1, a + b + 1],
                                              "destination_range": [c + 1, c + b + 1], "values": values}
            elif op == 134 and symbolic_environment and symbolic_field_reads:
                registers[c], registers[c + 1] = a, b
            elif op == 122 and symbolic_environment and symbolic_field_reads:
                left, right = registers.get(a), registers.get(b)
                if type(left) is not int or type(right) is not int or max(abs(left), abs(right), abs(left + right)) > 2**53:
                    break
                registers[c] = left + right
                event["exact_integer_addition"] = [left, right, left + right]
            elif op == 56 and symbolic_environment and symbolic_field_reads:
                registers[b] = second_word
                event["state_word_read"] = {"destination": b, "word": "y", "value": second_word}
            elif op == 149 and symbolic_environment and symbolic_field_reads:
                identity = f"{pc}:{len(heap) + 1}"
                heap[identity] = {}
                registers[c] = {"fresh_plain_table": identity}
                event["symbolic_allocation"] = {"destination": c, "table_id": identity, "kind": "fresh plain table"}
            elif op == 95 and symbolic_environment and symbolic_field_reads:
                base = registers.get(c)
                key = text_constant(a) if text_constant else None
                registers[b] = {"index": base, "key_reference": a, "key_text": key}
                event["symbolic_field_read"] = {"destination": b, "base_register": c,
                                                 "key_reference": a, "key_text": key}
                event["normal_completion_assumption"] = "symbolic field read succeeds; no actual table or metamethod accessed"
            elif op == 111:
                event["application_boundary"] = {"operation": "environment_read",
                                                 "global_name": text_constant(c) if text_constant else None}
                if not symbolic_environment: break
                name = event["application_boundary"]["global_name"]
                if name is None: break
                registers[a] = {"symbol": "global." + name}
                event["symbolic_result"] = registers[a]
            elif op == 86:
                # Source x[Z[PC]]=O[PC]. Only the pinned decorative V field may
                # be abstracted away; no actual table write or API replacement.
                name = text_constant(b) if text_constant else None
                if name != "V": break
                event["ignored_metadata_assignment"] = name
            elif op == 142:
                left = numeric_constant(c) if numeric_constant else None
                right = numeric_constant(b) if numeric_constant else None
                if track_register_writes:
                    event["constant_inputs"] = [{"reference_id": c, "value": left}, {"reference_id": b, "value": right}]
                registers[a] = left ^ right if type(left) is int and type(right) is int else None
            elif op == 132:
                value = registers.get(b)
                if type(value) is not int: break
                second_word = value
                if track_register_writes:
                    event["state_word_write"] = {"word": "y", "source_register": b, "value": value}
            elif op in (74, 125, 100):
                key = c if op == 100 else b ^ mix(second_word if op == 74 else first_word)
                if not 0 <= key <= 255: break
                patches.append({"reference_id": a, "key": key, "pc": pc, "variant": variant,
                                "confidence": "restricted initialization data-flow equation"})
                if patch_observer and patch_observer(patches[-1]) is False: break
                arrays["B"][ix] = 70
            elif op in (129, 119):
                state = second_word ^ ((second_word >> 14) & 262143) ^ ((second_word >> 28) & 15)
                bits = (7 if a < 16384 else 14 if a < 2097152 else 21) if op == 129 else (7 if a < 2097152 else 14)
                im, hm, am, om = (55, 114, 83, 105) if op == 129 else (65, 48, 120, 66)
                arrays["j"][ix] = (a & ((1 << bits) - 1)) ^ im ^ (state & 127)
                arrays["Z"][ix] = b ^ hm ^ ((state >> 7) & 127)
                arrays["O"][ix] = c ^ am ^ ((state >> 14) & 127)
                arrays["B"][ix] = (a >> bits) ^ om ^ ((state >> 21) & 127)
                continue
            elif op in (145, 108, 197):
                state = b if op == 197 else b ^ mix(second_word if op == 145 else first_word)
                start, end = a + 1, a + c + 1
                if not 1 <= start <= end <= limit + 1: break
                for target in range(start - 1, end - 1):
                    state = (state ^ (state << 13)) & MASK29
                    state ^= state >> 13
                    state = (state ^ (state << 14)) & MASK29
                    for name, shift in (("j", 0), ("Z", 7), ("O", 14), ("B", 21)):
                        arrays[name][target] ^= (state >> shift) & 127
                arrays["B"][ix] = 70
                event["rewritten_range"] = [start, end]
            elif op == 23:
                registers[c], registers[c + 1] = registers.get(a), registers.get(b)
            elif op == 31:
                registers[c] = registers.get(b)
            elif op == 139:
                registers[a] = c
            elif op == 21:
                value = registers.get(a)
                registers[c] = value + b if type(value) is int else None
            elif op == 13:
                value = registers.get(a)
                if type(value) is not int: break
                pc = pc + 1 if value <= c else b + 1
                continue
            elif op == 14:
                left, right = registers.get(c), registers.get(b)
                if type(left) is not int or type(right) is not int: break
                pc = pc + 1 if left < right else a + 1
                continue
            elif op == 32:
                pc = a + 1
                continue
            elif op in (92, 89):
                destination = registers.get(b if op == 92 else a)
                if type(destination) is not int: break
                pc = destination + 1
                continue
            elif op != 70:
                break
            pc += 1
            continue
        if variant == 163:
            if op == 22 and symbolic_environment and symbolic_field_reads:
                registers[c] = {"symbol": f"enclosing_capture_cell[{b}].value"}
                event["normal_completion_assumption"] = "enclosing capture cell read succeeds; cell not dereferenced"
            elif op == 17 and symbolic_environment and symbolic_field_reads:
                registers[b] = {"symbol": "decoder_context"}
            elif op == 144:
                variant, pc = a, b + 1
                continue
            elif op in (84, 96, 141):
                ref = c if op == 141 else a
                key = a if op == 141 else b ^ mix(second_word if op == 84 else first_word)
                if not 0 <= key <= 255: break
                patches.append({"reference_id": ref, "key": key, "pc": pc, "variant": variant,
                                "confidence": "restricted initialization data-flow equation"})
                if patch_observer and patch_observer(patches[-1]) is False: break
                arrays["j"][ix] = 30
            elif op == 86:
                state = second_word ^ ((second_word >> 14) & 262143) ^ ((second_word >> 28) & 15)
                bits = 7 if a < 16384 else 14 if a < 2097152 else 21
                arrays["B"][ix] = (a & ((1 << bits) - 1)) ^ 44 ^ (state & 127)
                arrays["Z"][ix] = b ^ 18 ^ ((state >> 7) & 127)
                arrays["O"][ix] = c ^ 2 ^ ((state >> 14) & 127)
                arrays["j"][ix] = (a >> bits) ^ 70 ^ ((state >> 21) & 127)
                continue
            elif op == 45:
                state = second_word ^ ((second_word >> 14) & 262143) ^ ((second_word >> 28) & 15)
                bits = 7 if b < 2097152 else 14
                arrays["B"][ix] = a ^ 38 ^ (state & 127)
                arrays["Z"][ix] = (b & ((1 << bits) - 1)) ^ 91 ^ ((state >> 7) & 127)
                arrays["O"][ix] = c ^ ((state >> 14) & 127)
                arrays["j"][ix] = (b >> bits) ^ 78 ^ ((state >> 21) & 127)
                continue
            elif op in (101, 134, 52):
                state = b if op == 101 else b ^ mix(second_word if op == 134 else first_word)
                start, end = a + 1, a + c + 1
                if not 1 <= start <= end <= limit + 1: break
                for target in range(start - 1, end - 1):
                    state = (state ^ (state << 13)) & MASK29
                    state ^= state >> 13
                    state = (state ^ (state << 14)) & MASK29
                    for name, shift in (("B", 0), ("Z", 7), ("O", 14), ("j", 21)):
                        arrays[name][target] ^= (state >> shift) & 127
                arrays["j"][ix] = 30
                event["rewritten_range"] = [start, end]
            elif op == 62:
                registers[c] = a
            elif op == 147:
                registers[a] = registers.get(b)
            elif op == 109:
                registers[c], registers[c + 1] = registers.get(a), registers.get(b)
            elif op == 2:
                destination = registers.get(c)
                if type(destination) is not int: break
                pc = destination + 1
                continue
            elif op == 24:
                pc = b + 1
                continue
            elif op != 30:
                break
            pc += 1
            continue
        if op in (11, 76, 14):
            ref = c if op == 14 else a
            key = b if op == 14 else b ^ mix(second_word if op == 11 else first_word)
            if not 0 <= key <= 255: break
            patches.append({"reference_id": ref, "key": key, "pc": pc,
                            "confidence": "restricted initialization data-flow equation"})
            if patch_observer and patch_observer(patches[-1]) is False: break
            arrays["O"][ix] = 140
        elif op in (127, 33, 57):
            state = b ^ mix(second_word if op == 127 else first_word) if op != 57 else b
            start, end = a + 1, a + c + 1
            if not 1 <= start <= end <= limit + 1: break
            for target in range(start - 1, end - 1):
                state = (state ^ (state << 13)) & MASK29
                state ^= state >> 13
                state = (state ^ (state << 14)) & MASK29
                for name, shift in (("j", 0), ("Z", 7), ("B", 14), ("O", 21)):
                    arrays[name][target] ^= (state >> shift) & 127
            arrays["O"][ix] = 140
            event["rewritten_range"] = [start, end]
        elif op in (150, 134):
            state = second_word ^ ((second_word >> 14) & 262143) ^ ((second_word >> 28) & 15)
            bits = (7 if a < 16384 else 14 if a < 2097152 else 21) if op == 150 else (7 if a < 2097152 else 14)
            i_mask, h_mask, w_mask, opcode_mask = (28, 30, 82, 80) if op == 150 else (105, 58, 39, 64)
            arrays["j"][ix] = (a & ((1 << bits) - 1)) ^ i_mask ^ (state & 127)
            arrays["Z"][ix] = b ^ h_mask ^ ((state >> 7) & 127)
            arrays["B"][ix] = c ^ w_mask ^ ((state >> 14) & 127)
            arrays["O"][ix] = (a >> bits) ^ opcode_mask ^ ((state >> 21) & 127)
            continue
        elif op == 69:
            registers[a] = b
        elif op == 34:
            registers[a] = registers.get(b)
        elif op == 84:
            registers[b], registers[b + 1] = registers.get(a), registers.get(c)
        elif op == 112:
            registers[b] = None  # involves lazy j[PC], do not invoke it
            event["normal_completion_assumption"] = "opaque lazy operands have not been materialized or type-checked"
        elif op == 138:
            registers[a] = None  # local register-span packing, contents unknown
        elif symbolic_environment and op == 73:
            if not 0 <= a <= 10000: break
            for offset in range(a):
                registers[c + offset] = {"symbol": f"argument[{offset + 1}]"}
        elif symbolic_environment and op == 44:
            registers[a] = {"symbol": f"enclosing_capture_cell[{b}]"}
        elif symbolic_environment and op == 149:
            value = registers.get(c)
            registers[a] = not value if type(value) is bool else {"not": value}
        elif symbolic_environment and op in (71, 139, 99, 118):
            register = b if op in (71, 99, 118) else c
            value = registers.get(register)
            if op == 99:
                other = registers.get(a)
                condition = value < other if type(value) is int and type(other) is int else None
                true_pc, false_pc = pc + 1, c + 1
                expression = f"register[{b}] < register[{a}]"
            elif op == 118:
                condition = value != a if type(value) is int else None
                true_pc, false_pc = c + 1, pc + 1
                expression = f"register[{b}] != {a}"
            else:
                true_pc, false_pc = (pc + 1, c + 1) if op == 71 else (a + 1, b + 1)
                condition = value <= a if op == 71 and type(value) is int else value if op == 139 and type(value) is bool else None
                expression = f"register[{register}] <= {a}" if op == 71 else f"truthy(register[{register}])"
            if type(condition) is not bool:
                event["unresolved_condition"] = {"expression": expression, "value": value,
                                                  "true_pc": true_pc, "false_pc": false_pc}
                if pc not in branch_decisions: break
                condition = branch_decisions[pc]
                if type(condition) is not bool: raise ValueError("Branch decisions must be boolean constraints")
                event["assumed_branch_constraint"] = {"expression": expression, "truth": condition}
            pc = true_pc if condition else false_pc
            continue
        elif op == 80:
            # Arguments remain unknown; initialization neither calls nor inspects them.
            for reg in list(registers):
                if reg >= b: registers[reg] = None
        elif op == 129:
            pc = a + 1
            continue
        elif op == 20:
            if b not in (163, 228, 82): break
            variant, pc = b, a + 1
            continue
        elif op == 22:
            destination = registers.get(b)
            if type(destination) is not int: break
            pc = destination + 1
            continue
        elif op != 140:
            break
        pc += 1
    else:
        return {"trace": trace, "patches": patches, "stop": "initialization budget exhausted", "pc": pc, "arrays": arrays, "heap": heap}
    return {"trace": trace, "patches": patches, "stop": "unsupported or unresolved operation; application boundary", "pc": pc, "arrays": arrays, "heap": heap}
