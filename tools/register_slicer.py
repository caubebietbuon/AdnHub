"""Bounded backward slices over recorded trace order, not numeric PC order.

Whitelist-only SSA for data provenance. Unknown writes kill prior definitions.
Capture cell identities are addresses, never implicit parent-value reads.
"""


class RegisterSlicer:
    def __init__(self, owner, trace):
        if len(trace) > 10000: raise ValueError("Slice trace exceeds limit")
        self.owner, self.trace = owner, trace
        self.nodes, self.before = [], []
        self.registers, self.states, self.absent = {}, {}, {}
        if trace:
            for word, value in zip(("V", "y"), trace[0]["state_words_before"]):
                self.states[word] = self.node("header_word", value=value, word=word)
        for index, event in enumerate(trace):
            for word, observed in zip(("V", "y"), event["state_words_before"]):
                node = self.nodes[self.states[word]]
                if node.get("constant", node.get("observed")) != observed:
                    self.states[word] = self.node("unmodeled_state_boundary", observed=observed,
                                                 step=index, pc=event["pc"], word=word)
            regs, states = dict(self.registers), dict(self.states)
            self.before.append((regs, states))
            for write in event.get("register_writes", []):
                register = write["register"]
                expression = self.expression(event, register, regs, states)
                expression.update(step=index, pc=event["pc"], register=register)
                identity = self.node(**expression)
                derived = self.nodes[identity].get("constant")
                # Known arithmetic/copy provenance must agree with the forward
                # model; unknown symbolic values are not promoted from logs.
                if type(derived) is int and (type(write["value"]) is not int or derived != write["value"]):
                    raise ValueError(f"Forward/backward value mismatch at {event['pc']}")
                self.registers[register] = identity
            if "state_word_write" in event:
                write = event["state_word_write"]
                if (event["variant"], event["opcode"], write["word"]) != (228, 132, "y"):
                    raise ValueError("Unreviewed state transfer")
                self.states["y"] = self.node("copy", deps=[self.reg(regs, write["source_register"])],
                    step=index, pc=event["pc"], word="y", observed=write["value"])

    def node(self, op, deps=(), **metadata):
        if len(self.nodes) >= 50000: raise ValueError("Slice node budget exhausted")
        result = {"id": len(self.nodes), "op": op, "deps": list(deps), **metadata}
        values = [self.nodes[dep].get("constant") for dep in deps]
        if op in ("literal", "header_word", "decoded_constant") and type(metadata.get("value")) is int:
            result["constant"] = metadata["value"]
        elif op == "copy" and values and type(values[0]) is int:
            result["constant"] = values[0]
        elif op in ("add", "subtract", "xor") and len(values) == 2 and all(type(value) is int for value in values):
            value = values[0] + values[1] if op == "add" else values[0] - values[1] if op == "subtract" else values[0] ^ values[1]
            if (op == "xor" and all(0 <= n <= 0xffffffff for n in values)) or (op in ("add", "subtract") and max(abs(n) for n in (*values, value)) <= 2**53):
                result["constant"] = value
        self.nodes.append(result)
        return result["id"]

    def reg(self, registers, index):
        if index not in registers:
            if index not in self.absent:
                self.absent[index] = self.node("absent_frame_entry", register=index,
                                              type_contract="nil in reviewed fresh frame; never numeric zero")
            return self.absent[index]
        return registers[index]

    def expression(self, event, destination, regs, states):
        variant, opcode = event["variant"], event["opcode"]
        a, b, c = event["operand1"], event["H"], event["operand3"]
        def copy(register): return {"op": "copy", "deps": [self.reg(regs, register)]}
        def literal(value): return {"op": "literal", "value": value}
        def add(register, value):
            return {"op": "add", "deps": [self.reg(regs, register), self.node("literal", value=value)]}
        if "symbolic_closure_creation" in event:
            return {"op": "closure_binding", **event["symbolic_closure_creation"],
                    "capture_semantics": "cell identity is not its mutable value"}
        if variant == 157:
            if opcode == 69: return literal(b)
            if opcode == 34: return copy(b)
            if opcode == 84: return copy(a if destination == b else c)
            if opcode == 73: return {"op": "argument", "ordinal": destination - c + 1}
            if opcode == 44: return {"op": "capture_cell_address", "ordinal": b}
        elif variant == 163:
            if opcode == 62: return literal(a)
            if opcode == 147: return copy(b)
            if opcode == 109: return copy(a if destination == c else b)
            if opcode == 83: return add(a, b)
            if opcode == 17: return {"op": "decoder_context"}
            if opcode == 22: return {"op": "capture_cell_value", "ordinal": b}
        elif variant == 228:
            if opcode in (97,98,140) and 'checkpoint_arithmetic' in event:
                observation=event['checkpoint_arithmetic']['primitive']
                constant=self.node('decoded_constant',value=observation['value'],reference_id=observation['reference_id'],
                    premise='reviewed primitive in guarded effective directory/cache context') if observation else None
                if opcode in (97,98) and constant is None:
                    return {'op':'opaque_write','reason':'missing checkpoint primitive provenance'}
                if opcode==97: return {'op':'add','deps':[constant,self.node('literal',value=c)]}
                if opcode==98: return {'op':'subtract','deps':[self.reg(regs,a),constant]}
                return {'op':'subtract','deps':[self.node('literal',value=c),self.reg(regs,a)]}
            if opcode == 75: return {'op':'capture_cell_value','ordinal':a}
            if opcode == 31: return copy(b)
            if opcode == 23: return copy(a if destination == c else b)
            if opcode == 139: return literal(c)
            if opcode == 134: return literal(a if destination == c else b)
            if opcode == 21: return add(a, b)
            if opcode == 122: return {"op": "add", "deps": [self.reg(regs, a), self.reg(regs, b)]}
            if opcode == 56: return {"op": "copy", "deps": [states["y"]]}
            if opcode == 142 and "constant_inputs" in event:
                return {"op": "xor", "deps": [self.node("decoded_constant", value=row["value"],
                    reference_id=row["reference_id"], premise="pinned primitive reader observation") for row in event["constant_inputs"]]}
            if opcode == 131: return {"op": "context_slot", "slot": b}
            if opcode == 111: return {"op": "environment_read", "reference_id": c}
            if opcode == 95: return {"op": "field_read", "deps": [self.reg(regs, c)], "key_reference": a}
            if opcode == 114: return {"op": "lazy_constant", "reference_id": b}
            if opcode == 149: return {"op": "fresh_table", "allocation_pc": event["pc"]}
        return {"op": "opaque_write", "variant": variant, "opcode": opcode}

    def slice(self, register=None, word=None, before_step=None):
        if (register is None) == (word is None): raise ValueError("Select register or state word")
        if before_step is None:
            regs, states = self.registers, self.states
        else:
            if type(before_step) is not int or not 0 <= before_step < len(self.before):
                raise ValueError("Slice step outside recorded prefix")
            regs, states = self.before[before_step]
        root = states[word] if word is not None else self.reg(regs, register)
        pending, selected = [root], set()
        while pending:
            identity = pending.pop()
            if identity in selected: continue
            selected.add(identity)
            pending.extend(self.nodes[identity]["deps"])
        nodes = [self.nodes[identity] for identity in sorted(selected)]
        return {"owner": self.owner, "root_node": root, "register": register, "word": word,
                "before_trace_step": before_step, "constant": self.nodes[root].get("constant"),
                "nodes": nodes, "unresolved_leaves": [node["id"] for node in nodes
                    if not node["deps"] and "constant" not in node],
                "scope": "recorded path only; not a reaching-definition proof at an unvisited PC"}
