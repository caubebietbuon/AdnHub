"""Restricted numeric/table reader IR for hash-pinned GW helpers.

Not a Lua runtime: no VM opcode handlers, application functions, dynamic
compilation, metatable execution, I/O, or arbitrary Python/Lua calls.
"""
from __future__ import annotations
from dataclasses import dataclass
import struct

import analyzer

HELPERS = set("r z M u a X s A F T B m j x c q H n G E t f C L J y e R h d Z S p _ l N Y g P b k I o GW".split())


class ModelError(ValueError): pass


class Boundary(Exception):
    def __init__(self, reason, slot=None, arguments=None, offset=None):
        self.reason, self.slot, self.arguments, self.offset = reason, slot, arguments, offset


class Returned(Exception):
    def __init__(self, values): self.values = values


class Scope:
    def __init__(self, parent=None): self.parent, self.data = parent, {}
    def get(self, key):
        if key in self.data: return self.data[key]
        if self.parent: return self.parent.get(key)
        raise ModelError(f"Unbound reader variable: {key}")
    def assign(self, key, value):
        if key in self.data: self.data[key] = value
        elif self.parent: self.parent.assign(key, value)
        else: raise ModelError(f"Nonlocal assignment denied: {key}")


@dataclass(eq=False)
class Table:
    id: int
    capacity_hint: int
    data: dict
    created_at: int
    metatable: object = None
    created_after_read: int | None = None
    first_value_read_end: int | None = None
    last_value_read_end: int | None = None


@dataclass
class Api:
    slot: int


@dataclass(eq=False)
class Opaque:
    label: str


class Parser:
    """Parse only the reader's expression/assignment/if/while/return subset."""
    PRECEDENCE = {"or": 1, "and": 2, "==": 3, "~=": 3, "<": 3, ">": 3, "<=": 3, ">=": 3,
                  "+": 4, "-": 4, "*": 5, "/": 5, "%": 5}
    def __init__(self, text, base=0):
        raw = analyzer.lex(text)
        self.tokens = []
        i = 0
        while i < len(raw):
            token = raw[i]
            if i + 1 < len(raw) and token.value + raw[i + 1].value in {"<=", ">=", "==", "~="}:
                self.tokens.append((token.value + raw[i + 1].value, base + token.start)); i += 2
            else:
                value = "<unsupported-string>" if token.kind in {"string", "long_string"} else token.value
                self.tokens.append((value, base + token.start)); i += 1
        self.tokens.append(("<eof>", base + len(text)))
        self.i = 0
    def peek(self): return self.tokens[self.i][0]
    def take(self, expected=None):
        value = self.peek()
        if expected is not None and value != expected: raise ModelError(f"Expected {expected}, got {value}")
        self.i += 1
        return value
    def expression(self, minimum=0):
        value, offset = self.tokens[self.i]
        if value in {"-", "not"}:
            self.take(); node = ("unary", value, self.expression(6), offset)
        elif value == "(":
            self.take(); node = ("group", self.expression(), offset); self.take(")")
        elif value == "{":
            self.take(); items = []
            if self.peek() != "}": items = self.expression_list()
            self.take("}"); node = ("table", items, offset)
        elif value in {"nil", "true", "false"}:
            self.take(); node = ("literal", {"nil": None, "true": True, "false": False}[value], offset)
        elif value[0].isdigit():
            self.take(); number = int(value, 0) if value.lower().startswith("0x") else float(value) if "." in value or "e" in value.lower() else int(value)
            node = ("literal", number, offset)
        elif value.isidentifier():
            self.take(); node = ("variable", value, offset)
        else: raise ModelError(f"Expression outside subset: {value}")
        while True:
            operator, at = self.tokens[self.i]
            if operator == "[":
                self.take(); key = self.expression(); self.take("]"); node = ("index", node, key, at)
            elif operator == ".":
                self.take(); name = self.take(); node = ("index", node, ("literal", name, at), at)
            elif operator == ":":
                self.take(); name = self.take(); self.take("("); args = [] if self.peek() == ")" else self.expression_list(); self.take(")")
                node = ("method", node, name, args, at)
            elif operator == "(":
                self.take(); args = [] if self.peek() == ")" else self.expression_list(); self.take(")"); node = ("call", node, args, at)
            elif operator in self.PRECEDENCE and self.PRECEDENCE[operator] >= minimum:
                self.take(); right = self.expression(self.PRECEDENCE[operator] + 1); node = ("binary", operator, node, right, at)
            else: break
        return node
    def expression_list(self):
        result = [self.expression()]
        while self.peek() == ",": self.take(); result.append(self.expression())
        return result
    def block(self):
        statements = []
        while self.peek() not in {"end", "elseif", "else", "<eof>"}:
            at = self.tokens[self.i][1]
            if self.peek() == ";": self.take(); continue
            if self.peek() == "local":
                self.take(); names = [self.take()]
                while self.peek() == ",": self.take(); names.append(self.take())
                exprs = []
                if self.peek() == "=": self.take(); exprs = self.expression_list()
                statements.append(("local", names, exprs, at))
            elif self.peek() == "if":
                self.take(); branches = []
                condition = self.expression(); self.take("then"); branches.append((condition, self.block()))
                while self.peek() == "elseif":
                    self.take(); condition = self.expression(); self.take("then"); branches.append((condition, self.block()))
                otherwise = []
                if self.peek() == "else": self.take(); otherwise = self.block()
                self.take("end"); statements.append(("if", branches, otherwise, at))
            elif self.peek() == "while":
                self.take(); condition = self.expression(); self.take("do"); body = self.block(); self.take("end")
                statements.append(("while", condition, body, at))
            elif self.peek() == "return":
                self.take(); exprs = [] if self.peek() in {"end", ";", "else", "elseif"} else self.expression_list()
                statements.append(("return", exprs, at))
            else:
                first = self.expression()
                if self.peek() in {"=", ","}:
                    targets = [first]
                    while self.peek() == ",": self.take(); targets.append(self.expression())
                    self.take("="); statements.append(("assign", targets, self.expression_list(), at))
                elif first[0] in {"call", "method"}: statements.append(("call_statement", first, at))
                else: raise ModelError("Unsupported reader statement")
        return statements
    def definition(self, name):
        self.take(name); self.take("="); self.take("function"); self.take("(")
        parameters = []
        if self.peek() != ")":
            parameters.append(self.take())
            while self.peek() == ",": self.take(); parameters.append(self.take())
        self.take(")"); body = self.block(); self.take("end")
        return parameters, body


def truth(value): return value is not None and value is not False


class ReaderModel:
    """Interpret only whitelisted reader IR operations; external calls stop."""
    def __init__(self, definitions, step_limit=16000000):
        self.definitions, self.step_limit = definitions, step_limit
        self.steps, self.tables, self.reads, self.calls = 0, [], [], {}
        self.state_hits = {}
        self.last_scope = None
        self.function_stack = []
    def tick(self):
        self.steps += 1
        if self.steps > self.step_limit: raise ModelError("Reader step budget exceeded")
    def table(self, hint=0, at=0):
        if isinstance(hint, bool) or not isinstance(hint, (int, float)) or not 0 <= hint <= 100000 or hint != int(hint): raise ModelError("Reader table bound exceeded")
        if len(self.tables) >= 10000: raise ModelError("Reader table count exceeded")
        result = Table(len(self.tables) + 1, int(hint), {}, at)
        result.created_after_read = self.reads[-1]["offset"] + self.reads[-1]["width"] if self.reads else None
        self.tables.append(result)
        return result
    def get(self, owner, key, at):
        if owner is self:
            if isinstance(key, (int, float)): return Api(int(key))
            raise Boundary("Non-reader self field lookup", key, offset=at)
        if not isinstance(owner, Table): raise ModelError(f"Index into non-table at {at}")
        if key not in owner.data and owner.metatable is not None:
            raise Boundary("Lazy metatable read denied", arguments=[owner, key], offset=at)
        return owner.data.get(key)
    def write(self, owner, key, value):
        if not isinstance(owner, Table) or key is None: raise ModelError("Invalid reader table assignment")
        if len(owner.data) >= 100000 and key not in owner.data: raise ModelError("Reader table size exceeded")
        if value is None: owner.data.pop(key, None)
        else: owner.data[key] = value
        if isinstance(key, int) and key >= 1 and self.reads:
            cursor = self.reads[-1]["offset"] + self.reads[-1]["width"]
            if owner.first_value_read_end is None: owner.first_value_read_end = cursor
            owner.last_value_read_end = cursor
    def values(self, exprs, scope):
        result = []
        for index, node in enumerate(exprs):
            if index == len(exprs) - 1 and node[0] in {"call", "method"}: result.extend(self.invoke(node, scope))
            else: result.append(self.expression(node, scope))
        return result
    def invoke(self, node, scope):
        if node[0] == "method":
            receiver = self.expression(node[1], scope)
            if receiver is not self or node[2] not in HELPERS: raise Boundary("Non-reader method denied", node[2], offset=node[-1])
            return self.function(node[2], [self] + self.values(node[3], scope))
        callee = self.expression(node[1], scope)
        args = self.values(node[2], scope)
        if not isinstance(callee, Api): raise Boundary("Non-primitive reader call denied", arguments=args, offset=node[-1])
        if callee.slot in {8, 46}:
            width = 4 if callee.slot == 8 else 1
            if len(args) != 2 or not isinstance(args[0], bytes) or isinstance(args[1], bool) or not isinstance(args[1], (int, float)) or args[1] != int(args[1]):
                raise ModelError("Invalid buffer read parameters")
            data, offset = args[0], int(args[1])
            if not 0 <= offset <= len(data) - width: raise ModelError(f"Reader buffer bounds at {offset}")
            value = struct.unpack_from("<I", data, offset)[0] if width == 4 else data[offset]
            if len(self.reads) < 100000: self.reads.append({"at": node[-1], "offset": offset, "width": width, "value": value,
                "helper": self.function_stack[-1] if self.function_stack else None})
            else: raise ModelError("Reader read-event budget exceeded")
            return [value]
        if callee.slot == 34:
            if len(args) != 1: raise ModelError("Unexpected table.create overload")
            return [self.table(args[0], node[-1])]
        if callee.slot == 97:
            if len(args) != 2 or not isinstance(args[0], Table): raise ModelError("Invalid metatable metadata")
            args[0].metatable = args[1]  # metadata only; never run metamethods.
            return [args[0]]
        raise Boundary("Function factory / unknown API denied BEFORE call", callee.slot, args, node[-1])
    def expression(self, node, scope):
        self.tick(); kind = node[0]
        if kind == "literal": return node[1]
        if kind == "variable": return scope.get(node[1])
        if kind == "group": return self.expression(node[1], scope)
        if kind == "table":
            table = self.table(at=node[-1])
            for i, value in enumerate(self.values(node[1], scope), 1): self.write(table, i, value)
            return table
        if kind == "index": return self.get(self.expression(node[1], scope), self.expression(node[2], scope), node[-1])
        if kind in {"call", "method"}:
            values = self.invoke(node, scope)
            return values[0] if values else None
        if kind == "unary":
            value = self.expression(node[2], scope)
            if node[1] == "not": return not truth(value)
            if isinstance(value, bool) or not isinstance(value, (int, float)): raise ModelError("Non-numeric unary operand")
            return -value
        if kind == "binary":
            op = node[1]; left = self.expression(node[2], scope)
            if op == "and": return self.expression(node[3], scope) if truth(left) else left
            if op == "or": return left if truth(left) else self.expression(node[3], scope)
            right = self.expression(node[3], scope)
            if op in {"==", "~="}:
                equal = type(left) is type(right) and left == right if isinstance(left, bool) or isinstance(right, bool) else left == right
                return equal if op == "==" else not equal
            if isinstance(left, bool) or isinstance(right, bool) or not isinstance(left, (int, float)) or not isinstance(right, (int, float)):
                raise ModelError("Non-numeric binary operand")
            if op == "+": return left + right
            if op == "-": return left - right
            if op == "*": return left * right
            if op == "/": return left / right
            if op == "%": return left % right
            if op == "<": return left < right
            if op == ">": return left > right
            if op == "<=": return left <= right
            if op == ">=": return left >= right
        raise ModelError(f"Unsupported expression: {kind}")
    def block(self, statements, scope, function):
        for statement in statements:
            self.tick(); kind = statement[0]
            if kind in {"local", "assign"}:
                values = self.values(statement[2], scope)
                targets = statement[1]
                locations = []
                if kind == "assign":
                    for target in targets:
                        if target[0] == "variable": locations.append(("variable", target[1]))
                        elif target[0] == "index": locations.append((self.expression(target[1], scope), self.expression(target[2], scope)))
                        else: raise ModelError("Invalid assignment target")
                for i, target in enumerate(targets):
                    value = values[i] if i < len(values) else None
                    if kind == "local": scope.data[target] = value
                    elif locations[i][0] == "variable": scope.assign(locations[i][1], value)
                    else: self.write(locations[i][0], locations[i][1], value)
            elif kind == "if":
                for condition, body in statement[1]:
                    if truth(self.expression(condition, scope)):
                        self.block(body, Scope(scope), function); break
                else: self.block(statement[2], Scope(scope), function)
            elif kind == "while":
                if function != "GW": raise ModelError("Only GW reader control loop is allowed")
                while truth(self.expression(statement[1], scope)):
                    state = scope.get("c")
                    self.state_hits[state] = self.state_hits.get(state, 0) + 1
                    self.last_scope = scope
                    self.block(statement[2], Scope(scope), function)
            elif kind == "return": raise Returned(self.values(statement[1], scope))
            elif kind == "call_statement": self.invoke(statement[1], scope)
            else: raise ModelError(f"Unsupported statement: {kind}")
    def function(self, name, args):
        if name not in self.definitions: raise ModelError(f"Unapproved reader helper: {name}")
        parameters, body = self.definitions[name]
        scope = Scope()
        for i, parameter in enumerate(parameters): scope.data[parameter] = args[i] if i < len(args) else None
        self.calls[name] = self.calls.get(name, 0) + 1
        self.function_stack.append(name)
        try:
            self.block(body, scope, name)
        except Returned as result:
            return result.values
        finally:
            self.function_stack.pop()
        return []
