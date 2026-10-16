"""SPDX expression tree with AND precedence, OR, parentheses and WITH.
Unknown license/exception symbols remain nodes; they are never discarded.
"""
import re
_TOKEN = re.compile(r"\s*(\(|\)|AND\b|OR\b|WITH\b|[A-Za-z0-9][A-Za-z0-9.+:_-]*)")
def parse_expression(text, normalize=lambda s: s):
    tokens=[]; pos=0
    while pos < len(text):
        if not text[pos:].strip(): break
        match=_TOKEN.match(text, pos)
        if not match: raise ValueError("Invalid license expression syntax")
        tokens.append(match.group(1)); pos=match.end()
    index=0
    def atom():
        nonlocal index
        if index >= len(tokens): raise ValueError("Missing license operand")
        token=tokens[index]; index+=1
        if token == "(":
            result=expr("OR")
            if index >= len(tokens) or tokens[index] != ")": raise ValueError("Unclosed license expression")
            index+=1
        elif token in {"AND","OR","WITH",")"}: raise ValueError("Invalid license operand")
        else:
            normalized=normalize(token)
            result={"op":"license","id":normalized or token,"known":normalized is not None}
        if index < len(tokens) and tokens[index] == "WITH":
            index+=1
            if index >= len(tokens) or tokens[index] in {"(",")","AND","OR","WITH"}: raise ValueError("Missing exception")
            result={"op":"WITH","license":result,"exception":tokens[index]}; index+=1
        return result
    def expr(operator):
        nonlocal index
        child=(lambda: expr("AND")) if operator == "OR" else atom
        nodes=[child()]
        while index < len(tokens) and tokens[index] == operator:
            index+=1; nodes.append(child())
        return nodes[0] if len(nodes)==1 else {"op":operator,"children":nodes}
    tree=expr("OR")
    if index != len(tokens): raise ValueError("Unexpected license token")
    return tree

def render(tree):
    if tree["op"] == "license": return tree["id"]
    if tree["op"] == "WITH": return f"{render(tree['license'])} WITH {tree['exception']}"
    return "(" + (" " + tree["op"] + " ").join(render(c) for c in tree["children"]) + ")"
