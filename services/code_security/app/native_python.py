"""Guardian-owned Python AST analysis with local assignment propagation.

This is intraprocedural static analysis, not whole-program symbolic execution.
Submitted source is parsed, never imported or executed.
"""
import ast
import re
from app.schemas import Finding, Severity


class NativeFindings(list):
    partial=False


def scan_python(content,filename):
    from app.scanner import REMEDIATION_MAP
    partial=False
    try:tree=ast.parse(content,filename=filename)
    except SyntaxError as original:
        lines=content.splitlines()
        tree=None
        for end in range(min((original.lineno or len(lines))-1,len(lines)),max(0,(original.lineno or len(lines))-33),-1):
            try:
                candidate=ast.parse('\n'.join(lines[:end]),filename=filename)
                if candidate.body:tree=candidate;partial=True;break
            except SyntaxError:continue
        if tree is None:raise original
    findings=NativeFindings();seen=set()
    findings.partial=partial
    def emit(node,rule,category,reason):
        key=(rule,node.lineno)
        if key in seen:return
        seen.add(key)
        findings.append(Finding(category=category,severity=Severity.high,confidence=.85,
            location=f'{filename}:{node.lineno}',reason=reason,remediation=REMEDIATION_MAP.get(rule),
            details={'rule_id':'guardian.'+rule,'language':'python','engine':'guardian_python_ast',
                     'analysis_scope':'intraprocedural','base_severity':'high','language_weighted':False,
                     'end_line':getattr(node,'end_lineno',node.lineno)}))
    def scope(body,inherited_aliases=None):
        aliases=dict(inherited_aliases or {});dynamic=set();constructed=set();constants=set()
        # Imports are resolved without loading the imported module.
        for node in body:
            if isinstance(node,ast.Import):
                for item in node.names:aliases[item.asname or item.name.split('.')[0]]=item.name
            elif isinstance(node,ast.ImportFrom):
                for item in node.names:aliases[item.asname or item.name]=(node.module+'.' if node.module else '')+item.name
        def names(node):
            if isinstance(node,ast.Name):
                value=aliases.get(node.id,node.id)
                return {value} if isinstance(value,str) else set(value)
            if isinstance(node,ast.Attribute):return {value+'.'+node.attr for value in names(node.value)}
            return {''}
        def name(node):return '|'.join(sorted(names(node)))
        def join_aliases(branches):
            aliases.clear()
            for key in set().union(*(set(branch) for branch in branches)):
                alternatives=set()
                for branch in branches:
                    value=branch.get(key,key)
                    alternatives.update({value} if isinstance(value,str) else value)
                if len(alternatives)>64:raise ValueError('Callable alias analysis exceeds work budget')
                aliases[key]=frozenset(alternatives)
        def uncertain(node):
            if isinstance(node,ast.Constant):return False
            if isinstance(node,(ast.List,ast.Tuple,ast.Dict,ast.Set)):
                return any(uncertain(child) for child in ast.iter_child_nodes(node) if isinstance(child,ast.expr))
            if isinstance(node,ast.Name):return node.id not in constants
            if isinstance(node,ast.JoinedStr):return any(isinstance(x,ast.FormattedValue) for x in node.values)
            if isinstance(node,ast.BinOp):return uncertain(node.left) or uncertain(node.right)
            return isinstance(node,(ast.Call,ast.Subscript,ast.Attribute))
        def composed(node):
            return isinstance(node,(ast.BinOp,ast.JoinedStr)) or (isinstance(node,ast.Name) and node.id in constructed)
        # Treat unresolved function parameters as external values. Constant
        # assignment kills taint along this simple sequential path.
        def inspect(node):
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
                for expression in [*node.decorator_list,*node.args.defaults,*[value for value in node.args.kw_defaults if value is not None]]:inspect(expression)
                function_dynamic={arg.arg for arg in [*node.args.posonlyargs,*node.args.args,*node.args.kwonlyargs]}
                if node.args.vararg:function_dynamic.add(node.args.vararg.arg)
                if node.args.kwarg:function_dynamic.add(node.args.kwarg.arg)
                old=set(dynamic);old_constructed=set(constructed);old_constants=set(constants);old_aliases=dict(aliases)
                dynamic.clear();dynamic.update(function_dynamic);constructed.clear();constants.difference_update(function_dynamic)
                for statement in node.body:inspect(statement)
                dynamic.clear();dynamic.update(old);constructed.clear();constructed.update(old_constructed)
                constants.clear();constants.update(old_constants);aliases.clear();aliases.update(old_aliases);return
            if isinstance(node,ast.Import):
                for item in node.names:aliases[item.asname or item.name.split('.')[0]]=item.name
            if isinstance(node,ast.ImportFrom):
                for item in node.names:aliases[item.asname or item.name]=(node.module+'.' if node.module else '')+item.name
            if isinstance(node,ast.ClassDef):
                for expression in [*node.decorator_list,*node.bases,*[keyword.value for keyword in node.keywords]]:inspect(expression)
                scope(node.body,aliases);return
            if isinstance(node,ast.If):
                inspect(node.test)
                before=(set(dynamic),set(constructed),set(constants));outputs=[];before_aliases=dict(aliases);alias_outputs=[]
                for branch in (node.body,node.orelse):
                    dynamic.clear();dynamic.update(before[0]);constructed.clear();constructed.update(before[1]);constants.clear();constants.update(before[2])
                    aliases.clear();aliases.update(before_aliases)
                    for statement in branch:inspect(statement)
                    outputs.append((set(dynamic),set(constructed),set(constants)))
                    alias_outputs.append(dict(aliases))
                join_aliases(alias_outputs)
                dynamic.clear();dynamic.update(outputs[0][0]|outputs[1][0])
                constructed.clear();constructed.update(outputs[0][1]|outputs[1][1])
                constants.clear();constants.update(outputs[0][2]&outputs[1][2]);return
            if isinstance(node,(ast.For,ast.AsyncFor,ast.While,ast.Try)):
                # A loop may execute zero times; exceptions may skip assignments.
                before=(set(dynamic),set(constructed),set(constants));outputs=[before];before_aliases=dict(aliases);alias_outputs=[before_aliases]
                branches=([node.body,node.orelse] if not isinstance(node,ast.Try) else [node.body,*[handler.body for handler in node.handlers],node.orelse])
                for branch in branches:
                    dynamic.clear();dynamic.update(before[0]);constructed.clear();constructed.update(before[1]);constants.clear();constants.update(before[2])
                    aliases.clear();aliases.update(before_aliases)
                    if branch is node.body and isinstance(node,(ast.For,ast.AsyncFor)):
                        for target in ast.walk(node.target):
                            if isinstance(target,ast.Name) and isinstance(target.ctx,ast.Store):
                                if uncertain(node.iter):dynamic.add(target.id);constants.discard(target.id)
                                else:dynamic.discard(target.id);constants.add(target.id)
                                constructed.discard(target.id)
                    for statement in branch:inspect(statement)
                    outputs.append((set(dynamic),set(constructed),set(constants)))
                    alias_outputs.append(dict(aliases))
                join_aliases(alias_outputs)
                dynamic.clear();dynamic.update(set.union(*(out[0] for out in outputs)))
                constructed.clear();constructed.update(set.union(*(out[1] for out in outputs)))
                constants.clear();constants.update(set.intersection(*(out[2] for out in outputs)))
                if isinstance(node,ast.While):inspect(node.test)
                elif isinstance(node,(ast.For,ast.AsyncFor)):inspect(node.iter)
                if isinstance(node,ast.Try):
                    for statement in node.finalbody:inspect(statement)
                return
            if isinstance(node,(ast.Assign,ast.AnnAssign)):
                value=node.value
                targets=node.targets if isinstance(node,ast.Assign) else [node.target]
                if value:
                    for target in targets:
                        for sub in ([target] if isinstance(target,ast.Name) else ast.walk(target) if isinstance(target,(ast.Tuple,ast.List)) else []):
                            if isinstance(sub,ast.Name):
                                if isinstance(value,(ast.Attribute,ast.Name)):
                                    candidates={target for target in names(value) if target.split('.')[0] in {'os','subprocess','pickle','yaml','hashlib','requests','builtins'} or target in {'eval','exec','compile'}}
                                    if candidates:aliases[sub.id]=frozenset(candidates)
                                if uncertain(value):dynamic.add(sub.id);constants.discard(sub.id)
                                else:dynamic.discard(sub.id);constants.add(sub.id)
                                if composed(value):constructed.add(sub.id)
                                else:constructed.discard(sub.id)
            if isinstance(node,ast.Compare) and any(isinstance(op,ast.Eq) for op in node.ops):
                if re.search(r'password|passwd|pwd',ast.unparse(node),re.I):
                    emit(node,'python-plaintext-password-comparison','weak_auth','Password-like value compared directly.')
            if isinstance(node,ast.Call):
                first=node.args[0] if node.args else None
                kwargs={keyword.arg:keyword.value for keyword in node.keywords}
                for called in sorted(names(node.func)):
                    if called in {'eval','exec','builtins.eval','builtins.exec'}:
                        emit(node,'python-eval-on-input','unsafe_eval','Dynamic Python execution allows arbitrary code execution.')
                    if called in {'pickle.load','pickle.loads'}:
                        emit(node,'python-insecure-deserialization-pickle','insecure_deserialization','Pickle can execute code during deserialization.')
                    if called=='yaml.load' and not names(kwargs.get('Loader')) <= {'yaml.SafeLoader','yaml.CSafeLoader'}:
                        emit(node,'python-insecure-yaml-load','insecure_deserialization','YAML loading does not specify a safe loader.')
                    if called.startswith('requests.') and isinstance(kwargs.get('verify'),ast.Constant) and kwargs['verify'].value is False:
                        emit(node,'python-requests-tls-verification-disabled','insecure_tls','TLS certificate verification is disabled.')
                    if first is not None and uncertain(first):
                        if called.endswith(('.execute','.executemany','.executescript')):
                            emit(node,'python-sql-injection-string-concat','sql_injection','Dynamic SQL text reaches execution; bound values do not sanitize the query text itself.')
                        shell=kwargs.get('shell')
                        if called=='os.system' or (called in {'subprocess.run','subprocess.call','subprocess.Popen'} and isinstance(shell,ast.Constant) and shell.value is True):
                            emit(node,'python-os-system-command-injection','command_injection','Dynamic command passed to a shell.')
                        if called.rsplit('.',1)[-1] in {'render_template_string','Markup'}:
                            emit(node,'python-flask-xss-render-template-string','xss','Dynamic HTML rendered without explicit escaping.')
                    url=node.args[1] if called=='requests.request' and len(node.args)>1 else first
                    if called in {'requests.get','requests.post','requests.request'} and url is not None and composed(url):
                        emit(node,'python-ssrf-requests-user-controlled-url','ssrf','Constructed URL requires explicit destination validation.')
                    if called in {'hashlib.md5','hashlib.sha1'} and first is not None and re.search(r'password|passwd|pwd',ast.unparse(first),re.I):
                        emit(node,'python-weak-password-hashing','weak_auth','Fast general-purpose hash used for a password-like value.')
            for child in ast.iter_child_nodes(node):inspect(child)
        for node in body:inspect(node)
    scope(tree.body)
    return findings
