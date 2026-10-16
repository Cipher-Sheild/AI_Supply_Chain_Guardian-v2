"""Guardian-owned multi-language syntax-tree rules.

Tree-sitter supplies grammars only. Guardian owns traversal, local assignment
propagation, sources/sinks, findings, and remediation. No scanner executable is
invoked and submitted programs are never compiled, imported, or executed.
"""
import re
from functools import lru_cache
from pathlib import Path
from app.schemas import Finding,Severity


class NativeFindings(list):
    partial=False


@lru_cache(maxsize=8)
def language_for(suffix):
    from tree_sitter import Language
    if suffix in {'.js','.jsx','.mjs','.cjs'}:
        import tree_sitter_javascript as grammar
        capsule=grammar.language()
    elif suffix in {'.ts','.tsx'}:
        import tree_sitter_typescript as grammar
        capsule=grammar.language_tsx() if suffix=='.tsx' else grammar.language_typescript()
    elif suffix in {'.php','.php-only'}:
        import tree_sitter_php as grammar
        capsule=grammar.language_php_only() if suffix=='.php-only' else grammar.language_php()
    elif suffix=='.java':
        import tree_sitter_java as grammar
        capsule=grammar.language()
    elif suffix=='.go':
        import tree_sitter_go as grammar
        capsule=grammar.language()
    else:raise ValueError('unsupported native grammar')
    return Language(capsule)


def scan(content,filename):
    if len(content.encode())>262144:raise ValueError('code exceeds analysis work budget')
    suffix=Path(filename).suffix.lower()
    if suffix=='.py':
        from app.native_python import scan_python
        return scan_python(content,filename)
    from tree_sitter import Parser
    from app.scanner import REMEDIATION_MAP
    grammar_suffix='.php-only' if suffix=='.php' and '<?' not in content else suffix
    source=content.encode();tree=Parser(language_for(grammar_suffix)).parse(source)
    language='js' if suffix in {'.js','.jsx','.mjs','.cjs','.ts','.tsx'} else suffix[1:]
    findings=NativeFindings();findings.partial=tree.root_node.has_error;seen=set();count=0
    def text(node):return source[node.start_byte:node.end_byte].decode(errors='replace') if node is not None else ''
    def field(node,key):return node.child_by_field_name(key)
    def emit(node,rule,category,message):
        key=(rule,node.start_point.row)
        if key in seen:return
        seen.add(key)
        findings.append(Finding(category=category,severity=Severity.high,confidence=.85,
            location=f'{filename}:{node.start_point.row+1}',reason=message,
            remediation=REMEDIATION_MAP.get(rule,'Validate external input, use safe APIs, and preserve isolation.'),
            details={'rule_id':'guardian.'+rule,'engine':'guardian_syntax_tree','analysis_scope':'intraprocedural',
                     'language':language,'base_severity':'high','language_weighted':False,'end_line':node.end_point.row+1}))
    scopes={'function_declaration','function_definition','method_declaration','arrow_function','anonymous_function','method_definition','func_literal'}
    assignments={'variable_declarator','assignment_expression','short_var_declaration','var_spec'}
    calls={'call_expression','function_call_expression','member_call_expression','scoped_call_expression','method_invocation','object_creation_expression','new_expression'}
    def call_name(node):
        function=field(node,'function') or field(node,'constructor') or field(node,'type')
        if function is not None:return re.sub(r'\s+','',text(function))
        obj=field(node,'object') or field(node,'scope');name=field(node,'name')
        return (text(obj)+'.' if obj is not None else '')+text(name)
    def arguments(node):
        args=field(node,'arguments')
        if args is None:return []
        return [child.named_children[-1] if child.type=='argument' and child.named_children else child for child in args.named_children]
    def label(node,bindings):
        if node is None:return 'constant'
        kind=node.type;value=text(node)
        if kind in {'expression_list','argument'} and len(node.named_children)==1:return label(node.named_children[0],bindings)
        if kind in {'identifier','variable_name','name'}:return bindings.get(value,'unknown')
        if kind in {'string','string_literal','interpreted_string_literal','raw_string_literal','encapsed_string','template_string'}:
            if any(child.type in {'template_substitution','variable_name','embedded_variable'} for child in node.named_children):return 'constructed'
            return 'constant'
        if kind in {'number','integer','integer_literal','decimal_integer_literal','true','false','null'}:return 'constant'
        if kind=='binary_expression':
            operator=re.sub(r'\s+','',text(node.child_by_field_name('operator')))
            # Grammar variants expose the operator as an unnamed token.
            if not operator:operator=next((text(child) for child in node.children if text(child) in {'+','.'}),'')
            if operator in {'+','.'}:
                labels=[label(child,bindings) for child in node.named_children]
                if all(item=='constant' for item in labels):return 'constant'
                if all(item in {'constant','html_escaped'} for item in labels):return 'html_escaped'
                return 'constructed'
        if node.type in calls and re.search(r'htmlspecialchars|htmlentities|DOMPurify\.sanitize|Encode\.forHtml',call_name(node)):return 'html_escaped'
        if re.search(r'\$_(?:GET|POST|REQUEST|COOKIE)|\.getParameter\(|\breq\.(?:query|body|params|headers)\b',value):return 'request'
        return 'unknown'
    def visit(node,bindings):
        nonlocal count
        count+=1
        if count>100000:raise ValueError('syntax tree exceeds analysis work budget')
        if node.type in {'comment','line_comment','block_comment'}:return
        if node.type in scopes:bindings=dict(bindings)
        if node.type in {'if_statement','conditional_expression','for_statement','while_statement','try_statement','switch_statement'}:
            branches=[dict(bindings)]
            for child in node.named_children:
                branch=dict(bindings);visit(child,branch);branches.append(branch)
            rank={'constant':0,'html_escaped':1,'unknown':2,'request':3,'constructed':4}
            for key in set().union(*(branch.keys() for branch in branches)):
                bindings[key]=max((branch.get(key,'unknown') for branch in branches),key=lambda item:rank[item])
            return
        if node.type in assignments:
            left=field(node,'name') or field(node,'left');right=field(node,'value') or field(node,'right')
            if left is not None and right is not None:
                if left.type=='expression_list' and len(left.named_children)==1:left=left.named_children[0]
                if left.type in {'identifier','variable_name','name'}:
                    bindings[text(left)]=label(right,bindings)
                if language=='js' and re.search(r'(?:\.innerHTML|dangerouslySetInnerHTML)$',text(left)) and label(right,bindings) not in {'constant','html_escaped'}:
                    emit(node,'js-xss-dangerous-html','xss','Dynamic HTML reaches an unescaped rendering sink.')
                if language=='js' and 'NODE_TLS_REJECT_UNAUTHORIZED' in text(left) and text(right).strip("'\"")== '0':
                    emit(node,'js-insecure-tls-verification-disabled','insecure_tls','TLS certificate verification is disabled.')
        if node.type in {'pair','keyed_element'}:
            key=field(node,'key');value=field(node,'value')
            if text(key).strip("'\"") in {'rejectUnauthorized','InsecureSkipVerify'} and text(value) in {'false' if language=='js' else 'true'}:
                emit(node,'js-insecure-tls-verification-disabled' if language=='js' else 'go-insecure-tls','insecure_tls','TLS certificate verification is disabled.')
        if language=='js' and node.type=='jsx_attribute' and text(field(node,'name'))=='dangerouslySetInnerHTML':
            emit(node,'js-xss-dangerous-html','xss','JSX inserts raw HTML; verify context-appropriate sanitization.')
        if language=='java' and node.type=='field_access' and text(field(node,'field'))=='ALLOW_ALL_HOSTNAME_VERIFIER':
            emit(node,'java-insecure-tls-verification-disabled','insecure_tls','An allow-all hostname verifier bypasses identity verification.')
        if node.type=='binary_expression' and re.search(r'password|passwd|pwd',text(node),re.I):
            if any(text(child) in {'==','==='} for child in node.children):
                rule={'js':'js-plaintext-password-comparison','php':'php-plaintext-password-comparison','go':'go-plaintext-password-comparison','java':'java-plaintext-password-comparison'}[language]
                emit(node,rule,'weak_auth','Password-like values are compared directly.')
        if language=='php' and node.type=='echo_statement':
            if any(label(child,bindings) in {'request','constructed','unknown'} for child in node.named_children):
                emit(node,'php-xss-unescaped-echo','xss','Potentially external content is echoed without escaping.')
        if node.type in calls:
            name=call_name(node);bare=re.split(r'\.|->|::',name)[-1];args=arguments(node)
            first=args[0] if args else None;kind=label(first,bindings)
            sql_index=1 if language=='php' and bare=='mysqli_query' or language=='go' and bare in {'QueryContext','ExecContext'} else 0
            query=args[sql_index] if len(args)>sql_index else None
            sql_names={'query','execute','mysqli_query','executeQuery','executeUpdate','Query','Exec','QueryContext','ExecContext'}
            if bare in sql_names and label(query,bindings) in {'constructed','html_escaped','request'}:
                rule={'js':'js-sql-injection-string-concat','php':'php-sql-injection-string-concat','java':'java-sql-injection-string-concat','go':'go-sql-injection'}[language]
                emit(node,rule,'sql_injection','Untrusted SQL text reaches execution; bound values do not sanitize the query text itself.')
            dynamic=kind!='constant'
            command=(language=='js' and bare=='exec') or (language=='php' and bare in {'shell_exec','system','exec','passthru'}) or (language=='java' and bare=='exec')
            if command and dynamic:
                emit(node,{'js':'js-command-injection','php':'php-command-injection','java':'java-command-injection'}[language],'command_injection','Dynamic command reaches a shell execution sink.')
            if language=='go' and name.endswith('exec.Command') and len(args)>=3 and text(args[1]).strip('"`')=='-c' and label(args[2],bindings)!='constant':
                emit(node,'go-command-injection','command_injection','Dynamic command is passed to a shell with -c.')
            if bare in {'eval','Function'}:
                emit(node,{'js':'js-eval-on-input','php':'php-eval-on-input','java':'java-scriptengine-eval-on-input'}.get(language,'go-unsafe-eval'),'unsafe_eval','Runtime code evaluation is a code-execution sink.')
            if bare in {'unserialize','readObject'}:
                emit(node,{'js':'js-insecure-deserialization','php':'php-insecure-deserialization','java':'java-insecure-deserialization'}.get(language,'go-insecure-deserialization'),'insecure_deserialization','Object deserialization can execute attacker-controlled behavior.')
            if language=='php' and bare=='curl_setopt' and len(args)>=3 and text(args[1]) in {'CURLOPT_SSL_VERIFYPEER','CURLOPT_SSL_VERIFYHOST'} and text(args[2]).lower() in {'false','0'}:
                emit(node,'php-insecure-tls-verification-disabled','insecure_tls','cURL certificate or hostname verification is disabled.')
            if language=='java' and bare in {'print','println','write'} and kind=='request':
                emit(node,'java-xss-unescaped-response-write','xss','Request data reaches response output without escaping.')
            if language=='go' and name.endswith('template.HTML') and dynamic:
                emit(node,'go-xss-unsafe-html','xss','Dynamic data is marked as trusted HTML.')
            ssrf=(language=='js' and bare in {'get','post','fetch','request'}) or (language=='php' and bare=='file_get_contents') or (language=='java' and bare=='URL') or (language=='go' and name in {'http.Get','http.Post'})
            if ssrf and kind in {'constructed','request','html_escaped'}:
                emit(node,{'js':'js-ssrf-user-controlled-url','php':'php-ssrf-curl-user-controlled-url','java':'java-ssrf-user-controlled-url','go':'go-ssrf'}[language],'ssrf','Constructed URL requires explicit destination validation.')
            if language=='java' and bare=='equals' and re.search(r'password|passwd|pwd',text(field(node,'object')),re.I):
                emit(node,'java-plaintext-password-comparison','weak_auth','Password-like value is compared directly.')
            weak=(language=='js' and bare=='createHash' and text(first).strip("'\"").lower() in {'md5','sha1'}) or (language=='java' and bare=='getInstance' and text(first).strip('"').lower() in {'md5','sha-1'}) or (language=='php' and bare in {'md5','sha1'} and re.search(r'password|passwd|pwd',text(first),re.I))
            if weak:
                emit(node,{'js':'js-weak-password-hashing','php':'php-weak-password-hashing','java':'java-weak-password-hashing'}[language],'weak_auth','A fast general-purpose hash is unsuitable for password storage.')
        for child in node.named_children:visit(child,bindings)
    visit(tree.root_node,{})
    return findings
