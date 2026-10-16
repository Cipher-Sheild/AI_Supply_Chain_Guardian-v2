"""Validate YAML expansion cost before constructing an untrusted document.

Aliases remain usable for ordinary CI/Compose reuse. Cycles and excessive
expanded structures are rejected before SafeLoader merge expansion can occur.
"""
import yaml


def load(content,max_expanded_bytes=4*1024*1024,max_nodes=50000,max_depth=64):
    anchors={};pending=set();stack=[];nodes=0
    def add(weight):
        if stack:
            stack[-1]['weight']+=weight
            if stack[-1]['weight']>max_expanded_bytes:raise ValueError('YAML expansion budget exceeded')
    for event in yaml.parse(content):
        nodes+=1
        if nodes>max_nodes:raise ValueError('YAML node budget exceeded')
        if isinstance(event,(yaml.MappingStartEvent,yaml.SequenceStartEvent)):
            if len(stack)>=max_depth:raise ValueError('YAML nesting budget exceeded')
            if event.anchor:pending.add(event.anchor)
            stack.append({'anchor':event.anchor,'weight':32})
        elif isinstance(event,(yaml.MappingEndEvent,yaml.SequenceEndEvent)):
            item=stack.pop()
            if item['anchor']:
                anchors[item['anchor']]=item['weight'];pending.discard(item['anchor'])
            add(item['weight'])
        elif isinstance(event,yaml.ScalarEvent):
            weight=32+len(event.value.encode())
            if event.anchor:anchors[event.anchor]=weight
            add(weight)
        elif isinstance(event,yaml.AliasEvent):
            if event.anchor in pending or event.anchor not in anchors:raise ValueError('cyclic or unresolved YAML alias')
            add(anchors[event.anchor])
    return yaml.safe_load(content)
