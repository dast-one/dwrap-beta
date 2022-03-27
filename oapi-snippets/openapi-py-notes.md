
```py
if True:
    q = yaml.safe_load(open('oapi.yaml').read())
    del q['components']['securitySchemes']
    for p in q['paths']:
        for m in q['paths'][p]:
            if 'security' in q['paths'][p][m]:
                del q['paths'][p][m]['security']
    # del q['paths']['/payments']['get']['responses']
    # del q['paths']['/payments/operations']['get']['responses']
```

```py
def deref(s):
    t = q
    for e in s.split('/')[1:]:
        t = t[e]
    if 'description' in t:
        del t['description']
    if 'x-collection' in t:
        del t['x-collection']
    return copy.deepcopy(t)

# deref('#/components/schemas/Announcement')
```

```py
def into(o):
    for k, v in list(o.items()):
        if k == '$ref':
            # o = deref(v)
            # o[k] = deref(v)
            del o['$ref']
            o.update(deref(v))
            print('.', end='')
        if isinstance(v, dict):
            into(v)
```

```py
# run this several times
for cs in q['components']['schemas'].values():
    into(cs)

# then this - also several times
into(q['paths'])

with open('oapi-m.yaml', 'w') as fo:
    fo.write(yaml.safe_dump(q, sort_keys=False, allow_unicode=True))
```

