import yaml, sys
with open('.github/workflows/benchmark_autorun.yml', 'r') as f:
    content = f.read()
try:
    parsed = yaml.safe_load(content)
    print('PyYAML parse: OK')
    print('Top-level keys:', list(parsed.keys()))
    print('Jobs:', list(parsed.get('jobs', {}).keys()))
    on_val = parsed.get('on', {})
    print('Triggers:', list(on_val.keys()) if isinstance(on_val, dict) else str(on_val))
    steps = parsed['jobs']['benchmark']['steps']
    print('Steps (%d):' % len(steps))
    for s in steps:
        label = s.get('name') or s.get('uses') or '??'
        print('  - ' + label)
    sys.exit(0)
except yaml.YAMLError as e:
    print('YAML ERROR: ' + str(e))
    sys.exit(1)
