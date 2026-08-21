import sys
import traceback
from guardian.runtime.interceptor import GuardianProxy

print('Imported')

config = {
    'proxy': {'enabled': True, 'listen_port': 65235},
    'scanner': {},
    'runtime_monitoring': {},
    'security_policies': {'admin_token': 'TEST_ADMIN_TOKEN'}
}

print('Config created')

try:
    p = GuardianProxy(config)
    print('Proxy created')
    p.start()
    print('Proxy started')
    import time
    time.sleep(2)
except BaseException as e:
    print(f'CAUGHT: {type(e)} {e}')
    traceback.print_exc()
