import re

with open('guardian/runtime/interceptor.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix the UnboundLocalError by removing the local import
content = content.replace('from flask import Response, stream_with_context', '')
content = content.replace('return Response(stream_with_context(generate())', 'from flask import stream_with_context\n                return Response(stream_with_context(generate())')

with open('guardian/runtime/interceptor.py', 'w', encoding='utf-8') as f:
    f.write(content)
