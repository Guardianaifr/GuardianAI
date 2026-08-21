with open('guardian/runtime/interceptor.py', 'r', encoding='utf-8') as f:
    content = f.read()

old_gen = '''            if is_stream:
                def generate():
                    window = ""
                    for chunk in resp.iter_content(chunk_size=1, decode_unicode=True):
                        if chunk:
                            window += chunk
                            if self.config.get('security_policies', {}).get('validate_output'):
                                _, detected = self.output_validator.sanitize_output(window)
                                if detected:
                                    yield 'data: {"error": "Forbidden: Potential data leak blocked by GuardianAI."}\\n\\n'
                                    break
                            if len(window) > 100:
                                yield window[:-100]
                                window = window[-100:]
                    if window:
                        yield window
                from flask import Response, stream_with_context
                return Response(stream_with_context(generate()), content_type=resp.headers.get('content-type', 'text/event-stream'))'''

new_gen = '''            if is_stream:
                def generate():
                    window = ""
                    # 500-byte margin to prevent prefix leaks of long sensitive patterns (P2-2 trade-off)
                    margin = 500
                    for chunk in resp.iter_content(chunk_size=1, decode_unicode=True):
                        if chunk:
                            window += chunk
                            if self.config.get('security_policies', {}).get('validate_output'):
                                _, detected = self.output_validator.sanitize_output(window)
                                if detected:
                                    yield 'data: {"error": "Forbidden: Potential data leak blocked by GuardianAI."}\\n\\n'
                                    break
                            if len(window) > margin:
                                yield window[:-margin]
                                window = window[-margin:]
                    if window:
                        yield window
                from flask import Response, stream_with_context
                return Response(stream_with_context(generate()), content_type=resp.headers.get('content-type', 'text/event-stream'))'''

content = content.replace(old_gen, new_gen)
with open('guardian/runtime/interceptor.py', 'w', encoding='utf-8') as f:
    f.write(content)
