def generate():
    window = ""
    chunks = [
        'data: {"choices": [{"delta": {"content": "This is a sec"}}]}\n\n',
        'data: {"choices": [{"delta": {"content": "ret password."}}]}\n\n'
    ]
    for chunk in chunks:
        if chunk:
            window += chunk
            if "secret password" in window:
                yield 'data: {"error": "Blocked"}\n\n'
                break
            if len(window) > 30:
                yield window[:-30]
                window = window[-30:]
    if window:
        yield window

for x in generate():
    print(repr(x))
