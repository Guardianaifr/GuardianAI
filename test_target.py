from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def catch_all(path):
    return jsonify({
        "headers": dict(request.headers),
        "cookies": dict(request.cookies)
    })

if __name__ == '__main__':
    app.run(port=9998)
