import json
import queue
from datetime import datetime

from flask import Flask, Response, jsonify, request, send_from_directory, stream_with_context


def create_app(server_instance):
    app = Flask(__name__, static_folder='../../static', static_url_path='')

    @app.get('/')
    def index():
        return send_from_directory(app.static_folder, 'index.html')

    @app.get('/api/connections')
    def get_connections():
        return jsonify({
            'code': 0,
            'data': server_instance.get_connections_payload()
        })

    @app.post('/api/connections/<client_id>/command')
    def send_command(client_id):
        payload = request.get_json(silent=True) or {}
        command = (payload.get('command') or '').strip()

        if not command:
            return jsonify({
                'code': 1,
                'message': 'command is required'
            }), 400

        try:
            result = server_instance.submit_web_command(client_id, command)
            return jsonify({
                'code': 0,
                'message': 'ok',
                'data': result
            })
        except Exception as e:
            return jsonify({
                'code': 1,
                'message': str(e)
            }), 400

    @app.post('/api/connections/<client_id>/kill')
    def kill_connection(client_id):
        try:
            server_instance.kill_connection_by_client_id(client_id)
            return jsonify({
                'code': 0,
                'message': 'ok'
            })
        except Exception as e:
            return jsonify({
                'code': 1,
                'message': str(e)
            }), 400

    @app.get('/api/stream')
    def stream():
        q = server_instance.event_bus.subscribe()

        def event_stream():
            try:
                while True:
                    try:
                        item = q.get(timeout=15)
                        yield f"event: {item['event']}\n"
                        yield f"data: {json.dumps(item['data'], ensure_ascii=False)}\n\n"
                    except queue.Empty:
                        yield "event: ping\n"
                        yield f"data: {json.dumps({'time': datetime.now().isoformat()}, ensure_ascii=False)}\n\n"
            finally:
                server_instance.event_bus.unsubscribe(q)

        return Response(
            stream_with_context(event_stream()),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'X-Accel-Buffering': 'no'
            }
        )

    return app