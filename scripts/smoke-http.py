#!/usr/bin/env python3
"""Original local fixtures; exercise the installed HTTP service from another process."""
import json
import os
from pathlib import Path
import socketserver
import tempfile
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

URL = os.environ.get('SCRIBE_URL', 'http://192.168.123.22:18081/run')

class HTTP(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(self.path[1:].encode())
    def log_message(self, *args):
        pass

class Banner(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b'SCRIBE fixture banner\r\n')

http = ThreadingHTTPServer(('127.0.0.1', 0), HTTP)
tcp = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Banner)
for server in (http, tcp):
    threading.Thread(target=server.serve_forever, daemon=True).start()
try:
    with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent, prefix='scribe-http-smoke-') as directory:
        script = Path(directory) / 'probe.lua'
        script.write_text('''return {api_version=1, action=function(target,args)
          if args.banner then return {data=sirius.call("tcp.exchange")} end
          local r=sirius.call("http.get", "/" .. args.mode)
          if r.body == "unknown" then return {data={body=r.body}} end
          return {verdict=r.body, data={body=r.body}}
        end}''')
        for mode in ('vulnerable', 'not_vulnerable', 'unknown', 'banner'):
            port = (tcp if mode == 'banner' else http).server_address[1]
            args = ['--dialect', 'sirius', '--script', str(script), '--host', '127.0.0.1',
                    '--port', str(port), '--args', json.dumps({'mode': mode, 'banner': mode == 'banner'})]
            request = urllib.request.Request(URL, data=json.dumps({'args': args}).encode(),
                                             headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(request, timeout=15) as response:
                records = [json.loads(line) for line in response if line.strip()]
            assert len(records) == 1, records
            result = records[0]
            assert result['status'] == 'completed', result
            assert result['verdict'] == ('unknown' if mode == 'banner' else mode), result
            if mode == 'banner':
                assert result['output']['data']['data'] == 'SCRIBE fixture banner\r\n', result
            print(json.dumps({'case': mode, 'result': result}))
finally:
    http.shutdown()
    tcp.shutdown()
    http.server_close()
    tcp.server_close()
