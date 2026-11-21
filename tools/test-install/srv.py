"""Local HTTPS server for tools/test-install/run.sh: serves the fake releases, quietly."""
import functools
import http.server
import ssl
import sys


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


handler = functools.partial(Quiet, directory=sys.argv[1])
server = http.server.ThreadingHTTPServer(("127.0.0.1", 8443), handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[2], sys.argv[3])
server.socket = ctx.wrap_socket(server.socket, server_side=True)
server.serve_forever()
