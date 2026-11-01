import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from code_health.github_http import open_metadata


class MetadataHttpTests(unittest.TestCase):
    def test_redirect_does_not_forward_authentication(self):
        received = []
        class Destination(BaseHTTPRequestHandler):
            def do_GET(self):
                received.append(self.headers.get('Authorization'))
                self.send_response(200)
                self.end_headers()
            def log_message(self, *_args):
                pass
        destination = ThreadingHTTPServer(('127.0.0.1', 0), Destination)
        class Redirect(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header('Location', f'http://127.0.0.1:{destination.server_port}/capture')
                self.end_headers()
            def log_message(self, *_args):
                pass
        origin = ThreadingHTTPServer(('127.0.0.1', 0), Redirect)
        threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (origin, destination)]
        for thread in threads:
            thread.start()
        try:
            request = urllib.request.Request(f'http://127.0.0.1:{origin.server_port}/',
                                             headers={'Authorization': 'Bearer synthetic-test-token'})
            with self.assertRaises(urllib.error.HTTPError) as error:
                open_metadata(request, timeout=3)
            self.assertEqual(error.exception.code, 302)
            self.assertEqual(received, [])
        finally:
            for server in (origin, destination):
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join(timeout=3)


if __name__ == '__main__':
    unittest.main()
