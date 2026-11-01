import contextlib
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

from bootstrap.recovery_client import _RecoveryConnection, probe_recovery

HOST = '100.80.1.2'
READY = b'{"version":1,"watchdogIdle":true,"protectionReadable":true}'


class LoopbackConnection(_RecoveryConnection):
    def _open_socket(self):
        return socket.create_connection(('127.0.0.1', self.port), self.timeout)


class RecoveryClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        def openssl(*args):
            subprocess.run(['/usr/bin/openssl', *args], cwd=cls.root, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        (cls.root / 'ca.cnf').write_text('[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=synthetic-ca\n[ext]\nbasicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n')
        openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.crt',
                '-days', '1', '-config', 'ca.cnf')
        for name in ('server', 'client'):
            openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', name + '.key', '-out', name + '.csr',
                    '-subj', '/CN=' + name)
            extra = 'subjectAltName=IP:' + HOST + '\n' if name == 'server' else 'extendedKeyUsage=clientAuth\n'
            (cls.root / (name + '.ext')).write_text('subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n' + extra)
            openssl('x509', '-req', '-in', name + '.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key',
                    '-CAcreateserial', '-out', name + '.crt', '-days', '1', '-extfile', name + '.ext')
        pem = (cls.root / 'server.crt').read_text()
        cls.fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def context(self, *, client=True):
        context = ssl.create_default_context(cafile=str(self.root / 'ca.crt'))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if client:
            context.load_cert_chain(str(self.root / 'client.crt'), str(self.root / 'client.key'))
        return context

    @contextlib.contextmanager
    def server(self, payload=READY, *, status=200, pause=0):
        captured = []
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                captured.append((self.path, self.headers.get('Authorization'), self.rfile.read(int(self.headers['Content-Length']))))
                time.sleep(pause)
                try:
                    self.send_response(status)
                    self.send_header('Content-Length', str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                    pass
            def log_message(self, *_args):
                pass
        class QuietServer(HTTPServer):
            def handle_error(self, *_args):
                pass
        server = QuietServer(('127.0.0.1', 0), Handler)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(str(self.root / 'server.crt'), str(self.root / 'server.key'))
        tls.load_verify_locations(cafile=str(self.root / 'ca.crt'))
        tls.verify_mode = ssl.CERT_REQUIRED
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            yield server.server_port, captured
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=3)

    def probe(self, port, **overrides):
        args = dict(host=HOST, port=port, context=self.context(), certificate_sha256=self.fingerprint,
                    head='a' * 40, base='b' * 40, _connect=LoopbackConnection)
        args.update(overrides)
        return probe_recovery(**args)

    def test_real_mutual_tls_and_exact_request(self):
        with self.server() as (port, captured):
            self.probe(port)
            self.assertEqual(1, len(captured))
            path, authorization, body = captured[0]
            self.assertEqual('/v1/bootstrap/readiness', path)
            self.assertIsNone(authorization)
            self.assertEqual({'head': 'a' * 40, 'base': 'b' * 40}, json.loads(body))

    def test_wrong_server_pin_missing_client_and_bad_responses_fail(self):
        with self.server() as (port, captured):
            with self.assertRaisesRegex(ValueError, 'unavailable'):
                self.probe(port, certificate_sha256='0' * 64)
            self.assertFalse(captured)
            with self.assertRaisesRegex(ValueError, 'unavailable'):
                self.probe(port, context=self.context(client=False))
        for payload in (b'{}', READY[:-1] + b',"extra":true}', b'{"version":1,"version":1}', b'x' * 4097):
            with self.subTest(payload=payload[:12]), self.server(payload) as (port, _):
                with self.assertRaisesRegex(ValueError, 'unavailable'):
                    self.probe(port)

    def test_timeout_and_invalid_inputs_fail_closed(self):
        with self.server(pause=0.3) as (port, _):
            start = time.monotonic()
            with self.assertRaisesRegex(ValueError, 'unavailable'):
                self.probe(port, timeout=0.1)
            self.assertLess(time.monotonic() - start, 1)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            def stall_handshake():
                connection, _ = listener.accept()
                with connection:
                    time.sleep(0.4)
            worker = threading.Thread(target=stall_handshake, daemon=True)
            worker.start()
            start = time.monotonic()
            with self.assertRaisesRegex(ValueError, 'unavailable'):
                self.probe(listener.getsockname()[1], timeout=0.1)
            self.assertLess(time.monotonic() - start, 1)
            worker.join(timeout=2)
        for overrides in ({'host': '127.0.0.1'}, {'host': '100.128.0.1'},
                          {'head': 'main'}, {'certificate_sha256': 'x' * 64}):
            with self.subTest(overrides=overrides), self.assertRaisesRegex(ValueError, 'invalid'):
                self.probe(8443, **overrides)
        with self.assertRaisesRegex(ValueError, 'invalid'):
            self.probe(True)


if __name__ == '__main__':
    unittest.main()
