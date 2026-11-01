"""Probe the protected recovery service; this does not authorise an exception."""
import hashlib
import hmac
import http.client
import ipaddress
import json
import re
import socket
import ssl
import threading
import time

MAX_RESPONSE_BYTES = 4096


class _RecoveryConnection(http.client.HTTPSConnection):
    def _open_socket(self):
        return socket.create_connection((self.host, self.port), self.timeout, self.source_address)

    def connect(self):
        raw = self._open_socket()
        try:
            if self._deadline_expired.is_set():
                raise TimeoutError()
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host, do_handshake_on_connect=False)
            if self._deadline_expired.is_set():
                raise TimeoutError()
            self.sock.do_handshake()
        except BaseException:
            self.close()
            raw.close()
            raise


def probe_recovery(*, host, port, context, certificate_sha256, head, base, timeout=15, _connect=None):
    """Require a pinned TLS server and a bounded, exact readiness response."""
    try:
        address = ipaddress.IPv4Address(host)
        valid = (str(address) == host and address in ipaddress.IPv4Network('100.64.0.0/10') and
                 type(port) is int and 1024 <= port <= 65535 and isinstance(context, ssl.SSLContext) and
                 context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname and
                 context.minimum_version >= ssl.TLSVersion.TLSv1_2 and
                 isinstance(certificate_sha256, str) and re.fullmatch('[0-9a-f]{64}', certificate_sha256) and
                 all(isinstance(value, str) and re.fullmatch('[0-9a-f]{40}', value) for value in (head, base)) and
                 type(timeout) in (int, float) and 0 < timeout <= 30)
        if not valid:
            raise ValueError('invalid recovery connection')
    except (ValueError, TypeError):
        raise ValueError('invalid recovery connection') from None
    deadline = time.monotonic() + timeout
    connection = (_connect or _RecoveryConnection)(host, port, context=context, timeout=timeout)
    expired = threading.Event()
    connection._deadline_expired = expired
    def stop():
        expired.set()
        transport = connection.sock
        if transport is not None:
            try:
                transport.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
    timer = threading.Timer(timeout, stop)
    timer.daemon = True
    timer.start()
    try:
        connection.connect()
        remaining = deadline - time.monotonic()
        if expired.is_set() or remaining <= 0:
            raise TimeoutError()
        transport = connection.sock
        if transport is None or not hmac.compare_digest(hashlib.sha256(transport.getpeercert(binary_form=True)).hexdigest(),
                                                        certificate_sha256):
            raise ValueError('server identity mismatch')
        body = json.dumps({'head': head, 'base': base}, separators=(',', ':')).encode()
        connection.request('POST', '/v1/bootstrap/readiness', body=body,
                           headers={'Content-Type': 'application/json', 'Content-Length': str(len(body))})
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError('recovery refused')
        data = bytearray()
        while True:
            if expired.is_set() or time.monotonic() >= deadline:
                raise TimeoutError()
            chunk = response.read1(min(1024, MAX_RESPONSE_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > MAX_RESPONSE_BYTES:
                raise ValueError('oversized response')
        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError('duplicate response field')
                value[key] = item
            return value
        result = json.loads(data.decode('utf-8'), object_pairs_hook=unique)
        if (expired.is_set() or time.monotonic() >= deadline or not isinstance(result, dict) or
                set(result) != {'version', 'watchdogIdle', 'protectionReadable'} or
                type(result['version']) is not int or result['version'] != 1 or
                result['watchdogIdle'] is not True or result['protectionReadable'] is not True):
            raise ValueError('invalid readiness response')
    except (OSError, http.client.HTTPException, ValueError, TypeError, AttributeError):
        raise ValueError('recovery readiness unavailable') from None
    finally:
        timer.cancel()
        connection.close()
