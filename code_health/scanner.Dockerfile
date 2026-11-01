FROM docker.io/library/python@sha256:3856e3e7bf4d0ba061501a84ed2eb0d429663307c0f54f191dc4de03c7081c3e

RUN python -m venv /opt/tool && chown -R 10001:10001 /opt/tool && mkdir /source
COPY code_health/requirements.lock /opt/code-health/code_health/requirements.lock
USER 10001:10001
ENV HOME=/tmp PATH=/opt/tool/bin:/usr/local/bin:/usr/bin:/bin
RUN /opt/tool/bin/python -I -m pip install --no-cache-dir --disable-pip-version-check --only-binary=:all: --require-hashes -r /opt/code-health/code_health/requirements.lock
COPY code_health/scanner_patch.py code_health/readers_lock.py code_health/scanner_entrypoint.py /opt/code-health/code_health/
RUN --network=none /opt/tool/bin/python -I /opt/code-health/code_health/scanner_patch.py
WORKDIR /source
ENTRYPOINT ["/opt/tool/bin/python", "-I", "-B", "-c", "import runpy,sys; sys.path.insert(0,'/opt/code-health'); runpy.run_module('code_health.scanner_entrypoint',run_name='__main__')"]
