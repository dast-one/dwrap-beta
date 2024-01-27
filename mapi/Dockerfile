# syntax=docker/dockerfile:1.4
##  gonna using heredoc facility, additional build context
##  build with DOCKER_BUILDKIT=1

FROM python:3-slim

ADD --chmod=0755 https://mayhem4api.forallsecure.com/downloads/cli/latest/linux-musl/mapi /usr/local/bin/mapi

COPY mapi.toml /root/.config/mapi/mapi.toml

COPY request-rewrite-plugin.proto pinj.py /usr/share/misc/

RUN --mount=type=cache,target=/root/.cache/pip \
    --mount=type=bind,from=common,source=aliases.sh,target=/tmp/aliases.sh \
    <<EOF
    \
    cat /tmp/aliases.sh >> /root/.bashrc
    pip install grpcio-tools
    cd /usr/share/misc
    python -m grpc_tools.protoc --python_out=. --grpc_python_out=. -I. request-rewrite-plugin.proto
EOF

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["/usr/local/bin/mapi"]
