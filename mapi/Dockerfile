# syntax=docker/dockerfile:1.4
# -- heredocs

FROM python:3-slim

ADD https://mayhem4api.forallsecure.com/downloads/cli/latest/linux-musl/mapi /usr/local/bin/mapi
RUN chmod +x /usr/local/bin/mapi

COPY mapi.toml /root/.config/mapi/mapi.toml

RUN pip install --no-cache-dir grpcio-tools
COPY request-rewrite-plugin.proto pinj.py /usr/share/misc/
RUN cd /usr/share/misc && python -m grpc_tools.protoc --python_out=. --grpc_python_out=. -I. request-rewrite-plugin.proto

COPY <<EOF /root/.bashrc
alias ls='ls --color=auto'
alias ll='ls -l'
alias eg='egrep --color=auto'
EOF

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["/usr/local/bin/mapi"]
