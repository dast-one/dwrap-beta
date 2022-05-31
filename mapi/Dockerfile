# syntax=docker/dockerfile:1.4
##  gonna using heredoc facility
##  build with DOCKER_BUILDKIT=1

FROM python:3-slim

ADD https://mayhem4api.forallsecure.com/downloads/cli/latest/linux-musl/mapi /usr/local/bin/mapi
RUN chmod +x /usr/local/bin/mapi
WORKDIR /root
COPY mapi.toml .config/mapi/mapi.toml

RUN pip install --no-cache-dir grpcio-tools
COPY request-rewrite-plugin.proto pinj.py /usr/share/misc/
RUN cd /usr/share/misc && python -m grpc_tools.protoc --python_out=. --grpc_python_out=. -I. request-rewrite-plugin.proto

COPY <<EOF .bashrc
alias ls='ls --color=auto'
alias ll='ls -l'
alias eg='egrep --color=auto'
EOF
