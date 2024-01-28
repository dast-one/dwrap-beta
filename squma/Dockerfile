# syntax=docker/dockerfile:1.4
##  gonna using heredoc facility, additional build context
##  build with DOCKER_BUILDKIT=1


# ---------------------------------------------------------------------
# -- Build stage

FROM alpine as auxbuilder

RUN <<EOF
    \
    apk add --no-cache curl jq
    curl -sL -o /tmp/sqlmap.tgz \
        $(curl -sL https://api.github.com/repos/sqlmapproject/sqlmap/releases/latest | jq -r '.tarball_url')
    mkdir -p /usr/share/sqlmap
    tar xf /tmp/sqlmap.tgz --strip-components 1 -C /usr/share/sqlmap
EOF


# ---------------------------------------------------------------------
# -- Main stage

FROM python:3.11-slim

RUN --mount=type=cache,target=/root/.cache/pip \
    --mount=type=cache,target=/var/cache/apt \
    --mount=type=bind,source=requirements.txt,target=/tmp/requirements.txt \
    --mount=type=bind,from=common,source=aliases.sh,target=/tmp/aliases.sh \
    <<EOF
    \
    cat /tmp/aliases.sh >> /root/.bashrc
    apt-get update
    apt-get install -y sqlmap
    pip3 install --disable-pip-version-check -r /tmp/requirements.txt
EOF

COPY --from=auxbuilder /usr/share/sqlmap/ /usr/share/sqlmap/

COPY ./openapi_sqlmap.py /usr/share/sqlmap/
COPY --chmod=0755 ./sqlmap-jockey.py /usr/share/sqlmap/
RUN ln -s '../share/sqlmap/sqlmap-jockey.py' /usr/bin/sqlmap-jockey
ENV PYTHONPATH="${PYTHONPATH}:/usr/share/sqlmap"
ENTRYPOINT [ "/usr/bin/sqlmap-jockey" ]

ENV PYTHONUNBUFFERED=1
