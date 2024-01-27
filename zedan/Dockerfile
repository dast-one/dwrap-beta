# syntax=docker/dockerfile:1.4
##  gonna using heredoc facility, additional build context
##  build with DOCKER_BUILDKIT=1

FROM ghcr.io/zaproxy/zaproxy:stable

RUN <<EOF
    \
    zap.sh -cmd -addonupdate
    zap.sh -cmd -addoninstall jython
    zap.sh -cmd -addoninstall sqliplugin
EOF

USER root

RUN --mount=type=cache,target=/root/.cache/pip \
    --mount=type=bind,source=requirements.txt,target=/tmp/requirements.txt \
    --mount=type=bind,from=common,source=aliases.sh,target=/tmp/aliases.sh \
    <<EOF
    \
    cat /tmp/aliases.sh >> ~zap/.bash_aliases
    pip3 install --disable-pip-version-check -r /tmp/requirements.txt
EOF

COPY ./templates /usr/local/share/zap-templates/
COPY --chmod=0755 ./zap-jockey.py /usr/local/bin/zap-jockey

ENTRYPOINT [ "/usr/local/bin/zap-jockey" ]

USER zap

ENV PYTHONUNBUFFERED=1
