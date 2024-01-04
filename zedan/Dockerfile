# syntax=docker/dockerfile:1.4
##  gonna using heredoc facility, additional build context
##  build with DOCKER_BUILDKIT=1

FROM ghcr.io/zaproxy/zaproxy:stable

RUN zap.sh -cmd -addonupdate && \
    zap.sh -cmd -addoninstall jython && \
    zap.sh -cmd -addoninstall sqliplugin

ENV PYTHONUNBUFFERED=1

USER root

COPY ./requirements.txt /tmp/
# Please do not forget about `--build-context ...=...`
COPY --from=zreprt . /usr/local/lib/zreprt/

RUN --mount=type=cache,target=/root/.cache/pip \
    <<EOF
    \
    pip3 install --disable-pip-version-check -r /tmp/requirements.txt
    pip3 install --disable-pip-version-check --editable /usr/local/lib/zreprt
EOF

COPY ./templates /usr/local/share/zap-templates/
COPY ./zap-jockey.py /usr/local/bin/zap-jockey

ENTRYPOINT [ "/usr/local/bin/zap-jockey" ]

USER zap
