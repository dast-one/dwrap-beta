# syntax=docker/dockerfile:1.4
##  gonna using heredoc facility, additional build context
##  build with DOCKER_BUILDKIT=1

FROM projectdiscovery/nuclei:latest

COPY ./requirements.txt /tmp/

# Please do not forget about `--build-context ...=...`
COPY --from=zreprt . /usr/local/lib/zreprt/

RUN --mount=type=cache,target=/root/.cache/pip \
    <<EOF
    \
    apk add --update --no-cache python3
    ln -sf python3 /usr/bin/python
    python3 -m ensurepip
    pip3 install --disable-pip-version-check -r /tmp/requirements.txt
    pip3 install --disable-pip-version-check --editable /usr/local/lib/zreprt
EOF

COPY ./nuclei-jockey.py /usr/local/bin/nuclei-jockey

ENV PYTHONUNBUFFERED=1

RUN nuclei -update-templates

ENTRYPOINT [ "/usr/local/bin/nuclei-jockey" ]
