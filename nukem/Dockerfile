# syntax=docker/dockerfile:1.4
##  gonna using heredoc facility, additional build context
##  build with DOCKER_BUILDKIT=1

FROM projectdiscovery/nuclei:latest

RUN --mount=type=cache,target=/root/.cache/pip \
    --mount=type=bind,source=requirements.txt,target=/tmp/requirements.txt \
    <<EOF
    \
    apk add --update --no-cache python3
    ln -sf python3 /usr/bin/python
    python3 -m ensurepip
    pip3 install --disable-pip-version-check -r /tmp/requirements.txt
EOF

COPY --chmod=0755 ./nuclei-jockey.py /usr/local/bin/nuclei-jockey
ENTRYPOINT [ "/usr/local/bin/nuclei-jockey" ]

COPY --from=common aliases.sh /etc/profile.d/

ENV PYTHONUNBUFFERED=1 ENV=/etc/profile

RUN nuclei -update-templates
