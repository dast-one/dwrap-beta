# syntax=docker/dockerfile:1.4
##  gonna using heredoc facility, additional build context
##  build with DOCKER_BUILDKIT=1

FROM restler:v9.2.4

# https://github.com/microsoft/restler-fuzzer/blob/main/docs/user-guide/Telemetry.md
ENV RESTLER_TELEMETRY_OPTOUT=1

RUN --mount=type=cache,target=/root/.cache/pip \
    --mount=type=bind,source=requirements.txt,target=/tmp/requirements.txt \
    <<EOF
    \
    apk add --update --no-cache curl jq
    pip3 install --disable-pip-version-check -r /tmp/requirements.txt
EOF

COPY ./rlr.py /usr/local/bin/
COPY --chmod=0755 ./rlr-jockey.py /usr/local/bin/rlr-jockey
ENTRYPOINT [ "/usr/local/bin/rlr-jockey" ]

COPY --from=common aliases.sh /etc/profile.d/

ENV PYTHONUNBUFFERED=1 ENV=/etc/profile
