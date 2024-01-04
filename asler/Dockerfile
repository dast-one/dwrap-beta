# syntax=docker/dockerfile:1.4
##  gonna using heredoc facility, additional build context
##  build with DOCKER_BUILDKIT=1

FROM restler:v9.2.3

# https://github.com/microsoft/restler-fuzzer/blob/main/docs/user-guide/Telemetry.md
ENV RESTLER_TELEMETRY_OPTOUT=1

ENV PYTHONUNBUFFERED=1 ENV=/etc/profile

COPY <<EOF /etc/profile.d/aliases.sh
alias ls='ls --color=auto'
alias ll='ls -l'
alias grep='grep --color=auto'
alias egrep='egrep --color=auto'
EOF

COPY ./requirements.txt /tmp/

# Please do not forget about `--build-context ...=...`
COPY --from=zreprt . /usr/local/lib/zreprt/

RUN --mount=type=cache,target=/root/.cache/pip \
    <<EOF
    \
    apk add --update --no-cache curl jq
    pip3 install --disable-pip-version-check -r /tmp/requirements.txt
    pip3 install --disable-pip-version-check --editable /usr/local/lib/zreprt
EOF

COPY ./rlr-jockey.py /usr/local/bin/rlr-jockey
COPY ./rlr.py /usr/local/bin/

ENTRYPOINT [ "/usr/local/bin/rlr-jockey" ]
