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

# Please do not forget about --build-context d1kit=...
COPY --from=d1kit . /usr/local/lib/d1kit/

RUN apk add --update --no-cache jq \
  && pip3 install --disable-pip-version-check --no-cache-dir jsonschema pydantic \
  && cd /usr/local/lib/d1kit \
  && pip3 install --disable-pip-version-check --no-cache-dir --editable . --config-settings editable_mode=compat

COPY ./rlr-jockey.py /usr/local/bin/rlr-jockey
COPY ./rlr.py /usr/local/bin/
# ENV PYTHONPATH=${PYTHONPATH}:/usr/local/bin

ENTRYPOINT [ "/usr/local/bin/rlr-jockey" ]
