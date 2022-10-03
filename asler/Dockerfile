# syntax=docker/dockerfile:1.4
##  gonna using heredoc facility
##  build with DOCKER_BUILDKIT=1

FROM restler:main-c1ace0c

ENV PYTHONUNBUFFERED=1 ENV=/etc/profile

COPY <<EOF /etc/profile.d/aliases.sh
alias ls='ls --color=auto'
alias ll='ls -l'
alias eg='egrep --color=auto'
EOF

RUN apk add --update --no-cache jq \
  && pip3 install --disable-pip-version-check --no-cache-dir jsonschema

COPY ./rlr-jockey.py /usr/local/bin/rlr-jockey
# COPY ./.env ./zreprt-pgup.py /usr/local/bin/

ENTRYPOINT [ "/usr/local/bin/rlr-jockey" ]
