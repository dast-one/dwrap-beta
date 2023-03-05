# syntax=docker/dockerfile:1.4
##  gonna using heredoc facility, additional build context
##  build with DOCKER_BUILDKIT=1

FROM restler:50944ac

ENV PYTHONUNBUFFERED=1 ENV=/etc/profile

COPY <<EOF /etc/profile.d/aliases.sh
alias ls='ls --color=auto'
alias ll='ls -l'
alias eg='egrep --color=auto'
EOF

# Please do not forget about --build-context d1kit=...
COPY --from=d1kit . /usr/local/lib/d1kit/

RUN apk add --update --no-cache jq \
  && pip3 install --disable-pip-version-check --no-cache-dir jsonschema pydantic \
  && cd /usr/local/lib/d1kit \
  && pip3 install --disable-pip-version-check --no-cache-dir --editable .

COPY ./rlr-jockey.py /usr/local/bin/rlr-jockey
COPY ./rlr.py /usr/local/bin/
ENV PYTHONPATH=${PYTHONPATH}:/usr/local/bin

ENTRYPOINT [ "/usr/local/bin/rlr-jockey" ]
