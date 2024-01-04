# syntax=docker/dockerfile:1.4
##  gonna using heredoc facility, additional build context
##  build with DOCKER_BUILDKIT=1

FROM kalilinux/kali-rolling

COPY ./requirements.txt /tmp/

# Please do not forget about `--build-context ...=...`
COPY --from=zreprt . /usr/local/lib/zreprt/

RUN --mount=type=cache,target=/root/.cache/pip \
    --mount=type=cache,target=/var/cache/apt \
    <<EOF
    \
    echo 'deb http://mirrors.dotsrc.org/kali kali-rolling main contrib non-free' > /etc/apt/sources.list
    apt-get update
    apt-get install -y python3-pip sqlmap
    pip3 install --disable-pip-version-check -r /tmp/requirements.txt
    pip3 install --disable-pip-version-check --editable /usr/local/lib/zreprt
EOF

COPY ./openapi_sqlmap.py ./sqlmap-jockey.py /usr/share/sqlmap/
RUN ln -s '../share/sqlmap/sqlmap-jockey.py' /usr/bin/sqlmap-jockey
ENV PYTHONPATH="${PYTHONPATH}:/usr/share/sqlmap"

ENV PYTHONUNBUFFERED=1

ENTRYPOINT [ "/usr/bin/sqlmap-jockey" ]
