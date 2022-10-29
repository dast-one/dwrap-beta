FROM kalilinux/kali-rolling

RUN echo 'deb http://mirrors.dotsrc.org/kali kali-rolling main contrib non-free' > /etc/apt/sources.list \
  && apt-get update && apt-get install -y \
    python3-yaml \
    python3-jsonschema \
    sqlmap \
    python3-dateutil \
    python3-sqlalchemy \
    python3-psycopg2 \
  && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY ./openapi_sqlmap.py ./sqlmap-jockey.py /usr/share/sqlmap/
# COPY ./.env ./zreprt-pgup.py /usr/share/sqlmap/
RUN ln -s '../share/sqlmap/sqlmap-jockey.py' /usr/bin/sqlmap-jockey
ENV PYTHONPATH="${PYTHONPATH}:/usr/share/sqlmap"

ENV PYTHONUNBUFFERED=1

ENTRYPOINT [ "/usr/bin/sqlmap-jockey" ]
