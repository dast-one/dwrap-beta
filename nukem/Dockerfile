FROM projectdiscovery/nuclei

RUN apk add --update --no-cache \
    python3 postgresql-dev gcc python3-dev musl-dev \
  && ln -sf python3 /usr/bin/python \
  && python3 -m ensurepip \
  && pip3 install --no-cache-dir --upgrade pip setuptools \
    jsonschema \
    dateutils psycopg2 sqlalchemy

COPY ./nuclei-jockey.py /usr/local/bin/nuclei-jockey
# COPY ./.env ./zreprt-pgup.py /usr/local/bin/

ENV PYTHONUNBUFFERED=1

RUN nuclei -update-templates

ENTRYPOINT [ "/usr/local/bin/nuclei-jockey" ]
