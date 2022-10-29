FROM owasp/zap2docker-stable

USER root

RUN apt-get update && apt-get install -y \
    python3-dateutil \
    python3-sqlalchemy \
    python3-psycopg2 \
  && apt-get clean && rm -rf /var/lib/apt/lists/* \
  && pip3 install --no-cache-dir --disable-pip-version-check \
    Jinja2 \
    jsonschema \
    docker

COPY ./templates-zap /usr/local/share/masc/
COPY ./zap-jockey.py /usr/local/bin/zap-jockey
# COPY ./.env ./zreprt-pgup.py /usr/local/bin/

ENV PYTHONUNBUFFERED=1

USER zap

RUN zap.sh -cmd -addonupdate && \
    zap.sh -cmd -addoninstall jython && \
    zap.sh -cmd -addoninstall sqliplugin

ENTRYPOINT [ "/usr/local/bin/zap-jockey" ]
