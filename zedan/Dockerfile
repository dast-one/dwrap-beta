FROM ghcr.io/zaproxy/zaproxy:stable

USER root

RUN pip3 install --no-cache-dir --disable-pip-version-check \
    Jinja2 \
    jsonschema

COPY ./templates /usr/local/share/zap-templates/
COPY ./zap-jockey.py /usr/local/bin/zap-jockey

ENV PYTHONUNBUFFERED=1

USER zap

RUN zap.sh -cmd -addonupdate && \
    zap.sh -cmd -addoninstall jython && \
    zap.sh -cmd -addoninstall sqliplugin

ENTRYPOINT [ "/usr/local/bin/zap-jockey" ]
