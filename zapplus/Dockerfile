FROM owasp/zap2docker-stable

USER root
COPY ./templates-zap /usr/local/share/masc/
COPY ./zap-jockey /usr/local/bin/
RUN pip3 install --no-cache-dir \
    Jinja2 \
    jsonschema \
    docker

USER zap

RUN zap.sh -cmd -addonupdate && \
    zap.sh -cmd -addoninstall jython && \
    zap.sh -cmd -addoninstall sqliplugin
