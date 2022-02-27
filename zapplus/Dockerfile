FROM owasp/zap2docker-stable

USER root
COPY ./templates-zap /usr/local/share/masc/
COPY ./zap-jockey /usr/local/bin/
RUN pip3 install --no-cache-dir \
    Jinja2 \
    jsonschema \
    docker

# Writing reports to mounted volumes as non-root
# is not supported in asc.runner environment.
# As soon as that's fixed,
#   - uncomment switching to `zap` user,
#   - and remove copying home-stuff below.

# USER zap

RUN cp -rv /home/zap/. /root; \
    zap.sh -cmd -addonupdate && \
    zap.sh -cmd -addoninstall jython && \
    zap.sh -cmd -addoninstall sqliplugin
