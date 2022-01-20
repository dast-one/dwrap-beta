FROM owasp/zap2docker-stable

USER root
COPY ./templates-zap /usr/local/share/masc/
COPY ./zap-jockey.py /usr/local/bin/
RUN pip3 install --no-cache-dir \
    Jinja2 \
    jsonschema \
    docker

# Writing reports to mounted volumes as non-root not supported in asc.runner environment.
#   Uncomment switching to `zap` user when that's fixed.
#   And remove copying home-stuff.
# USER zap
RUN cp -rv /home/zap/. /root

RUN zap.sh -cmd -addonupdate
RUN zap.sh -cmd -addoninstall jython
