FROM projectdiscovery/nuclei

ENV PYTHONUNBUFFERED=1
RUN apk add --update --no-cache python3 && ln -sf python3 /usr/bin/python \
    && python3 -m ensurepip \
    && pip3 install --no-cache --upgrade pip setuptools \
  jsonschema

COPY ./nuclei-jockey.py /usr/local/bin/nuclei-jockey

RUN nuclei -update-templates
# ENTRYPOINT [ "nuclei", "-ni", "-duc" ]
ENTRYPOINT [ "/usr/local/bin/nuclei-jockey" ]
