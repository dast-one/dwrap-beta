FROM projectdiscovery/nuclei

RUN apk add --update --no-cache \
    python3 \
  && ln -sf python3 /usr/bin/python \
  && python3 -m ensurepip \
  && pip3 install --no-cache-dir --upgrade pip setuptools \
    jsonschema

COPY ./nuclei-jockey.py /usr/local/bin/nuclei-jockey

ENV PYTHONUNBUFFERED=1

RUN nuclei -update-templates

ENTRYPOINT [ "/usr/local/bin/nuclei-jockey" ]
