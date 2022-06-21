FROM kalilinux/kali-rolling

RUN echo 'deb http://mirrors.dotsrc.org/kali kali-rolling main contrib non-free' > /etc/apt/sources.list \
&& apt-get update && apt-get install -y \
    python3-yaml \
    python3-jsonschema \
    sqlmap \
&& apt-get clean && rm -rf /var/lib/apt/lists/*

ENV PYTHONPATH=/usr/share/sqlmap
COPY ./openapi_sqlmap.py ./sqlmap-jockey.py /usr/share/sqlmap/
RUN ln -s '../share/sqlmap/sqlmap-jockey.py' /usr/bin/sqlmap-jockey

ENTRYPOINT [ "/usr/bin/sqlmap-jockey" ]
