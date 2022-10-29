FROM openapitools/openapi-generator-cli

COPY oapiconv-jockey /usr/local/bin/

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["oapiconv-jockey"]

WORKDIR /wrk
