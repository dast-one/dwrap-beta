FROM openapitools/openapi-generator-cli

COPY --chmod=0755 oapiconv-jockey /usr/local/bin/

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["oapiconv-jockey"]

WORKDIR /wrk
