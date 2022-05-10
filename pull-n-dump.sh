#!/bin/bash

function scrambledump {
    IMG="${1}"
    FNAME="${1//[^A-Za-z0-9]/-}"
    [ -z "$IMG" -o -z "$FNAME" ] && exit 0
    set -o xtrace
    docker save "${IMG}" | xz -eT0 > "${FNAME}.txz"
    openssl enc -aes-256-cbc -pbkdf2 -nosalt -pass 'pass:typoscramble' \
        -in "${FNAME}.txz" -out "${FNAME}.txz.ebin"
    sha256sum "${FNAME}.txz" "${FNAME}.txz.ebin" > "${FNAME}.sha256"
    rm "${FNAME}.txz"
    set +o xtrace
}

case "$1" in

    oapitools)
        IMG="swaggerapi/swagger-editor"
        docker pull "${IMG}" && scrambledump "${IMG}"
        IMG="openapitools/openapi-generator-cli"
        docker pull "${IMG}" && scrambledump "${IMG}"
        IMG="node:16-slim"
        docker pull "${IMG}" || exit 1
        # scrambledump "${IMG}"
        echo -e "FROM ${IMG}"'\nRUN npm i postman-to-openapi -g' | docker build -t postman-to-openapi -
        scrambledump "postman-to-openapi"
    ;;

    goat)
        IMG="webgoat/goatandwolf"
        docker pull "${IMG}" && scrambledump "${IMG}"
    ;;

    juice)
        IMG="bkimminich/juice-shop"
        docker pull "${IMG}" && scrambledump "${IMG}"
    ;;

    chisel)
        IMG="jpillora/chisel"
        docker pull "${IMG}" || exit 1
        scrambledump "${IMG}"
        echo -e "FROM ${IMG}"'\nCMD ["client", "--fingerprint", "mdHLmDMW3hRNwGXalt+4lnXWSYX2+zgzs2igAc2mIC0=", "10.73.133.28:8080", "R:socks"]' | docker build -t dastembass -
        scrambledump "dastembass"
        # server-side would be:
        # CMD ["server", "--reverse", "--socks5", "--key", "klmn"]
    ;;

    mongo)
        IMG="mongo"
        docker pull "${IMG}" && scrambledump "${IMG}"
    ;;

    *)
        echo "USAGE: $0 "'{ goat | juice | chisel | mongo }'
    ;;

esac
