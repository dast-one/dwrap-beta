#!/bin/bash

function pull_n_dump {
    IMG="$1"
    FNAME="$2"
    [ -z "$IMG" -o -z "$FNAME" ] && exit 0
    set -o xtrace
    docker pull "${IMG}" || exit 1
    docker save "${IMG}" | xz -T0 > "${FNAME}.txz"
    openssl enc -aes-256-cbc -pbkdf2 -nosalt -pass 'pass:typoscramble' \
        -in "${FNAME}.txz" -out "${FNAME}.txz.ebin"
    sha256sum "${FNAME}.txz" "${FNAME}.txz.ebin" > "${FNAME}.sha256"
    rm "${FNAME}.txz"
    set +o xtrace
}

case "$1" in

    g|goatandwolf)
        pull_n_dump "webgoat/goatandwolf" "webgoat-goatandwolf"
    ;;

    j|juiceshop)
        pull_n_dump "bkimminich/juice-shop" "juice-shop"
    ;;

    c|chisel)
        pull_n_dump "jpillora/chisel" "chisel"
    ;;

    *)
        echo "USAGE: $0 "'{ g|goatandwolf | j|juiceshop | c|chisel }'
    ;;

esac
