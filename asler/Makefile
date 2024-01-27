TARGET_NAME := dast.asler

TAG := rlr-$(shell grep '^FROM restler:' Dockerfile | sed -e 's/^FROM restler://')

DKR_BLD_ADDITIONALS := --build-context common=../_common

include ../docker-recipes.mk
