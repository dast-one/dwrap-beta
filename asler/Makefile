TARGET_NAME := dast.asler

TAG := rlr-$(shell grep '^FROM restler:' Dockerfile | sed -e 's/^FROM restler://')
DKR_BLD_ADDITIONALS := --build-context zreprt=../../zreprt

include ../docker-recipes.mk
