SOURCE_NAME := kalilinux/kali-rolling
TARGET_NAME := kaplus

TAG := $(shell git rev-parse --short HEAD)
ifndef TAG
$(error TAG is not set; _x3_ what's being built.)
endif

GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
DOCKER_IMAGE := ${TARGET_NAME}:${TAG}
D_IMG_LATEST := ${TARGET_NAME}:latest

.DEFAULT_GOAL := build

.PHONY: full pull build


full: | pull build


pull:
	@echo "[make]  ---- pull ----"
	docker pull ${SOURCE_NAME}


build:
	@echo "[make]  ---- build ----"
	docker build --no-cache -t ${DOCKER_IMAGE} .
ifeq ($(GIT_BRANCH), main)
	docker tag ${DOCKER_IMAGE} ${D_IMG_LATEST}
else
	@echo "[make] Current branch is ${TARGET_NAME}. Skipping TAGging as latest."
endif
