TAG := $(shell git rev-parse --short HEAD)
ifndef TAG
$(error TAG is not set; _x3_ what's being built.)
endif

GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
DOCKER_IMAGE := ${TARGET_NAME}:${TAG}
D_IMG_LATEST := ${TARGET_NAME}:latest

.DEFAULT_GOAL := express-build


.PHONY: full
full: | pull build

.PHONY: pull
pull:
	@echo "[make]  ---- pull ----"
	docker pull ${SOURCE_NAME}

.PHONY: express-build
express-build:
	@echo "[make]  ---- build ----"
	docker build -t ${DOCKER_IMAGE} .

.PHONY: build
build:
	@echo "[make]  ---- build ----"
	docker build --pull --no-cache -t ${DOCKER_IMAGE} .
ifeq ($(GIT_BRANCH), main)
	docker tag ${DOCKER_IMAGE} ${D_IMG_LATEST}
else
	@echo "[make] Current branch is ${GIT_BRANCH}. Skipping TAGging as latest."
endif

.PHONY: dump
dump:
	docker save ${D_IMG_LATEST} | xz -eT0 > "${TARGET_NAME}.txz"
	openssl enc -aes-256-cbc -pbkdf2 -nosalt -pass 'pass:typoscramble'  \
	  -in "${TARGET_NAME}.txz" -out "${TARGET_NAME}.txz.ebin"
	sha256sum "${TARGET_NAME}.txz" "${TARGET_NAME}.txz.ebin" > "${TARGET_NAME}.sha256"
	rm "${TARGET_NAME}.txz"
