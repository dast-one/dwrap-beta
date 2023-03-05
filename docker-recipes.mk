ifndef TAG
TAG := git-$(shell git rev-parse --short HEAD)
endif

ifndef TARGET_NAME
$(error TARGET_NAME is not set; _x3_ what's being built.)
endif
DOCKER_IMAGE := ${TARGET_NAME}:latest

.DEFAULT_GOAL := express-build


.PHONY: express-build
express-build:
	@echo "[make]  ---- express-build ----"
	docker build -t ${DOCKER_IMAGE} .

.PHONY: full
full:
	@echo "[make]  ---- full-build ----"
# 	docker build --pull --no-cache -t ${DOCKER_IMAGE} .
	docker build --no-cache ${DKR_BLD_ADDITIONALS} -t ${DOCKER_IMAGE} .
ifdef TAG
	docker tag ${DOCKER_IMAGE} ${TARGET_NAME}:${TAG}
endif

.PHONY: dump
dump:
	docker save ${DOCKER_IMAGE} | xz -T0 > "${TARGET_NAME}.txz"
	sha256sum "${TARGET_NAME}.txz" > "${TARGET_NAME}.sha256"
ifdef SCP_TO
	scp "${TARGET_NAME}.txz" "${TARGET_NAME}.sha256" "${SCP_TO}"
	rm "${TARGET_NAME}.txz" "${TARGET_NAME}.sha256"
endif

.PHONY: scramble
scramble:
	openssl enc -aes-256-cbc -pbkdf2 -nosalt -pass 'pass:typoscramble'  \
	  -in "${TARGET_NAME}.txz" -out "${TARGET_NAME}.txz.ebin"
	sha256sum "${TARGET_NAME}.txz.ebin" >> "${TARGET_NAME}.sha256"
	rm "${TARGET_NAME}.txz"
