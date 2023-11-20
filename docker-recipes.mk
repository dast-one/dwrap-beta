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
	docker build --build-context d1kit=/opt/d1/src/dyna-misc/d1kit-pkg -t ${DOCKER_IMAGE} .

.PHONY: full
full:
	@echo "[make]  ---- full-build ----"
	docker build --build-context d1kit=/opt/d1/src/dyna-misc/d1kit-pkg --no-cache ${DKR_BLD_ADDITIONALS} -t ${DOCKER_IMAGE} .
ifdef TAG
	docker tag ${DOCKER_IMAGE} ${TARGET_NAME}:${TAG}
endif
