
NAME = phaser
COMMIT = $(shell git rev-parse HEAD)
DATE := $(shell date +"%Y-%m-%d")
DOCKER_IMAGE = ghcr.io/skerkour/phaser


.PHONY: all
all: docker


.PHONY: release
release:
	git checkout release
	git merge main
	git push
	git checkout main


.PHONY: docker
docker:
	docker build -t $(DOCKER_IMAGE):latest .


.PHONY: docker_release
docker_release:
	docker push $(DOCKER_IMAGE):latest
