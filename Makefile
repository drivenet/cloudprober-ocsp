VERSION ?= $(shell git describe --tags)
DOCKER_VERSION ?= $(VERSION)
GIT_COMMIT = $(strip $(shell git rev-parse --short HEAD))
DOCKER_PREFIX = "docker.pkg.github.com/drivenet/cloudprober-ocsp"
DOCKER_IMAGE ?= $(DOCKER_PREFIX)/cloudprober

test:
	go test -v -race -covermode=atomic ./...

docker_build: deps protoc Dockerfile
	docker build \
		--build-arg BUILD_DATE=`date -u +"%Y-%m-%dT%H:%M:%SZ"` \
		--build-arg VERSION=$(VERSION) \
		--build-arg VCS_REF=$(GIT_COMMIT) \
		-t $(DOCKER_IMAGE)  .

docker_push:
	docker login -u "${DOCKER_USER}" -p "${DOCKER_PASS}" ${DOCKER_REGISTRY}
	docker push $(DOCKER_IMAGE):latest

docker_push_tagged:
	docker tag $(DOCKER_IMAGE) $(DOCKER_IMAGE):$(DOCKER_VERSION)
	docker login -u "${DOCKER_USER}" -p "${DOCKER_PASS}" ${DOCKER_REGISTRY}
	docker push $(DOCKER_IMAGE):$(DOCKER_VERSION)

docker_release: docker_build docker_push

# Dependencies
deps:
	@go mod tidy -v
	@go mod vendor

protoc: LIBS:=""
protoc:
	@find . -type f -name '*.proto' -not -path './vendor/*' \
		-exec protoc \
		--proto_path=$(GOPATH)/src:./vendor:. \
		--gofast_out=plugins=$(LIBS):. '{}' \;