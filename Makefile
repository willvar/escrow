.PHONY: check check-format format go-test go-vet golden vue-build vue-check vue-format vue-format-check vue-install vue-test

GO_FILES := $(shell find . -name '*.go' -not -path './vue/node_modules/*' -not -path './vue/dist/*')

check: check-format go-test go-vet vue-format-check vue-check vue-test vue-build

format:
	gofmt -w $(GO_FILES)

check-format:
	@test -z "$$(gofmt -l $(GO_FILES))" || { gofmt -l $(GO_FILES); exit 1; }

go-test:
	GOWORK=off go test ./...

go-vet:
	GOWORK=off go vet ./...

golden:
	GOWORK=off go run ./scripts/golden

vue-install:
	npm --prefix vue install

vue-check:
	npm --prefix vue run check

vue-format:
	npm --prefix vue run format

vue-format-check:
	npm --prefix vue run format:check

vue-test:
	npm --prefix vue test

vue-build:
	npm --prefix vue run build
