BINARY := tf
DIST := dist

GOOS_LIST := linux darwin windows
GOARCH_LIST := amd64 arm64

.PHONY: build build-all clean

build:
	@mkdir -p $(DIST)
	CGO_ENABLED=0 go build -o $(DIST)/$(BINARY)$(if $(filter windows,$(shell go env GOOS)),.exe,) ./cmd/tf

build-all:
	@mkdir -p $(DIST)
	@$(foreach goos,$(GOOS_LIST),\
		$(foreach goarch,$(GOARCH_LIST),\
			echo "Building $(goos)/$(goarch)..." && \
			CGO_ENABLED=0 GOOS=$(goos) GOARCH=$(goarch) go build -o $(DIST)/$(BINARY)_$(goos)_$(goarch)$(if $(filter windows,$(goos)),.exe,) ./cmd/tf && \
		) \
	) true

clean:
	rm -rf $(DIST)
