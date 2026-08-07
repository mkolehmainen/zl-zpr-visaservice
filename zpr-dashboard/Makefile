BINARY      := zpr-dashboard
CMD_PATH    := ./cmd/zpr-dashboard
BIN_DIR     := bin
BIN         := $(BIN_DIR)/$(BINARY)

GO          := go
GOFLAGS     :=
LDFLAGS     := -s -w

.DEFAULT_GOAL := build

.PHONY: all
all: clean fmt build 

.PHONY: build
build: $(BIN)

$(BIN): $(shell find . -name '*.go') go.mod go.sum
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) $(CMD_PATH)

.PHONY: run
run:
	$(GO) run $(CMD_PATH)

.PHONY: status
status:
	$(GO) run $(SIM_PATH) status

.PHONY: install
install:
	$(GO) install $(GOFLAGS) -trimpath -ldflags '$(LDFLAGS)' $(CMD_PATH)

.PHONY: fmt
fmt:
	$(GO) fmt ./...

.PHONY: clean
clean:
	rm -rf $(BIN_DIR)
