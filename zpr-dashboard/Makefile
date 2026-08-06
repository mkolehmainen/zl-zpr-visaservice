BINARY      := zpr-dashboard
CMD_PATH    := ./cmd/zpr-dashboard
SIM_PATH    := ./cmd/zpr-sim
BIN_DIR     := bin
BIN         := $(BIN_DIR)/$(BINARY)
SIM         := $(BIN_DIR)/zpr-sim

GO          := go
GOFLAGS     :=
LDFLAGS     := -s -w

.DEFAULT_GOAL := build

.PHONY: all
all: clean fmt build sim

.PHONY: build
build: $(BIN)

$(BIN): $(shell find . -name '*.go') go.mod go.sum
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) $(CMD_PATH)

.PHONY: run
run:
	$(GO) run $(CMD_PATH)

.PHONY: sim
sim: $(SIM)

$(SIM): $(shell find . -name '*.go') go.mod go.sum
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -trimpath -ldflags '$(LDFLAGS)' -o $(SIM) $(SIM_PATH)

.PHONY: seed
seed:
	$(GO) run $(SIM_PATH) seed

.PHONY: unseed
unseed:
	$(GO) run $(SIM_PATH) unseed

.PHONY: status
status:
	$(GO) run $(SIM_PATH) status

.PHONY: simulate
simulate:
	$(GO) run $(SIM_PATH) run

.PHONY: install
install:
	$(GO) install $(GOFLAGS) -trimpath -ldflags '$(LDFLAGS)' $(CMD_PATH)

.PHONY: fmt
fmt:
	$(GO) fmt ./...

.PHONY: clean
clean:
	rm -rf $(BIN_DIR)
