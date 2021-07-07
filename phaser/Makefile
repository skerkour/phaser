NAME = phaser
COMMIT = $(shell git rev-parse HEAD)
DATE := $(shell date +"%Y-%m-%d")
DIST_DIR = dist
TARGET_DIR = target
RELEASE_BINARY = target/release/$(NAME)
TAKEOVER_FINGERPRINTS_FILE = takeover_fingerprints.json

.PHONY: all
all: build


.PHONY: build
build:
	mkdir -p $(DIST_DIR)
	cargo build --release
	cp -r $(RELEASE_BINARY) $(DIST_DIR)/
	cp $(TAKEOVER_FINGERPRINTS_FILE) $(DIST_DIR)/$(TAKEOVER_FINGERPRINTS_FILE)


.PHONY: build_dev
build_dev:
	cargo build


.PHONY: build_static
build_static:
	mkdir -p $(DIST_DIR)
	cargo build --target x86_64-unknown-linux-musl --release
	cp target/x86_64-unknown-linux-musl/release/$(NAME) $(DIST_DIR)/$(NAME)
	cp $(TAKEOVER_FINGERPRINTS_FILE) $(DIST_DIR)/$(TAKEOVER_FINGERPRINTS_FILE)


.PHONY: check
check:
	cargo check


.PHONY: fmt
fmt:
	cargo +nightly fmt


.PHONY: lint
lint:
	cargo +nightly fmt -- --check
	cargo clippy -- -D warnings


.PHONY: vendor
vendor:
	cargo vendor vendor


# Update dependencies
.PHONY: update
update:
	rm -rf vendor && mv .cargo/config.toml .cargo/config_tmp.toml
	cargo update
	mv .cargo/config_tmp.toml .cargo/config.toml
	make vendor


.PHONY: test
test:
	# cargo test --doc --all
	cargo test --all


.PHONY: clean
clean:
	rm -rf $(DIST_DIR) $(TARGET_DIR)


.PHONY: publish
publish:
	cargo publish
