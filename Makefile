.DEFAULT_GOAL := release

TARGET ?= x86_64-unknown-linux-musl
CARGO_TARGET_DIR ?= target
OUTPUT ?= dist/telegraff
BINARY ?= $(CARGO_TARGET_DIR)/$(TARGET)/release/telegraff
export CARGO_TARGET_DIR

.PHONY: release check-build-tools verify-static

# Build dependencies are needed only on the build host, not the destination VPS.
release: check-build-tools
	rustup target add $(TARGET)
	cargo build --release --locked --target $(TARGET)
	$(MAKE) verify-static
	install -D -m 0755 "$(BINARY)" "$(OUTPUT).new"
	mv -f "$(OUTPUT).new" "$(OUTPUT)"
	@echo "Static release: $(OUTPUT) ($(TARGET))"

check-build-tools:
	@case "$(TARGET)" in *-unknown-linux-musl) ;; *) echo 'TARGET must be a Linux musl target'; exit 1 ;; esac
	@command -v cargo >/dev/null || { echo 'Install Rust using rustup first'; exit 1; }
	@command -v rustup >/dev/null || { echo 'Install rustup first'; exit 1; }
	@command -v readelf >/dev/null || { echo 'Install binutils first'; exit 1; }
	@command -v musl-gcc >/dev/null || { echo 'Install musl-tools (Debian/Ubuntu) or configure a musl cross compiler'; exit 1; }

verify-static:
	@readelf -h "$(BINARY)" >/dev/null
	@readelf -lW "$(BINARY)" | awk '/INTERP/ { print "ERROR: binary has a dynamic loader"; exit 1 }'
	@readelf -dW "$(BINARY)" | awk '/NEEDED/ { print "ERROR: binary requires a shared library"; exit 1 }'
	@echo 'Verified: no dynamic loader or shared-library dependencies'
