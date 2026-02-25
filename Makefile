.PHONY: build install

build:
	cargo build --release

install: build
	mkdir -p ~/.local/bin
	cp target/release/vt ~/.local/bin/vt
