build:
    cargo build --release

install: build
    mkdir -p ~/.local/bin
    cp target/release/vt ~/.local/bin/vt

ssh:
    ssh -A -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -i .vagrant/machines/default/libvirt/private_key \
        vagrant@192.168.121.242
