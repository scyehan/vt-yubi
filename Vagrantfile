Vagrant.configure("2") do |config|
  config.vm.box = "debian/bookworm64"
  config.vm.hostname = "vt-test"

  # Forward agent only after SSH session is established, not during vagrant's
  # own boot/provision connection (net-ssh crashes with the vt SSH agent).
  config.ssh.forward_agent = false
  config.vm.synced_folder ".", "/vagrant", disabled: true

  config.vm.provision "file", source: "target/release/vt", destination: "/tmp/vt"
  config.vm.provision "file", source: "setup-pam.sh", destination: "/tmp/setup-pam.sh"

  config.vm.provision "shell", inline: <<-SHELL
    cp /tmp/vt /usr/local/bin/vt
    chmod +x /usr/local/bin/vt
    cp /tmp/setup-pam.sh /usr/local/bin/setup-pam.sh
    chmod +x /usr/local/bin/setup-pam.sh

    # Require password for sudo (replace NOPASSWD with password-required)
    echo 'vagrant ALL=(ALL) ALL' > /etc/sudoers.d/vagrant
    chmod 440 /etc/sudoers.d/vagrant
    echo 'vagrant:vagrant' | chpasswd
  SHELL
end
