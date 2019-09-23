Linux installation on Qemu
===

First, you need to install [qemu](https://www.qemu.org/) to emulate ARM architecture. After that you can install Linux Debian for ARM32.

**Note:** Installation requires few hours

```bash
# Install qemu
sudo apt-get install qemu-system-arm
cd drtaint/qemu

# Get the installer files
wget -O installer-vmlinuz http://http.us.debian.org/debian/dists/stretch/main/installer-armhf/current/images/netboot/vmlinuz
wget -O installer-initrd.gz http://http.us.debian.org/debian/dists/stretch/main/installer-armhf/current/images/netboot/initrd.gz

# Create image file for linux filesystem and start installation
qemu-img create -f qcow2 hda.qcow2 8G
sudo sh ./install_deb.sh
```

Install Linux


<div style="text-align:center;">
<img title="qemu_install" alt="qemu_install" width="500" src="/assets/qemu_install.PNG"/>
</div>
<br>

Unfortunately, bootloader **will not** be installed. So, few hours later you will see this:

<div style="text-align:center;">
<img title="bootloader_failed" alt="bootloader_failed" width="500" src="/assets/bootloader_failed.PNG"/>
</div>
<br>

Enter *Continue* few times and then choose next item after GRUB in Linux installation menu. 

<div style="text-align:center;">
<img title="continue" alt="continue" width="500" src="/assets/continue.PNG"/>
</div>
<br>

You will see Linux is finishing installation. On completion, press *Continue* again and wait for system shutdown.

<div style="text-align:center;">
<img title="finish_install" alt="finish_install" width="500" src="/assets/finish_install.PNG"/>
</div>
<br>

After shutdown you need to copy out right *vmlinuz* and *initrd.img* manually:

```bash
# We will do it with libguestfs
sudo apt-get install libguestfs-tools
virt-copy-out -a hda.qcow2 /boot .
sudo sh ./launch_deb.sh
```

You have a tty access

<div style="text-align:center;">
<img title="linux_boot" alt="linux_boot" width="500" src="/assets/linux_boot.PNG"/>
</div>
<br>

And also a ssh access from Linux host

<div style="text-align:center;">
<img title="linux_ssh" alt="linux_ssh" width="500" src="/assets/linux_ssh.PNG"/>
</div>
<br>

Almost everything is done! Finally, login as root and enter commands below:

```bash
# Enable 'sudo' command for your user 
apt install sudo
export USERNAME="<your-username>"
echo "$USERNAME ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers

# Login as user and check it worked
su $USERNAME

# Output must be 'root'
sudo whoami

# Setup profile
echo "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" >> ~/.bashrc
```

Enjoy :)

---
If you've encountered some challenges, these links might help:

- https://translatedcode.wordpress.com/2016/11/03/installing-debian-on-qemus-32-bit-arm-virt-board/
- https://gist.github.com/Liryna/10710751

