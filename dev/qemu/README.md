# Linux installation on Qemu

First, you need to install [qemu](https://www.qemu.org/) to emulate ARM architecture. After that you can install Linux Debian for ARM32. For installation you can follow instructions below.

**Note:** Installation requires few hours

```bash=
# Go to work folder
cd DrTaint/dev/qemu

# Get the installer files
wget -O installer-vmlinuz http://http.us.debian.org/debian/dists/stretch/main/installer-armhf/current/images/netboot/vmlinuz
wget -O installer-initrd.gz http://http.us.debian.org/debian/dists/stretch/main/installer-armhf/current/images/netboot/initrd.gz

# Create image file for linux filesystem and start installation
qemu-img create -f qcow2 hda.qcow2 8G
sudo sh ./install_deb.sh
```

After that you'll see Linux installation prompt in terminal. Do it as usual: *yes, continue, ...*


<div style="text-align:center;">
<img title="Linux installation" alt="Linux installation" width="500" src="/assets/qemu_install.PNG"/>
</div>
<br>

Unfortunately, bootloader **will not** be installed. So, few hours later you will see this:

<div style="text-align:center;">
<img title="Linux installation" alt="Linux installation" width="500" src="/assets/bootloader_failed.PNG"/>
</div>
<br>

Enter *Continue* few times and then choose next item after GRUB in Linux installation menu. You will see Linux is finishing installation. On completion, press *Continue* again and wait for system shutdown.

<div style="text-align:center;">
<img title="Linux installation" alt="Linux installation" width="500" src="/assets/finish_install.PNG"/>
</div>
<br>

After shutdown enter these commads:
```bash=
clear
mkdir boot

# Mount hda.cow2 image. Wait few seconds
sudo sh sudo sh ./mount_deb_fs.sh
```

Now you have an access to Linux filesystem and boot files. You need to copy bootloader files *initrd.img-XXX* and *vmlinuz-XXX* to *boot* folder which you've created.

![](/assets/mounted_fs.PNG)

Now, you're ready to boot your Linux:
```bash=
sudo sh ./unmount_deb_fs.sh
mv boot/initrd.img-* boot/initrd.img
mv boot/vmlinuz-* boot/vmlinuz
sudo sh ./launch_deb.sh
```

You have a tty access

<div style="text-align:center;">
<img title="Linux installation" alt="Linux installation" width="500" src="/assets/linux_boot.PNG"/>
</div>
<br>

And also a ssh access from Linux host

<div style="text-align:center;">
<img title="Linux installation" alt="Linux installation" width="500" src="/assets/linux_ssh.PNG"/>
</div>
<br>

Almost everything is done! Finally, login as root and enter commands below:

```bash=
# Enable 'sudo' command for your user 
apt install sudo
export USERNAME="<your-username>"
echo "$USERNAME ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers

# Login as user and check it worked
su $USERNAME

# Output must be 'root'
sudo whoami

# Setup profile
echo "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" >> .bashrc
```

Enjoy :)

---
If you've encountered some challenges, these links might help:

- https://translatedcode.wordpress.com/2016/11/03/installing-debian-on-qemus-32-bit-arm-virt-board/
- https://gist.github.com/Liryna/10710751
