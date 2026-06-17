# Self-contained mkosi build environment. Everything the build touches lives
# here, not on the host. mkosi is git-installed (it is NOT on PyPI). Run
# privileged with /dev mounted for loop devices + verity.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git xz-utils zstd cpio \
        python3 python3-pip \
        systemd systemd-boot systemd-boot-efi systemd-ukify \
        cryptsetup-bin \
        erofs-utils squashfs-tools dosfstools mtools e2fsprogs \
        gdisk dmsetup kmod util-linux binutils \
        apt dpkg debian-archive-keyring ubuntu-keyring \
        bubblewrap \
        linux-image-gcp ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# mkosi 26 from git (not published to PyPI). Works with the container's
# systemd 255 (matches the host where it reached initrd assembly).
RUN pip install --break-system-packages "git+https://github.com/systemd/mkosi.git@v26"

RUN mkosi --version
