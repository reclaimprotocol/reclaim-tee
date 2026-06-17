# Throwaway image-build environment for the two-tier SEV-SNP image (base UKI +
# app partition). Uses ukify + systemd-repart (two-tier UKI, no full-OS rootfs). Run
# privileged with /dev mounted for the loop-free systemd-repart disk assembly.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        systemd systemd-boot-efi systemd-ukify \
        dosfstools mtools \
        zstd cpio binutils \
        linux-image-gcp ca-certificates \
        python3 \
    && rm -rf /var/lib/apt/lists/*
