# Throwaway image-build environment for the two-tier SEV-SNP image (base UKI +
# app partition). Uses ukify + systemd-repart (two-tier UKI, no full-OS rootfs). Run
# privileged with /dev mounted for the loop-free systemd-repart disk assembly.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Cloud-specific kernel: linux-image-gcp or linux-image-aws. Each ships a few
# non-builtin modules the loader bundles+inserts (gve on GCP, sev-guest on AWS).
ARG KERNEL_PKG=linux-image-gcp

# systemd-boot-efi (the UKI stub) and systemd-ukify (the UKI builder) are pinned
# because the stub is embedded in the base UKI and thus measured into PCR 11.
RUN apt-get update && apt-get install -y --no-install-recommends \
        systemd \
        systemd-boot-efi=255.4-1ubuntu8.16 systemd-ukify=255.4-1ubuntu8.16 \
        dosfstools mtools \
        zstd cpio binutils \
        "${KERNEL_PKG}" ca-certificates \
        python3 \
    && rm -rf /var/lib/apt/lists/*
