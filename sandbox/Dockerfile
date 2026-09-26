FROM kalilinux/kali-rolling:latest

# Development image only. The release gate requires a digest-pinned base,
# package lock, inventory verification, SBOM, and license review.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       kali-linux-headless kali-tools-web kali-tools-reverse-engineering \
       ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# The runtime enforces the numeric UID even if this image-level name is unavailable.
RUN useradd --uid 65534 --non-unique --home-dir /tmp shadow || true
USER 65534:65534
WORKDIR /workspace
