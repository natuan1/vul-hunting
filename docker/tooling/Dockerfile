# Tooling image cho Recon Phase (ticket #8) — cũng là terminal.docker_image
# cho sandbox verification (ticket #11, ADR-0003).
#
# Version các tool ghi rõ dưới đây (pin cứng, có kiểm tra checksum SHA-256
# từ checksums.txt chính thức của từng release).

FROM debian:bookworm-slim

ARG TARGETARCH=amd64

ARG SUBFINDER_VERSION=2.16.0
ARG AMASS_VERSION=5.1.1
ARG DNSX_VERSION=1.3.1
ARG NAABU_VERSION=2.6.1
ARG HTTPX_VERSION=1.11.0

LABEL org.opencontainers.image.title="vulhunt-tooling" \
      org.opencontainers.image.description="Recon CLI tools: subfinder/amass/dnsx/naabu/httpx" \
      org.opencontainers.image.licenses="MIT"

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl unzip \
 && rm -rf /var/lib/apt/lists/*

# ── subfinder ──
RUN curl --retry 3 --retry-delay 2 -sfL "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${TARGETARCH}.zip" -o "/tmp/subfinder_${SUBFINDER_VERSION}_linux_${TARGETARCH}.zip" \
 && curl --retry 3 --retry-delay 2 -sfL "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_checksums.txt" -o /tmp/subfinder.sha256 \
 && (cd /tmp && grep "subfinder_${SUBFINDER_VERSION}_linux_${TARGETARCH}.zip" subfinder.sha256 | sha256sum -c -) \
 && unzip -o "/tmp/subfinder_${SUBFINDER_VERSION}_linux_${TARGETARCH}.zip" subfinder -d /usr/local/bin \
 && rm /tmp/subfinder_*.zip /tmp/subfinder.sha256

# ── dnsx ──
RUN curl --retry 3 --retry-delay 2 -sfL "https://github.com/projectdiscovery/dnsx/releases/download/v${DNSX_VERSION}/dnsx_${DNSX_VERSION}_linux_${TARGETARCH}.zip" -o "/tmp/dnsx_${DNSX_VERSION}_linux_${TARGETARCH}.zip" \
 && curl --retry 3 --retry-delay 2 -sfL "https://github.com/projectdiscovery/dnsx/releases/download/v${DNSX_VERSION}/dnsx_${DNSX_VERSION}_checksums.txt" -o /tmp/dnsx.sha256 \
 && (cd /tmp && grep "dnsx_${DNSX_VERSION}_linux_${TARGETARCH}.zip" dnsx.sha256 | sha256sum -c -) \
 && unzip -o "/tmp/dnsx_${DNSX_VERSION}_linux_${TARGETARCH}.zip" dnsx -d /usr/local/bin \
 && rm /tmp/dnsx_*.zip /tmp/dnsx.sha256

# ── naabu (Cần CAP_NET_RAW cho SYN scan — docker run mặc định đã cấp) ──
RUN curl --retry 3 --retry-delay 2 -sfL "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_${TARGETARCH}.zip" -o "/tmp/naabu_${NAABU_VERSION}_linux_${TARGETARCH}.zip" \
 && curl --retry 3 --retry-delay 2 -sfL "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu-checksums.txt" -o /tmp/naabu.sha256 \
 && (cd /tmp && grep "naabu_${NAABU_VERSION}_linux_${TARGETARCH}.zip" naabu.sha256 | sha256sum -c -) \
 && unzip -o "/tmp/naabu_${NAABU_VERSION}_linux_${TARGETARCH}.zip" naabu -d /usr/local/bin \
 && rm /tmp/naabu_*.zip /tmp/naabu.sha256

# ── httpx ──
RUN curl --retry 3 --retry-delay 2 -sfL "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_${TARGETARCH}.zip" -o "/tmp/httpx_${HTTPX_VERSION}_linux_${TARGETARCH}.zip" \
 && curl --retry 3 --retry-delay 2 -sfL "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_checksums.txt" -o /tmp/httpx.sha256 \
 && (cd /tmp && grep "httpx_${HTTPX_VERSION}_linux_${TARGETARCH}.zip" httpx.sha256 | sha256sum -c -) \
 && unzip -o "/tmp/httpx_${HTTPX_VERSION}_linux_${TARGETARCH}.zip" httpx -d /usr/local/bin \
 && rm /tmp/httpx_*.zip /tmp/httpx.sha256

# ── amass (tar lớn — tách layer download để cache, tar có thư mục con amass_linux_<arch>/) ──
RUN curl --retry 5 --retry-delay 3 -sfL "https://github.com/owasp-amass/amass/releases/download/v${AMASS_VERSION}/amass_linux_${TARGETARCH}.tar.gz" -o "/tmp/amass_linux_${TARGETARCH}.tar.gz" \
 && curl --retry 5 --retry-delay 3 -sfL "https://github.com/owasp-amass/amass/releases/download/v${AMASS_VERSION}/amass_checksums.txt" -o /tmp/amass.sha256 \
 && (cd /tmp && grep "amass_linux_${TARGETARCH}.tar.gz" amass.sha256 | sha256sum -c -)
RUN tar -xzf "/tmp/amass_linux_${TARGETARCH}.tar.gz" -C /tmp \
 && mv "/tmp/amass_linux_${TARGETARCH}/amass" /usr/local/bin/amass \
 && rm -rf /tmp/amass_*.tar.gz /tmp/amass.sha256 "/tmp/amass_linux_${TARGETARCH}"

# thư mục làm việc ghi được (amass v4/v5 cần nơi lưu graph db tạm trong container)
RUN useradd --create-home --shell /bin/bash tooler \
 && mkdir -p /home/tooler/.config/amass /home/tooler/.local/share \
 && chown -R tooler:tooler /home/tooler
USER tooler
WORKDIR /home/tooler

CMD ["httpx", "-version"]
