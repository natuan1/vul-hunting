# Tooling image cho Recon Phase (ticket #8, #9) — cũng là terminal.docker_image
# cho sandbox verification (ticket #11, ADR-0003).
#
# Version các tool ghi rõ dưới đây (pin cứng, có kiểm tra checksum SHA-256
# từ checksums.txt chính thức của từng release; tool không phát hành binary
# (gf) thì build từ source pin theo commit).

# ── stage build gf (repo GOPATH-era, không phát hành binary) ──
FROM golang:1.24-bookworm AS gf-builder
ARG GF_COMMIT=dcd4c361f9f5ba302294ed38b8ce278e8ba69006
RUN git clone --quiet https://github.com/tomnomnom/gf /src/gf \
 && cd /src/gf \
 && git checkout --quiet "${GF_COMMIT}" \
 && go build -o /out/gf main.go

FROM debian:bookworm-slim

ARG TARGETARCH=amd64

ARG SUBFINDER_VERSION=2.16.0
ARG AMASS_VERSION=5.1.1
ARG DNSX_VERSION=1.3.1
ARG NAABU_VERSION=2.6.1
ARG HTTPX_VERSION=1.11.0
ARG KATANA_VERSION=1.7.0
ARG GAU_VERSION=2.2.4
ARG WAYMORE_VERSION=8.9
ARG GF_PATTERNS_COMMIT=f686f06ae647726578920084c894100d702496cc

LABEL org.opencontainers.image.title="vulhunt-tooling" \
      org.opencontainers.image.description="Recon CLI tools: subfinder/amass/dnsx/naabu/httpx/katana/gau/waymore/gf" \
      org.opencontainers.image.licenses="MIT"

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl unzip jq python3 python3-venv \
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

# ── katana (ticket #9): crawl các live host — checksums file dùng dấu gạch ngang ──
RUN curl --retry 3 --retry-delay 2 -sfL "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_${TARGETARCH}.zip" -o "/tmp/katana_${KATANA_VERSION}_linux_${TARGETARCH}.zip" \
 && curl --retry 3 --retry-delay 2 -sfL "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana-${KATANA_VERSION}-checksums.txt" -o /tmp/katana.sha256 \
 && (cd /tmp && grep "katana_${KATANA_VERSION}_linux_${TARGETARCH}.zip" katana.sha256 | sha256sum -c -) \
 && unzip -o "/tmp/katana_${KATANA_VERSION}_linux_${TARGETARCH}.zip" katana -d /usr/local/bin \
 && rm /tmp/katana_*.zip /tmp/katana.sha256

# ── gau (ticket #9): URL lịch sử từ Wayback + Common Crawl + OTX (keyless) ──
RUN curl --retry 3 --retry-delay 2 -sfL "https://github.com/lc/gau/releases/download/v${GAU_VERSION}/gau_${GAU_VERSION}_linux_${TARGETARCH}.tar.gz" -o "/tmp/gau_${GAU_VERSION}_linux_${TARGETARCH}.tar.gz" \
 && curl --retry 3 --retry-delay 2 -sfL "https://github.com/lc/gau/releases/download/v${GAU_VERSION}/gau_${GAU_VERSION}_checksums.txt" -o /tmp/gau.sha256 \
 && (cd /tmp && grep "gau_${GAU_VERSION}_linux_${TARGETARCH}.tar.gz" gau.sha256 | sha256sum -c -) \
 && tar -xzf "/tmp/gau_${GAU_VERSION}_linux_${TARGETARCH}.tar.gz" -C /usr/local/bin gau \
 && rm /tmp/gau_*.tar.gz /tmp/gau.sha256

# ── waymore (ticket #9): URL lịch sử đầy đủ hơn — Python package trong venv.
# waymore đọc OTX_API_KEY từ env (worker truyền qua docker -e khi có key);
# không key vẫn chạy với Wayback + Common Crawl.
RUN python3 -m venv /opt/waymore \
 && /opt/waymore/bin/pip install --no-cache-dir "waymore==${WAYMORE_VERSION}" \
 && ln -s /opt/waymore/bin/waymore /usr/local/bin/waymore

# ── gf + Gf-Patterns (ticket #9): phân loại URL theo class lỗ hổng.
# gf build từ source (stage gf-builder, pin commit); patterns là các file JSON
# của 1ndianl33t/Gf-Patterns pin theo commit → ~/.gf (gf đọc $HOME/.gf).
COPY --from=gf-builder /out/gf /usr/local/bin/gf
RUN curl --retry 3 --retry-delay 2 -sfL "https://github.com/1ndianl33t/Gf-Patterns/archive/${GF_PATTERNS_COMMIT}.tar.gz" -o /tmp/gf-patterns.tar.gz \
 && mkdir -p /home/tooler/.gf /tmp/gf-patterns \
 && tar -xzf /tmp/gf-patterns.tar.gz -C /tmp/gf-patterns --strip-components=1 \
 && mv /tmp/gf-patterns/*.json /home/tooler/.gf/ \
 && chown -R root:root /home/tooler/.gf && chmod -R a+rX /home/tooler/.gf \
 && rm -rf /tmp/gf-patterns /tmp/gf-patterns.tar.gz

# ── gf-slice: wrapper phân loại URL bằng engine gf (worker gọi như 1 tool) ──
COPY gf-slice /usr/local/bin/gf-slice
RUN chmod 755 /usr/local/bin/gf-slice

# thư mục làm việc ghi được (amass v4/v5 cần nơi lưu graph db tạm trong container,
# waymore lần chạy đầu ghi config.yml vào ~/.config/waymore)
RUN useradd --create-home --shell /bin/bash tooler \
 && mkdir -p /home/tooler/.config/amass /home/tooler/.config/waymore /home/tooler/.local/share \
 && chown -R tooler:tooler /home/tooler
USER tooler
WORKDIR /home/tooler

CMD ["httpx", "-version"]
