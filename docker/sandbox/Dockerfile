# DeepAudit Agent Sandbox
# 安全沙箱环境用于漏洞验证和 PoC 执行
# 集成各类安全扫描工具 (Semgrep, Bandit, Gitleaks, etc.)

FROM python:3.11-bullseye

LABEL maintainer="XCodeReviewer Team"
LABEL description="Secure sandbox environment for vulnerability verification and security scanning"

# 安装基本工具
# 安装基本工具
RUN unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY && \
    apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    netcat-openbsd \
    dnsutils \
    iputils-ping \
    ca-certificates \
    git \
    unzip \
    jq \
    php-cli \
    openjdk-11-jdk-headless \
    ruby-full \
    build-essential \
    cmake \
    clang \
    llvm \
    && rm -rf /var/lib/apt/lists/*

# 安装 Node.js (用于 JavaScript/TypeScript 代码执行 和 npm audit)
RUN unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY && \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && npm config set registry https://registry.npmjs.org \
    && (npm install -g hardhat truffle --silent || true) \
    && rm -rf /var/lib/apt/lists/*

# 安装 Go
ENV PATH=$PATH:/usr/local/go/bin
RUN unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY && \
    curl -L https://go.dev/dl/go1.21.6.linux-amd64.tar.gz -o go.tar.gz && \
    tar -C /usr/local -xzf go.tar.gz && \
    rm go.tar.gz

# 安装 Rust
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
RUN unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal && \
    chmod -R a+w /usr/local/cargo

# 安装 Python 安全工具
RUN unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY && \
    pip install --no-cache-dir --retries 8 --timeout 120 \
    requests \
    httpx \
    aiohttp \
    beautifulsoup4 \
    lxml \
    pycryptodome \
    paramiko \
    pyjwt \
    python-jose \
    sqlparse \
    semgrep \
    bandit \
    safety

# 安装 Solidity 安全工具（主力静态分析 + 符号执行）
RUN unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY && \
    pip install --no-cache-dir --retries 8 --timeout 120 \
    slither-analyzer \
    solc-select && \
    (pip install --no-cache-dir --retries 8 --timeout 120 mythril==0.24.8 || \
     pip install --no-cache-dir --retries 8 --timeout 120 mythril || \
     echo "WARNING: mythril install failed, continue with slither only")

# 预装常用 solc 版本，提升 Solidity 扫描稳定性
RUN unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY && \
    solc-select install 0.4.26 && \
    solc-select install 0.5.17 && \
    solc-select install 0.6.12 && \
    solc-select install 0.7.6 && \
    solc-select install 0.8.10 && \
    solc-select install 0.8.17 && \
    solc-select install 0.8.20 && \
    solc-select install 0.8.24 && \
    solc-select use 0.8.24

# 安装 Gitleaks
RUN unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY && \
    curl -L https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz -o gitleaks.tar.gz && \
    tar -xzf gitleaks.tar.gz && \
    mv gitleaks /usr/local/bin/ && \
    rm gitleaks.tar.gz

# 安装 TruffleHog
RUN unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY && \
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# 安装 OSV-Scanner
RUN unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY && \
    curl -L https://github.com/google/osv-scanner/releases/download/v1.6.2/osv-scanner_1.6.2_linux_amd64 -o /usr/local/bin/osv-scanner && \
    chmod +x /usr/local/bin/osv-scanner

# 创建非 root 用户
RUN groupadd -g 1000 sandbox && \
    useradd -u 1000 -g sandbox -m -s /bin/bash sandbox

# 创建工作目录
RUN mkdir -p /workspace /tmp/sandbox && \
    chown -R sandbox:sandbox /workspace /tmp/sandbox

# 复制 solc-select 数据到 sandbox 用户目录（避免运行时找不到已安装版本）
RUN mkdir -p /home/sandbox/.solc-select && \
    cp -r /root/.solc-select/* /home/sandbox/.solc-select/ && \
    chown -R sandbox:sandbox /home/sandbox/.solc-select

# 设置环境变量
ENV HOME=/home/sandbox
ENV PATH=/home/sandbox/.local/bin:$PATH
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# 限制 Python 导入路径
ENV PYTHONPATH=/workspace

# 切换到非 root 用户
USER sandbox

WORKDIR /workspace

# 默认命令
CMD ["/bin/bash"]
