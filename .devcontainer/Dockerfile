FROM ubuntu:22.04 as ubuntu2204-node20

# Set environment variables for configuration and defaults
ENV NODE_VERSION=20
ENV NVM_DIR="/opt/nvm"

# Install dependencies
# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install -y --no-install-recommends wget ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Install nvm
RUN mkdir ${NVM_DIR} && \
    wget -nv https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh && \
    bash install.sh && \
    rm install.sh

# Set the nvm environment variables
ENV SHIPPABLE_NODE_VERSION=$NODE_VERSION

# hadolint ignore=SC2016
RUN echo "export NVM_DIR=\"${NVM_DIR}\"" >> /etc/profile && \
    echo '[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"' >> /etc/profile && \
    echo 'nvm use default' >> /etc/profile

# Make npm, node, and others available with sudo
# hadolint ignore=DL4006,SC2086
RUN for file in `ls -1 $NVM_DIR/versions/node/$(. "$NVM_DIR/nvm.sh" && nvm which $NODE_VERSION | xargs dirname | xargs dirname | xargs basename)/bin/*`; do \
        ln -s "${file}" "/usr/local/bin/$(basename ${file})"; \
    done

FROM ubuntu2204-node20

# hadolint ignore=DL3005,DL3008
RUN apt-get update && \
    apt-get dist-upgrade -y && \
    sed -i 's,path-exclude=/usr/share/man/,#path-exclude=/usr/share/man/,' /etc/dpkg/dpkg.cfg.d/excludes && \
    DEBIAN_FRONTEND=noninteractive apt-get -y install --no-install-recommends \
        build-essential autoconf automake libtool pkg-config libnl-3-dev libnl-genl-3-dev libssl-dev \
        ethtool shtool rfkill zlib1g-dev libpcap-dev libsqlite3-dev libpcre2-dev libhwloc-dev \
        libcmocka-dev hostapd wpasupplicant tcpdump screen iw usbutils expect gawk bear zsh curl \
        libtinfo5 clang-14 clangd-14 clang-format-14 python3-pip binfmt-support codespell wget \
        man-db manpages-posix-dev manpages-dev gdb valgrind locales sudo ltrace strace shellcheck \
        cppcheck yamllint pre-commit cpplint nano vim less && \
    rm -rf /var/lib/apt/lists/*

# Symlink for pre-commit
RUN ln -s /usr/bin/clang-format-14 /usr/local/bin/clang-format

# ActionLint
RUN if [ "$(dpkg --print-architecture)" = "amd64" ]; then \
        wget -nv https://github.com/rhysd/actionlint/releases/download/v1.7.1/actionlint_1.7.1_linux_amd64.tar.gz -O /usr/local/bin/actionlint; \
        chmod +x /usr/local/bin/actionlint; \
    elif [ "$(dpkg --print-architecture)" = "arm64" ]; then \
        wget -nv https://github.com/rhysd/actionlint/releases/download/v1.7.1/actionlint_1.7.1_linux_arm64.tar.gz -O /usr/local/bin/actionlint; \
        chmod +x /usr/local/bin/actionlint; \
    else \
        echo "Installation of actionlint for $(dpkg --print-architecture) not implemented"; \
    fi

# ACT
RUN if [ "$(dpkg --print-architecture)" = "amd64" ]; then \
        wget -nv https://github.com/nektos/act/releases/latest/download/act_Linux_x86_64.tar.gz -O /usr/local/bin/act; \
        chmod +x /usr/local/bin/act; \
    elif [ "$(dpkg --print-architecture)" = "arm64" ]; then \
        wget -nv https://github.com/nektos/act/releases/latest/download/act_Linux_arm64.tar.gz -O /usr/local/bin/act; \
        chmod +x /usr/local/bin/act; \
    else \
        echo "Installation of act for $(dpkg --print-architecture) not implemented"; \
    fi

RUN if [ "$(dpkg --print-architecture)" = "amd64" ]; then \
        wget -nv https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-x86_64 -O /usr/local/bin/hadolint; \
        chmod +x /usr/local/bin/hadolint; \
    elif [ "$(dpkg --print-architecture)" = "arm64" ]; then \
        wget -nv https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-arm64 -O /usr/local/bin/hadolint; \
        chmod +x /usr/local/bin/hadolint; \
    else \
        echo "Hadolint not available for $(dpkg --print-architecture)"; \
    fi

# Install @devcontainers/cli
# hadolint ignore=DL3016
RUN npm install -g @devcontainers/cli

# Create locale
RUN sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
    locale-gen

# Fix man redirection
RUN rm -f /usr/bin/man && \
    dpkg-divert --remove --rename /usr/bin/man

# Add vscode user
RUN useradd -m vscode && \
    sed -i 's/env_reset/env_reset\nDefaults        env_keep += "PATH NVM_INC NVM_DIR NVM_CD_FLAGS NVM_BIN SHIPPABLE_NODE_VERSION NODE_VERSION"/' /etc/sudoers && \
    echo "vscode ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers && \
    chown -R vscode:vscode /root && \
    chown -R vscode:vscode /opt/nvm
