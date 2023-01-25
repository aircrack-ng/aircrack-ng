ARG IMAGE_BASE=debian:unstable-slim
FROM ${IMAGE_BASE} AS builder

# Install dependencies for building
COPY docker_package_install.sh /opt
RUN sh /opt/docker_package_install.sh builder

# Build Aircrack-ng
RUN mkdir -p /aircrack-ng /output
COPY . /aircrack-ng
WORKDIR /aircrack-ng
# hadolint ignore=SC2006
RUN set -x \
	&& make distclean || : && \
		autoreconf -vif && \
		set -e; \
			./configure --with-experimental --with-ext-scripts --enable-maintainer-mode --without-opt --prefix=/usr && \
			make -j3 && \
		set +e && \
			if ! make check -j3; then \
				echo "Processor: $(uname -m)"; \
				for file in `grep -l "(exit status: [1-9]" test/*.log`; do \
					echo "[*] Test ${file}:"; \
					cat "${file}"; \
				done; \
				exit 1; \
			fi && \
		set -e && \
			make install DESTDIR=/output

# Stage 2
FROM ${IMAGE_BASE}

COPY --from=builder /output/usr /usr

COPY docker_package_install.sh /opt

# Install dependencies
# hadolint ignore=DL3008
RUN set -x \
 && sh /opt/docker_package_install.sh stage2 \
 && rm /opt/docker_package_install.sh \
 && aircrack-ng -u
