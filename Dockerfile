ARG IMAGE_BASE=debian:unstable-slim
# hadolint ignore=DL3006
FROM ${IMAGE_BASE} AS builder

# Install dependencies for building
COPY docker_package_install.sh /
RUN chmod +x docker_package_install.sh && \
	 /docker_package_install.sh builder

# Build Aircrack-ng
# hadolint ignore=DL3059
RUN mkdir -p /aircrack-ng /output
COPY . /aircrack-ng
WORKDIR /aircrack-ng
# hadolint ignore=SC2006,SC2086,DL4006
RUN set -x \
	&& make distclean || : && \
		autoreconf -vif && \
		set -e; \
			./configure --with-experimental --with-ext-scripts --enable-maintainer-mode --prefix=/usr/local && \
			make -j$(nproc) && \
		set +e && \
			if ! make check -j$(nproc); then \
				echo "Processor: $(uname -m)"; \
				for file in `grep -l "(exit status: [1-9]" test/*.log`; do \
					echo "[*] Test ${file}:"; \
					cat "${file}"; \
				done; \
				exit 1; \
			fi && \
		set -e && \
			export PYTHONPATH="/output/usr/local/lib/python$(python3 --version | awk '{print $2}' | awk -F. '{print $1 "." $2}')/site-packages/" && \
			mkdir -p ${PYTHONPATH} && \
			make install DESTDIR=/output

# Stage 2
# hadolint ignore=DL3006
FROM ${IMAGE_BASE}

# Due to the behavior of buildx failing to copy to directories being
# a symlink (whereas docker build works), copy the content to /output
# then manually move all the files in /usr/local
# In Arch-based distros, /usr/local/share/man is a symlink
RUN mkdir /output
COPY --from=builder /output/usr /output
# And another workaround for Clear Linux where this directory does not exist
# hadolint ignore=SC2015
RUN set -x && \
	[ -d /usr/local/share/man ] || \
		mkdir -p /usr/local/share/man
RUN cp -r /output/local/share/man/* /usr/local/share/man/ && \
	rm -rf /output/local/share/man && \
	cp -r /output/* /usr/ && \
	rm -rf /output

COPY docker_package_install.sh /

# Install dependencies
RUN set -x \
 && sh /docker_package_install.sh stage2 \
 && rm /docker_package_install.sh \
 && aircrack-ng -u
