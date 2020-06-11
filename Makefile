RELEASE ?= 0

ifeq ($(RELEASE),1)
	PROFILE ?= release
	CARGO_ARGS = --release
else
	PROFILE ?= debug
	CARGO_ARGS =
endif

.PHONY: all
all:
	cargo build ${CARGO_ARGS}

.PHONY: install
install: all
	install -D -t ${DESTDIR}/usr/libexec target/${PROFILE}/ssh-key-dir
	install -D -m 644 -t ${DESTDIR}/etc/ssh/sshd_config.d conf/40-ssh-key-dir.conf
