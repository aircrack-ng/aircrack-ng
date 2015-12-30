need := 3.81
ok := $(filter $(need),$(firstword $(sort $(MAKE_VERSION) \
	$(need))))

ifndef ok
    $(error fatal error... Need make $(need) but using $(MAKE_VERSION), please upgrade)
endif

AC_ROOT		= .
include		$(AC_ROOT)/common.mak

DOCFILES        = ChangeLog INSTALLING README LICENSE AUTHORS VERSION

COVERITY_BUILD	?= cov-build
COVERITY_DIR	= cov-int

COVERITY_TAR_GZ	= Aircrack-ng.tar.gz
COVERITY_CREDS_DIR	= coverity
COVERITY_TOKEN	= $(shell cat ${COVERITY_CREDS_DIR}/token)
COVERITY_EMAIL	= $(shell cat ${COVERITY_CREDS_DIR}/email)

default: all

all:
	$(MAKE) -C src $(@)

coverity-build:
	$(COVERITY_BUILD) --dir $(COVERITY_DIR) $(MAKE) sqlite=true experimental=true pcre=true

coverity-package: coverity-build
	tar czvf $(COVERITY_TAR_GZ) $(COVERITY_DIR)

coverity-upload: coverity-package
	curl --form project=Aircrack-ng --form token=$(COVERITY_TOKEN) --form email=$(COVERITY_EMAIL) --form file=@$(COVERITY_TAR_GZ) --form version=r$(REVISION) --form description="Aircrack-ng svn r$(REVISION)" http://scan5.coverity.com/cgi-bin/upload.py

coverity-show-creds:
	@echo "Token: $(COVERITY_TOKEN)"
	@echo "Email: $(COVERITY_EMAIL)"

aircrack-ng-opt-prof_gen: all
	mkdir -p prof
	$(MAKE) -C src $(@)

aircrack-ng-opt-prof_use:
	$(MAKE) -C src $(@)

install: all
	$(MAKE) -C src $(@)
	$(MAKE) -C scripts $(@)
	$(MAKE) -C manpages $(@)
	@echo " "
	@echo "[*] Run 'airodump-ng-oui-update' as root (or with sudo) to install or update Airodump-ng OUI file (Internet connection required)."

uninstall:
	$(MAKE) -C src $(@)
	-rm -fr $(DESTDIR)$(docdir)
	$(MAKE) -C manpages $(@)
	$(MAKE) -C scripts $(@)

strip:
	$(MAKE) -C src $(@)

doc:
	install -d $(DESTDIR)$(docdir)
	install -m 644 $(DOCFILES) $(DESTDIR)$(docdir)

clean:
	-rm -rf $(COVERITY_DIR)
	-rm -f common.cfg
	$(MAKE) -C src $(@)
	$(MAKE) -C test/cryptounittest $(@)
	$(MAKE) -C test $(@)

distclean: clean

check: 
	$(MAKE) -C src $(@)
	$(MAKE) -C test/cryptounittest $(@)
	$(MAKE) -C test $(@)
	
