AC_ROOT		= ..
include		$(AC_ROOT)/common.mak

MP_FILES	= aircrack-ng.1 airdecap-ng.1 ivstools.1 kstats.1 makeivs-ng.1 \
		  packetforge-ng.1 airdecloak-ng.1 wpaclean.1 besside-ng-crawler.1

SMP_FILES	= aireplay-ng.8 airmon-ng.8 airodump-ng.8 besside-ng.8 \
		  airserv-ng.8 airtun-ng.8 airbase-ng.8 airodump-ng-oui-update.8 \

ifeq ($(subst TRUE,true,$(filter TRUE true,$(sqlite) $(SQLITE))),true)
	MP_FILES += airolib-ng.1
endif

ifeq ($(subst TRUE,true,$(filter TRUE true,$(experimental) $(EXPERIMENTAL))),true)
	MP_FILES  += buddy-ng.1
	SMP_FILES += tkiptun-ng.8 easside-ng.8 wesside-ng.8 airventriloquist.8
endif


default: all

all:
	@echo Nothing to do

install: uninstall
	install -d $(DESTDIR)$(mandir)
	install -d $(DESTDIR)$(smandir)
	install -m 644 $(MP_FILES) $(DESTDIR)$(mandir)
	install -m 644 $(SMP_FILES) $(DESTDIR)$(smandir)

# Uninstall just calls cleanfiles with all possible switches enabled to
# ensure all previously installed manpages are cleaned
uninstall:
	$(MAKE) cleanfiles sqlite=true experimental=true

cleanfiles:
	@-$(foreach CUR_MP,$(MP_FILES), rm -f $(DESTDIR)$(mandir)/$(CUR_MP); echo rm -f $(DESTDIR)$(mandir)/$(CUR_MP); )
	@-$(foreach CUR_SMP,$(SMP_FILES), rm -f $(DESTDIR)$(smandir)/$(CUR_SMP); echo rm -f $(DESTDIR)$(smandir)/$(CUR_SMP); )
