AC_ROOT		= ..
include		$(AC_ROOT)/common.mak

MP_FILES        = aircrack-ng.1 airdecap-ng.1 airdriver-ng.1 aireplay-ng.1 \
                  airmon-ng.1 airodump-ng.1 airserv-ng.1 airtun-ng.1 \
                  ivstools.1 kstats.1 makeivs-ng.1 airbase-ng.1 \
                  packetforge-ng.1 airdecloak-ng.1 


ifeq ($(SQLITE), true)
	MP_FILES += airolib-ng.1
else
	ifeq ($(sqlite), true)
		MP_FILES += airolib-ng.1
	else
		ifeq ($(SQLITE), TRUE)
			MP_FILES += airolib-ng.1
		else
			ifeq ($(sqlite), TRUE)
				MP_FILES += airolib-ng.1
			endif
		endif
	endif
endif


ifeq ($(UNSTABLE), true)
	MP_FILES	+= wesside-ng.1 tkiptun-ng.1 buddy-ng.1 easside-ng.1 
else
	ifeq ($(unstable), true)
		MP_FILES        += wesside-ng.1 tkiptun-ng.1 buddy-ng.1 easside-ng.1 
	else
		ifeq ($(UNSTABLE), TRUE)
			MP_FILES        += wesside-ng.1 tkiptun-ng.1 buddy-ng.1 easside-ng.1 
		else
			ifeq ($(unstable), TRUE)
				MP_FILES        += wesside-ng.1 tkiptun-ng.1 buddy-ng.1 easside-ng.1 
			endif
		endif
	endif
endif


default: all

all:
	@echo Nothing to do
	
install: uninstall
	install -d $(DESTDIR)$(mandir)
	install -m 644 $(MP_FILES) $(DESTDIR)$(mandir)

uninstall:
	@-$(foreach CUR_MP,$(MP_FILES), rm -f $(DESTDIR)$(mandir)/$(CUR_MP); echo rm -f $(DESTDIR)$(mandir)/$(CUR_MP); ) 
	-rm -f $(DESTDIR)$(mandir)/airolib-ng.1
	-rm -f $(DESTDIR)$(mandir)/wesside-ng.1
	-rm -f $(DESTDIR)$(mandir)/tkiptun-ng.1
	-rm -f $(DESTDIR)$(mandir)/buddy-ng.1
	-rm -f $(DESTDIR)$(mandir)/easside-ng.1
