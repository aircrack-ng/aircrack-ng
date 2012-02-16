DOCFILES = Apple.sample.txt dropRules.conf.example
default: all

all:
	@echo "Nothing to do, run make install" 

install:
	install -d $(DESTDIR)$(docdir)
	install -d $(DESTDIR)$(mandir)
	install -m 644 $(DOCFILES) $(DESTDIR)$(docdir)
	install -m 644 airdrop-ng.1 $(DESTDIR)$(mandir)
