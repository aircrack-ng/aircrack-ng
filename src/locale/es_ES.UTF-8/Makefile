all: install
localedir=/usr/local/share/locale/es_ES.UTF-8/LC_MESSAGES
# FIXME

build:
	@msgfmt airoscript-ng.po -o airoscript-ng.mo

install:
	@mkdir -p $(localedir)
	@cp airoscript-ng.mo $(localedir)

uninstall:
	@rm -f $(localedir)/`basename \`pwd\``/airoscript-ng.mo

clean:
	@rm -f airoscript-ng.mo
