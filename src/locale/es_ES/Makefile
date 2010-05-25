all: build

build:
	@msgfmt airoscript.po -o airoscript.mo

install:
	@echo "\t Installing locale es_ES"
	@$(INSTALLDATA) airoscript.mo $(localedir)/`basename \`pwd\``

uninstall:
	@rm $(localedir)/`basename \`pwd\``/airoscript.mo

clean:
	@rm airoscript.mo
