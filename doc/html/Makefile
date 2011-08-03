all: install
install:
	@echo "\t Installing html documentation"
	@rst2html *.rst 
	@$(INSTALLDATA) *.html $(docdir)/html
	@$(INSTALLDATA) images/* $(docdir)/html/images/

uninstall:
	@echo "Removing html documentation from $(docdir)/html"
	@rm -r $(docdir)/html

