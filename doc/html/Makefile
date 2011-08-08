all: install 

install:
	@echo "\t Installing html documentation"
	@$(INSTALLDATA) *.html $(docdir)/html
	@$(INSTALLDATA) images/* $(docdir)/html/images/

build:
	@echo "\t Building html documentation from rst"
	@for i in *.rst; do rst2html $$i --link-stylesheet --stylesheet=css/stylesheet.css $$i.html; done

uninstall:
	@echo "Removing html documentation from $(docdir)/html"
	@rm -r $(docdir)/html

