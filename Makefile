.PHONY: compile deps clean distclean

REBAR = rebar

all: compile

deps:
	$(REBAR) get-deps

compile: deps
	$(REBAR) compile escriptize

clean:
	$(REBAR) clean

distclean: clean
	@rm -rf deps ebin .rebar

install: compile
	install -d $(DESTDIR)/usr/local/bin
	install -m755 $< $(DESTDIR)/usr/local/bin

# vim: set filetype=make syntax=make noet ts=4 sts=4 sw=4 si:
