.PHONY: compile clean distclean

REBAR3_URL = https://s3.amazonaws.com/rebar3/rebar3

# If there is a rebar in the current directory, use it
ifeq ($(wildcard rebar3),rebar3)
REBAR3 = $(CURDIR)/rebar3
endif

# Fallback to rebar on PATH
REBAR3 ?= $(shell which rebar3)

# And finally, prep to download rebar if all else fails
ifeq ($(REBAR3),)
REBAR3 = $(CURDIR)/rebar3
endif

all: compile

compile: $(REBAR3)
	@$(REBAR3) do clean, compile, escriptize

clean: $(REBAR3)
	@$(REBAR3) clean

distclean: clean
	@rm -rf deps ebin .rebar _build

install: compile
	install -d $(DESTDIR)/usr/local/bin
	install -m755 $< $(DESTDIR)/usr/local/bin

$(REBAR3):
	curl -s -Lo rebar3 $(REBAR3_URL) || wget $(REBAR3_URL)
	chmod a+x rebar3

# vim: set filetype=make syntax=make noet ts=4 sts=4 sw=4 si:
