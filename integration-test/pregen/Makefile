ZPLC ?= zplc
KEY := zpr-rsa-key.pem

OBJS := zpt-test.bin2 zpt-test-oidc.bin2

info:
	@echo Makefile to help with compiling the ZPR policies
	@echo from source.
	@echo
	@echo make clean - removes all the .bin policy files
	@echo make all   - recompiles out of date policy files
	@echo
	@echo Requires that \'zplc\' the ZPL compiler is in your path.
	@echo Or you can set path to zplc by setting ZPLC variable.
	@echo

all: $(OBJS)

clean:
	rm -f $(OBJS)

%.bin2: %.zpl %.zplc
	$(ZPLC) -k $(KEY) --outfmt v2 $<

rebuild: clean all

.PHONY: all clean rebuild

.DEFAULT_GOAL: info
