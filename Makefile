CC		?= gcc
CFLAGS	?= -std=c11 -Wall -O2 -D_GNU_SOURCE -D_DEFAULT_SOURCE
LDFLAGS	?=
AC_NAME ?= pppoe-atm-relay

PREFIX	?= /usr
BINDIR	?= $(PREFIX)/bin
MANDIR	?= $(PREFIX)/share/man/man8

TARGET	= pppoe-atm-relay
SRC		= pppoe-atm-relay.c

all: $(TARGET)

$(TARGET): $(SRC)
	@echo "AC_NAME used in building: $(AC_NAME)"
	$(CC) $(CFLAGS) -DAC_NAME=\"$(AC_NAME)\" -o $@ $^ $(LDFLAGS)

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)/
	install -d $(DESTDIR)$(MANDIR)
	install -m 0644 pppoe-atm-relay.8 $(DESTDIR)$(MANDIR)/

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	rm -f $(DESTDIR)$(MANDIR)/pppoe-atm-relay.8

clean:
	rm -f $(TARGET)

.PHONY: all install uninstall clean