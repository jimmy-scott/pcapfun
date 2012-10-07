CC := gcc
CFLAGS := -pedantic -Wall -std=c99 -O2 -lpcap -D_GNU_SOURCE

PROGS := pcapfun

all: $(PROGS)


$(PROGS): %: %.c
	$(CC) $(CFLAGS) $^ -o $@

.PHONY: clean
clean:
	rm -f $(PROGS)

