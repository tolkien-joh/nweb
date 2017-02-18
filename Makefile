
all: nweb

nweb: nweb24.c
	${CC} -o $@ $<

clean:
	rm -f *~

distclean:
	rm client nweb *.log
