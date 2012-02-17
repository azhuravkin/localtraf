CC = gcc
CFLAGS = -Wall -pthread
LIBS = -lpanel -lncursesw -lpcap
OBJECTS = main.o display.o pcap.o sort.o http.o
TARGET = localtraf

all: $(TARGET)

localtraf: Makefile $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LIBS)
	strip -s $(TARGET)

main.o: Makefile main.h display.h main.c
	$(CC) $(CFLAGS) -c main.c

display.o: Makefile main.h display.h pcap.h sort.h http.h display.c
	$(CC) $(CFLAGS) -c display.c

pcap.o: Makefile main.h display.h pcap.c
	$(CC) $(CFLAGS) -c pcap.c

sort.o: Makefile main.h display.h sort.c
	$(CC) $(CFLAGS) -c sort.c

http.o: Makefile main.h display.h sort.h http.h pcap.h http.c
	$(CC) $(CFLAGS) -c http.c

clean:
	rm -f $(TARGET) $(OBJECTS)
