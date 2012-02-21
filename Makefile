CC = gcc
CFLAGS = -Wall -pthread
LIBS = -lpanel -lncursesw -lpcap
OBJECTS = localtraf.o display.o sort.o
TARGET = localtraf

all: $(TARGET)

localtraf: Makefile $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LIBS)
	strip -s $(TARGET)

localtraf.o: Makefile localtraf.h display.h localtraf.c
	$(CC) $(CFLAGS) -c localtraf.c

display.o: Makefile localtraf.h sort.h display.h display.c
	$(CC) $(CFLAGS) -c display.c

sort.o: Makefile localtraf.h sort.h sort.c
	$(CC) $(CFLAGS) -c sort.c

clean:
	rm -f $(TARGET) $(OBJECTS)
