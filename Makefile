CC = gcc
CFLAGS = -Wall -Wextra -O2
LDLIBS = -lpcap

TARGET = arp-spoof
OBJS = main.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

main.o: main.c ansheader.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)
