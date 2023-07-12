CC=gcc
CFLAGS=-Wall -Wextra -Wwrite-strings -g
SRC= $(wildcard *.c)
TARGET=inject
LIBS=-lpcap -lcrypto

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) $(LIBS) -o $(TARGET)

clean: 
	rm -rf $(TARGET)