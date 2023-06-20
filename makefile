CC=gcc
CFLAGS=-Wall -Wextra -Werror -Wwrite-strings -g
SRC= $(wildcard *.c)
TARGET=flood

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)