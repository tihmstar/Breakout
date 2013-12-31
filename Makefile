CC=gcc
IDIR=include
SDIR=src
CFLAGS= -g -Wall -I$(IDIR)
LIBS = -limobiledevice -lplist -lusbmuxd -lssl -lcrypto
TARGET = breakout

all: $(TARGET)

$(TARGET): $(SDIR)/$(TARGET).c
		$(CC) $(CFLAGS) -o $(TARGET) $(SDIR)/$(TARGET).c $(LIBS)

clean:
	rm $(TARGET)