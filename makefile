CC = gcc
SRC = cJSON key main socket ms util
INC = include -I/usr/local/modsecurity/include
LIB = -Llib -L/usr/lib64/ -L/usr/local/modsecurity/lib -ldl -lpthread -lm -lz -lmodsecurity -lmsutil
OBJS = $(addsuffix .o, $(SRC))
TARGET = uniwaf

all: share $(OBJS)
	$(CC) -g -o $(addprefix bin/, $(TARGET)) $(addprefix obj/, $(OBJS)) $(LIB)
origin: $(OBJS)
	$(CC) -g -o $(addprefix bin/, $(TARGET)) $(addprefix obj/, $(OBJS)) $(LIB)
%.o: $(addprefix src/, %.c)
	$(CC) -g -c -Wall $< -I$(INC) -o $(addprefix obj/, $@)
clean:
	rm -rf obj/* bin/* lib/*
share:
	$(CC) -fPIC -shared -I$(INC) src/so.c -o  lib/libmsutil.so
install: all
	rm -rf /usr/local/bin/$(TARGET)
	cp bin/$(TARGET) /usr/local/bin/
