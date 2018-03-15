CC = gcc
OBJS = main.o biture_common.o func_sniff.o 
CFLAGS = -g -I./
TARGET = main

.SUFFIXES : .c .o

all : $(TARGET)

$(TARGET) : $(OBJS)
	$(CC) $(FLAGS) -o $@ $(OBJS) -lpcap

clean :
	rm -rf $(OBJS) $(TARGET)



