CC = g++
OBJS = main.o BtrMenuPrinter.o BtrSummaryPrinter.o BtrSniffFeature.o 
CPPFLAGS = -g -std='c++1y' -I./ 
TARGET = main

.SUFFIXES : .cpp .o

all : $(TARGET)

$(TARGET) : $(OBJS)
	$(CC) $(CPPFLAGS) -o $@ $(OBJS) -lpcap

clean :
	rm -rf $(OBJS) $(TARGET)



