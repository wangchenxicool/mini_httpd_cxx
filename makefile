#ARCH=ARM
OTHERSLIBPWD=/home/usrc

ifeq ($(ARCH),ARM)
CROSS=mipsel-openwrt-linux-
endif

SRC:=$(shell ls *.c)
SRC+=$(shell ls *.cpp)
SRC+=$(shell ls $(PWD)/libiniparser/*.c)
SRC+=$(shell ls $(PWD)/json_njsk/*.cpp)

ifeq ($(ARCH),ARM)
else
endif
IPATH:=-I$(PWD)/curl
IPATH+=-I$(PWD)/libiniparser
IPATH+=-I$(PWD)/json_njsk


ifeq ($(ARCH),ARM)
else
endif
#LPATH:=-L$(PWD)/curl


ifeq ($(ARCH),ARM)
else
endif
LFLAGS:=-lpthread
#LFLAGS+=-lcurl


ifeq ($(ARCH),ARM)
TARGET:=web_for_huihui.bin
else
TARGET:=web_for_huihui.bin
endif


$(TARGET) : $(SRC)
	$(CROSS)g++ $(CFLAG) -o $(TARGET) $^ $(LPATH) $(IPATH) $(LFLAGS) $(CFLAGS)

clean:
	rm -f  *.bin  *.dis  *.elf  *.o
