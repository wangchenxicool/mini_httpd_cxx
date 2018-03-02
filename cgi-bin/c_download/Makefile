#ARCH=ARM
OTHERSLIBPWD=/home/usrc
INSTALL=install -o $(USER) -g $(USER)

ifeq ($(ARCH),ARM)
#CROSS=arm-linux-
CROSS=mipsel-openwrt-linux-
endif

SRC:=$(shell ls *.c)

CFLAG = -static

ifeq ($(ARCH),ARM)
else
endif

LIBS:=-lpthread

ifeq ($(ARCH),ARM)
TARGET:=download
else
TARGET:=download
endif

$(TARGET) : $(SRC)
	$(CROSS)g++ $(CFLAG) -o $(TARGET) $^ $(LPATH) $(IPATH) $(LIBS)

install:
	@$(INSTALL) -m 755 ./$(TARGET) ./bb_setup/BangBangDog/

clean:
	rm -f  *.bin  *.dis  *.elf  *.o
