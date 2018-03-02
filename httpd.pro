QT -= core gui
TARGET = httpd
CONFIG += console
TEMPLATE = app

HEADERS += \
    json_njsk/json.h \
    libiniparser/dictionary.h \
    libiniparser/iniparser.h \
    bb_client.h \
    config.h \
    httpd.h \
    md5.h \
    mping.h \
    my_popen.h \
    safe.h \
    wcx_log.h \
    terminal_color.h

SOURCES += \
    json_njsk/json.cpp \
    config.cpp \
    httpd.cpp \
    main.cpp \
    wcx_log.cpp \
    libiniparser/dictionary.c \
    libiniparser/iniparser.c \
    bb_client.c \
    md5.c \
    mping.c \
    my_popen.c \
    safe.c
