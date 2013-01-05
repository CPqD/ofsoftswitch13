noinst_LIBRARIES += oflib/liboflib.a

oflib_liboflib_a_SOURCES = \
	oflib/ofl.h \
	oflib/ofl-actions.c \
	oflib/ofl-actions.h \
	oflib/ofl-actions-pack.c \
	oflib/ofl-actions-print.c \
	oflib/ofl-actions-unpack.c \
	oflib/ofl-messages.c \
	oflib/ofl-messages.h \
	oflib/ofl-messages-pack.c \
	oflib/ofl-messages-print.c \
	oflib/ofl-messages-unpack.c \
	oflib/oxm-match.c \
	oflib/oxm-match.h \
	oflib/ofl-print.c \
	oflib/ofl-print.h \
	oflib/ofl-structs.c \
	oflib/ofl-structs.h \
	oflib/ofl-structs-match.c \
	oflib/ofl-structs-pack.c \
	oflib/ofl-structs-print.c \
	oflib/ofl-structs-unpack.c \
	oflib/ofl-utils.h

AM_CPPFLAGS += -DOFL_LOG_VLOG

