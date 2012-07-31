noinst_LIBRARIES += oflib-exp/liboflib_exp.a

oflib_exp_liboflib_exp_a_SOURCES = \
	oflib-exp/ofl-exp.c \
	oflib-exp/ofl-exp.h \
	oflib-exp/ofl-exp-nicira.c \
	oflib-exp/ofl-exp-nicira.h \
	oflib-exp/ofl-exp-openflow.c \
	oflib-exp/ofl-exp-openflow.h

AM_CPPFLAGS += -DOFL_LOG_VLOG
