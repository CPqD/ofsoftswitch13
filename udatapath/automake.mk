#
# Build udatapath as binary
#

bin_PROGRAMS += udatapath/ofdatapath
man_MANS += udatapath/ofdatapath.8

udatapath_ofdatapath_SOURCES = \
	udatapath/action_set.c \
	udatapath/action_set.h \
	udatapath/crc32.c \
	udatapath/crc32.h \
	udatapath/datapath.c \
	udatapath/datapath.h \
	udatapath/dp_actions.c \
	udatapath/dp_actions.h \
	udatapath/dp_buffers.c \
	udatapath/dp_buffers.h \
	udatapath/dp_control.c \
	udatapath/dp_control.h \
	udatapath/dp_exp.c \
	udatapath/dp_exp.h \
	udatapath/dp_ports.c \
	udatapath/dp_ports.h \
	udatapath/flow_table.c \
	udatapath/flow_table.h \
	udatapath/flow_entry.c \
	udatapath/flow_entry.h \
	udatapath/group_table.c \
	udatapath/group_table.h \
	udatapath/group_entry.c \
	udatapath/group_entry.h \
	udatapath/match_std.c \
    udatapath/match_std.h \
	udatapath/meter_entry.c \
	udatapath/meter_entry.h \
	udatapath/meter_table.c \
	udatapath/meter_table.h \	
	udatapath/packet.c \
	udatapath/packet.h \
	udatapath/packet_handle_std.c \
    udatapath/packet_handle_std.h \
	udatapath/pipeline.c \
	udatapath/pipeline.h \
	udatapath/udatapath.c

udatapath_ofdatapath_LDADD = lib/libopenflow.a oflib/liboflib.a oflib-exp/liboflib_exp.a nbee_link/libnbee_link.a $(SSL_LIBS) $(FAULT_LIBS)
udatapath_ofdatapath_CPPFLAGS = $(AM_CPPFLAGS)
nodist_EXTRA_udatapath_ofdatapath_SOURCES = dummy.cxx

EXTRA_DIST += udatapath/ofdatapath.8.in
DISTCLEANFILES += udatapath/ofdatapath.8

if BUILD_HW_LIBS

# Options for each platform
if NF2
udatapath_ofdatapath_CPPFLAGS += -DOF_HW_PLAT -DUSE_NETDEV -g
endif

endif

if BUILD_HW_LIBS
#
# Build udatapath as a library
#

noinst_LIBRARIES += udatapath/libudatapath.a

udatapath_libudatapath_a_SOURCES = \
	udatapath/action_set.c \
	udatapath/action_set.h \
	udatapath/crc32.c \
	udatapath/crc32.h \
	udatapath/datapath.c \
	udatapath/datapath.h \
	udatapath/dp_actions.c \
	udatapath/dp_actions.h \
	udatapath/dp_buffers.c \
	udatapath/dp_buffers.h \
	udatapath/dp_control.c \
	udatapath/dp_control.h \
	udatapath/dp_exp.c \
	udatapath/dp_exp.h \
	udatapath/flow_table.c \
	udatapath/flow_table.h \
	udatapath/flow_entry.c \
	udatapath/flow_entry.h \
	udatapath/group_table.c \
	udatapath/group_table.h \
	udatapath/group_entry.c \
	udatapath/group_entry.h \
	udatapath/match_std.c \
	udatapath/match_std.h \
	udatapath/packet.c \
	udatapath/packet.h \
	udatapath/packet_handle_std.c \
	udatapath/packet_handle_std.h \
	udatapath/pipeline.c \
	udatapath/pipeline.h \
	udatapath/udatapath.c

udatapath_libudatapath_a_CPPFLAGS = $(AM_CPPFLAGS)
udatapath_libudatapath_a_CPPFLAGS += -DOF_HW_PLAT -DUDATAPATH_AS_LIB -g -lnbee_link

endif
