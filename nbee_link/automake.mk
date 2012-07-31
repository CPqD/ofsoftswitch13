# Process this file with automake to produce Makefile.in
noinst_LIBRARIES += nbee_link/libnbee_link.a
#lib_LTLIBRARIES += nbee_link/libnbeelink.la
#lib_LTLIBRARIES = libnbeelink.la
#nbee_link_libnbee_link_a_LDADD = lib/libopenflow.a
#nbee_link_libnbee_link_a_LIBADD = \
#	lib/util.o 	\
#	lib/hmap.o 	

nbee_link_libnbee_link_a_SOURCES = nbee_link/nbee_link.cpp \
			nbee_link/nbee_link.h

MAINTAINERCLEANFILES = Makefile.in aclocal.m4 config.guess config.sub config.h.in configure depcomp install-sh missing ltmain.sh *~ *.tar.*


