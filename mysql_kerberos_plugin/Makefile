#
#
#ifndef PREFIX
#$(error PREFIX not set -- Did you source compiler-config?)
#endif # 

CPPFLAGS_EXTRA = -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DMYSQL_DYNAMIC_PLUGIN
CFLAGS_EXTRA   = -g -pipe -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector --param=ssp-buffer-size=4 -m64 -mtune=generic -fno-strict-aliasing -fwrapv -shared -fPIC
LDFLAGS_EXTRA  = 
LIBS_EXTRA     =  -lgssapi_krb5 

CPPFLAGS    += $(CPPFLAGS_EXTRA)
CFLAGS      += $(CFLAGS_EXTRA)
LDFLAGS     += $(LDFLAGS_EXTRA)
LIBS        += $(LIBS_EXTRA)
SRC         =  constants.cc kerberos_auth.cc mysql_kerb.cc
CONF        = mysql_kerb.conf
PROG        = mysql_kerb.so
LIBMODE     = 555
CONFMODE    = 644
DIRMODE     = 755
OWNER       = root
GROUP       = root
LIBDIR      = $(PREFIX)/lib
CONFDIR     = $(PREFIX)/etc
INSTALL     = install-sh
RM          = /bin/rm

.PHONY: clean 
ALL: $(PROG)

$(PROG): $(SRC)
	$(CC) -o $(PROG) $(SRC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(LIBS)

clean:
	$(RM) -f $(PROG) Makefile core core.*


install: $(PROG)
	@@ if [ ! -d $(LIBDIR) ] ; then \
		echo "creating directory $(LIBDIR)"; \
		echo "$(INSTALL) -d -o  $(OWNER) -g $(GROUP) -m $(DIRMODE) $(LIBDIR)"; \
		$(INSTALL) -d -o  $(OWNER) -g $(GROUP) -m $(DIRMODE) $(LIBDIR); \
	fi;
	@@ if [ ! -d $(CONFDIR) ] ; then \
		echo "creating directory $(CONFDIR)"; \
		echo "$(INSTALL) -d -o  $(OWNER) -g $(GROUP) -m $(DIRMODE) $(CONFDIR)"; \
		$(INSTALL) -d -o  $(OWNER) -g $(GROUP) -m $(DIRMODE) $(CONFDIR); \
	fi;
		$(INSTALL) -C -o $(OWNER) -g $(GROUP) -m $(LIBMODE) $(PROG) $(LIBDIR); 
		$(INSTALL) -C -o $(OWNER) -g $(GROUP) -m $(CONFMODE) $(CONF) $(CONFDIR); 

