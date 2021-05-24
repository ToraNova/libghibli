# builds recursively in the /src directory
SUBDIRS = src
ACLOCAL_AMFLAGS = -I m4

install-exec-hook:
	rm -f $(libsecuritydir)/pam_ghibc.la
	chmod -f 644 $(libsecuritydir)/pam_ghibc.so || true
