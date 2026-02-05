# $Id: Makefile,v 1.7 2004/03/12 22:16:58 max Exp $
# $FreeBSD$

PROG=		hcidump
BINDIR=		/usr/local/bin
MANDIR=		/usr/local/man/man
MAN1=		hcidump.1
SRCS=		hcidump.c
WARNS?=		2
DEBUG_FLAGS=	-g
CFLAGS=		-O2 -I../parser

DPADD+=		../parser/libparser.a
LDADD+=		-L../parser -lparser

.include <bsd.prog.mk>

