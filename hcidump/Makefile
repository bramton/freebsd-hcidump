PROG=		hcidump
PREFIX?=	/usr/local
BINDIR?=	${PREFIX}/bin
MANDIR?=	${PREFIX}/share/man/man
WARNS?=		2
CFLAGS+=	-I../parser

DPADD+=		../parser/libparser.a
LDADD+=		-L../parser -lparser

.include <bsd.prog.mk>

