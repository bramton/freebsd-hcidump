PROG=		hcidump
WARNS?=		2
CFLAGS+=	-I../parser

DPADD+=		../parser/libparser.a
LDADD+=		-L../parser -lparser

.include <bsd.prog.mk>

