#include "smp.h"

void smp_dump(int level, struct frame *frm) {
	p_indent(level, frm);
	uint8_t type = *(uint8_t *)frm->ptr;
	switch (type) {
		case SMP_CODE_PAIRREQ:
			printf("SMP: Pairing request (0x%02x)\n", type);
			reqres_dump(++level, frm);
			break;
		case SMP_CODE_PAIRRES:
			printf("SMP: Pairing response (0x%02x)\n", type);
			reqres_dump(++level, frm);
			break;
		case SMP_CODE_PAIRCONFIRM:
			printf("SMP: Pairing confirm (0x%02x)\n", type);
			break;
		case SMP_CODE_PAIRRAND:
			printf("SMP: Pairing random (0x%02x)\n", type);
			break;
		case SMP_CODE_PAIRFAIL:
			printf("SMP: Pairing failed (0x%02x)\n", type);
			p_indent(++level, frm);
			printf("Reason: 0x%02x\n", get_u8(frm));
			break;
		case SMP_CODE_LTK:
			printf("SMP: Encryption information (LTK) (0x%02x)\n", type);
			break;
		case SMP_CODE_CID:
			printf("SMP: Central information (0x%02x)\n", type);
			break;
		case SMP_CODE_IRK:
			printf("SMP: Identity information (IRK) (0x%02x)\n", type);
			break;
		default:
			printf("SMP data: %02x\n", type);
	}
}

static void reqres_dump(int level, struct frame *frm) {
	struct ng_l2cap_smp_pairinfo *pkt = (struct ng_l2cap_smp_pairinfo *) frm->ptr;
	uint8_t flags = pkt->authreq;
	p_indent(level, frm);
	printf("Flags: ");
	if (flags & SMP_AUTH_BOND)
		printf("bond |");
	if (flags & SMP_AUTH_MITM)
		printf("mitm |");
	if (flags & SMP_AUTH_CS)
		printf("cs |");
	if (flags & SMP_AUTH_KEYPRESS)
		printf("keyp |");
	if (flags & SMP_AUTH_CT2)
		printf("ct2");
	printf("\n");

	p_indent(level, frm);
	printf("Max key size: %d\n", pkt->maxkeysize);
}
