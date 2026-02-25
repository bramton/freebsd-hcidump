#include "att.h"

void att_dump(int level, struct frame *frm) {
	p_indent(level, frm);
	uint8_t opc = get_u8(frm); /* Attribute opcode */
	printf("ATT data: %02x\n", opc & 0x3f);
}
