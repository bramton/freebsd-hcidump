/* 
   HCIDump - HCI packet analyzer	
   Copyright (C) 2000-2001 Maxim Krasnyansky <maxk@qualcomm.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 2 as
   published by the Free Software Foundation;

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
   OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS.
   IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE FOR ANY CLAIM,
   OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES WHATSOEVER
   RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
   NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE
   USE OR PERFORMANCE OF THIS SOFTWARE.

   ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS, COPYRIGHTS,
   TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS SOFTWARE IS DISCLAIMED.
*/

/*
 * Id: parser.c,v 1.14 2002/12/08 00:37:07 holtmann Exp 
 * $Id: parser.c,v 1.4 2003/09/12 23:38:11 max Exp $
 */

#include <sys/types.h>
#include <netinet/in.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "parser.h"

struct parser_t parser;

void init_parser(unsigned long flags, unsigned long filter,
	unsigned int defpsm)
{
	if ((flags & DUMP_RAW) && !(flags & DUMP_TYPE_MASK))
		flags |= DUMP_HEX;

	parser.flags  = flags;
	parser.filter = filter;
	parser.defpsm = defpsm;
	parser.state  = 0;
}

void parse(struct frame *frm)
{
	p_indent(-1, NULL);
	if (parser.flags & DUMP_RAW)
		raw_dump(0, frm);
	else
		hci_dump(0, frm);
	fflush(stdout);
}

void p_indent(int level, struct frame *f)
{
	if (level < 0) {
		parser.state = 0;
		return;
	}

	if (!parser.state) {
		if (parser.flags & DUMP_TSTAMP)
			printf("%8lu.%06lu ", f->ts.tv_sec, f->ts.tv_usec);
		printf("%c ", (f->in ? '>' : '<'));
		parser.state = 1;
	} else
		printf("  ");

	if (level)
		printf("%*c", (level*2), ' ');
}

/* get_uXX functions do byte swaping */

uint8_t get_u8(struct frame *frm)
{
	uint8_t *u8_ptr = frm->ptr;
	frm->ptr += 1;
	frm->len -= 1;
	return *u8_ptr;
}

uint16_t get_u16(struct frame *frm)
{
	uint16_t *u16_ptr = frm->ptr;
	frm->ptr += 2;
	frm->len -= 2;
	return ntohs(get_unaligned(u16_ptr));
}

uint32_t get_u32(struct frame *frm)
{
	uint32_t *u32_ptr = frm->ptr;
	frm->ptr += 4;
	frm->len -= 4;
	return ntohl(get_unaligned(u32_ptr));
}

uint64_t get_u64(struct frame *frm)
{
	uint64_t *u64_ptr = frm->ptr;
	uint64_t u64 = get_unaligned(u64_ptr), tmp;
	frm->ptr += 8;
	frm->len -= 8;
	tmp = ntohl(u64 & 0xffffffff);
	u64 = (tmp << 32) | ntohl(u64 >> 32);
	return u64;
}

void get_u128(struct frame *frm, uint64_t *l, uint64_t *h)
{
	*h = get_u64(frm);
	*l = get_u64(frm);
}

static void hex_dump(int level, struct frame *frm, int num)
{
	unsigned char *buf = frm->ptr;
	register int i,n;

	if ((num < 0) || (num > frm->len))
		num = frm->len;

	for (i=0, n=1; i<num; i++, n++) {
		if (n == 1)
			p_indent(level, frm);
		printf("%2.2X ", buf[i]);
		if (n == DUMP_WIDTH) {
			printf("\n");
			n = 0;
		}
	}
	if (i && n!=1)
		printf("\n");
}

static void ascii_dump(int level, struct frame *frm, int num)
{
	unsigned char *buf = frm->ptr;
	register int i,n;

	if ((num < 0) || (num > frm->len))
		num = frm->len;

	for (i=0, n=1; i<num; i++, n++) {
		if (n == 1)
			p_indent(level, frm);
		printf("%1c ", isprint(buf[i]) ? buf[i] : '.');
		if (n == DUMP_WIDTH) {
			printf("\n");
			n = 0;
		}
	}
	if (i && n!=1)
		printf("\n");
}

void raw_ndump(int level, struct frame *frm, int num)
{
	if (!frm->len)
		return;

	switch (parser.flags & DUMP_TYPE_MASK) {
	case DUMP_ASCII:
		ascii_dump(level, frm, num);
		break;

	case DUMP_HEX:
		hex_dump(level, frm, num);
		break;

	}
}

void raw_dump(int level, struct frame *frm)
{
	raw_ndump(level, frm, -1);
}
