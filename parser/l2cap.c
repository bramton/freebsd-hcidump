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

#include <sys/types.h>
#include <sys/endian.h>
#include <netgraph/bluetooth/include/ng_hci.h>
#include <netgraph/bluetooth/include/ng_l2cap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "parser.h"

typedef struct {
	uint16_t handle;
	struct frame frm;
} handle_info;
#define HANDLE_TABLE_SIZE 10

static handle_info handle_table[HANDLE_TABLE_SIZE];

typedef struct {
	uint16_t cid;
	uint16_t psm;
} cid_info;
#define CID_TABLE_SIZE	20

static cid_info cid_table[2][CID_TABLE_SIZE];

static struct frame * add_handle(uint16_t handle)
{
	register handle_info *t = handle_table;
	register int i;

	for (i=0; i<HANDLE_TABLE_SIZE; i++)
		if (!t[i].handle) {
			t[i].handle = handle;
			return &t[i].frm;
		}
	return NULL;
}

static struct frame * get_frame(uint16_t handle)
{
	register handle_info *t = handle_table;
	register int i;

	for (i=0; i<HANDLE_TABLE_SIZE; i++)
		if (t[i].handle == handle)
			return &t[i].frm;

	return add_handle(handle);
}

static void add_cid(int in, uint16_t cid, uint16_t psm)
{
	register cid_info *table = cid_table[in];
	register int i;

	for (i=0; i<CID_TABLE_SIZE; i++)
		if (!table[i].cid || table[i].cid == cid) {
			table[i].cid = cid;
			table[i].psm = psm;
			break;
		}
}

static void del_cid(int in, uint16_t dcid, uint16_t scid)
{
	register int t, i;
	uint16_t cid[2];

	if (!in) {
		cid[0] = dcid;
		cid[1] = scid;
	} else {
		cid[0] = scid;
		cid[1] = dcid;	
	}

	for (t=0; t<2; t++) {	
		for (i=0; i<CID_TABLE_SIZE; i++)
			if (cid_table[t][i].cid == cid[t]) {
				cid_table[t][i].cid = 0;
				break;
			}
	}
}

static uint16_t get_psm(int in, uint16_t cid)
{
	register cid_info *table = cid_table[in];
	register int i;
	
	for (i=0; i<CID_TABLE_SIZE; i++)
		if (table[i].cid == cid)
			return table[i].psm;
	return parser.defpsm;
}

static void command_rej(int level, struct frame *frm)
{
	ng_l2cap_cmd_rej_cp *h = frm->ptr;

	printf("Command rej: reason %d\n", 
			le16toh(h->reason));
}

static void conn_req(int level, struct frame *frm)
{
	ng_l2cap_con_req_cp *h = frm->ptr;

	add_cid(frm->in, le16toh(h->scid), le16toh(h->psm));

	if (p_filter(FILT_L2CAP))
		return;

	printf("Connect req: psm %d scid 0x%4.4x\n", 
			le16toh(h->psm), le16toh(h->scid));
}

static void conn_rsp(int level, struct frame *frm)
{
	ng_l2cap_con_rsp_cp *h = frm->ptr;
	uint16_t psm;

	if ((psm = get_psm(!frm->in, le16toh(h->scid))))
		add_cid(frm->in, le16toh(h->dcid), psm);

	if (p_filter(FILT_L2CAP))
		return;

	printf("Connect rsp: dcid 0x%4.4x scid 0x%4.4x result %d status %d\n",
			le16toh(h->dcid), le16toh(h->scid),
			le16toh(h->result), le16toh(h->status));
}

static uint32_t conf_opt_val(uint8_t *ptr, uint8_t len)
{
	switch (len) {
	case 1:
		return *ptr;

        case 2:
                return le16toh(get_unaligned((uint16_t *)ptr));

        case 4:
                return le32toh(get_unaligned((uint32_t *)ptr));
	}
	return 0;
}

static void conf_opt(int level, void *ptr, int len)
{
	p_indent(level, 0);
	while (len > 0) {
		ng_l2cap_cfg_opt_t *h = ptr;
	
		ptr += sizeof(*h) + h->length;
		len -= sizeof(*h) + h->length;
		
		switch (h->type) {
		case NG_L2CAP_OPT_MTU:
			printf("MTU %d ", conf_opt_val((uint8_t *)(h + 1), h->length));
			break;
		case NG_L2CAP_OPT_FLUSH_TIMO:
			printf("FlushTO %d ", conf_opt_val((uint8_t *)(h + 1), h->length));
			break;
		default:
			printf("Unknown (type %2.2x, len %d) ", h->type, h->length);
			break;
		}
	}
	printf("\n");
}

static void conf_req(int level, ng_l2cap_cmd_hdr_t *cmd, struct frame *frm)
{
	ng_l2cap_cfg_req_cp *h = frm->ptr;
	int clen = le16toh(cmd->length) - sizeof(*h);

	if (p_filter(FILT_L2CAP))
		return;

	printf("Config req: dcid 0x%4.4x flags 0x%4.4x clen %d\n",
			le16toh(h->dcid), le16toh(h->flags), clen);
	if (clen)
		conf_opt(level, (void *)(h + 1), clen);
}

static void conf_rsp(int level, ng_l2cap_cmd_hdr_t *cmd, struct frame *frm)
{
	ng_l2cap_cfg_rsp_cp *h = frm->ptr;
	int clen = le16toh(cmd->length) - sizeof(*h);

	if (p_filter(FILT_L2CAP))
		return;

	printf("Config rsp: scid 0x%4.4x flags 0x%4.4x result %d clen %d\n",
			le16toh(h->scid), le16toh(h->flags), le16toh(h->result), clen);
	if (clen)
		conf_opt(level, (void *)(h + 1), clen);
}

static void disconn_req(int level, struct frame *frm)
{
	ng_l2cap_discon_req_cp *h = frm->ptr;

	if (p_filter(FILT_L2CAP))
		return;

	printf("Disconn req: dcid 0x%4.4x scid 0x%4.4x\n", 
			le16toh(h->dcid), le16toh(h->scid));
}

static void disconn_rsp(int level, struct frame *frm)
{
	ng_l2cap_discon_rsp_cp *h = frm->ptr;
	del_cid(frm->in, le16toh(h->dcid), le16toh(h->scid));

	if (p_filter(FILT_L2CAP))
		return;

	printf("Disconn rsp: dcid 0x%4.4x scid 0x%4.4x\n",
			le16toh(h->dcid), le16toh(h->scid));
}

static void echo_req(int level, ng_l2cap_cmd_hdr_t *cmd, struct frame *frm)
{
	if (p_filter(FILT_L2CAP))
		return;

	printf("Echo req: dlen %d\n", 
			le16toh(cmd->length));
	raw_dump(level, frm);
}

static void echo_rsp(int level, ng_l2cap_cmd_hdr_t *cmd, struct frame *frm)
{
	if (p_filter(FILT_L2CAP))
		return;

	printf("Echo rsp: dlen %d\n", 
			le16toh(cmd->length));
	raw_dump(level, frm);
}

static void info_req(int level, ng_l2cap_cmd_hdr_t *cmd, struct frame *frm)
{
	if (p_filter(FILT_L2CAP))
		return;

	printf("Info req: dlen %d\n", 
			le16toh(cmd->length));
	raw_dump(level, frm);
}

static void info_rsp(int level, ng_l2cap_cmd_hdr_t *cmd, struct frame *frm)
{
	if (p_filter(FILT_L2CAP))
		return;

	printf("Info rsp: dlen %d\n", 
			le16toh(cmd->length));
	raw_dump(level, frm);
}

static void l2cap_parse(int level, struct frame *frm)
{
	ng_l2cap_hdr_t *hdr = (void *)frm->ptr;
	uint16_t dlen = le16toh(hdr->length);
	uint16_t cid  = le16toh(hdr->dcid);
	uint16_t psm;

	frm->ptr += sizeof(*hdr);
	frm->len -= sizeof(*hdr);

	if (cid == NG_L2CAP_SIGNAL_CID) {
		/* Signaling channel */

		while (frm->len >= sizeof(ng_l2cap_cmd_hdr_t)) {
			ng_l2cap_cmd_hdr_t *hdr = frm->ptr;

			frm->ptr += sizeof(*hdr);
			frm->len -= sizeof(*hdr);

			if (!p_filter(FILT_L2CAP)) {
				p_indent(level, frm);
				printf("L2CAP(s): ");
			}

			switch (hdr->code) {
			case NG_L2CAP_CMD_REJ:
				command_rej(level, frm);
				break;
			
			case NG_L2CAP_CON_REQ:
				conn_req(level, frm);
				break;
	
			case NG_L2CAP_CON_RSP:
				conn_rsp(level, frm);
				break;

			case NG_L2CAP_CFG_REQ:
				conf_req(level, hdr, frm);		
				break;

			case NG_L2CAP_CFG_RSP:
				conf_rsp(level, hdr, frm);
				break;

			case NG_L2CAP_DISCON_REQ:
				disconn_req(level, frm);
				break;

			case NG_L2CAP_DISCON_RSP:
				disconn_rsp(level, frm);
				break;
	
			case NG_L2CAP_ECHO_REQ:
				echo_req(level, hdr, frm);
				break;

			case NG_L2CAP_ECHO_RSP:
				echo_rsp(level, hdr, frm);	
				break;

			case NG_L2CAP_INFO_REQ:
				info_req(level, hdr, frm);
				break;

			case NG_L2CAP_INFO_RSP:
				info_rsp(level, hdr, frm);
				break;

			default:
				if (p_filter(FILT_L2CAP))
					break;
				printf("code 0x%2.2x ident %d len %d\n", 
					hdr->code, hdr->ident, le16toh(hdr->length));
				raw_dump(level, frm);
			}
			frm->ptr += le16toh(hdr->length);
			frm->len -= le16toh(hdr->length);
		}
	} else if (cid == NG_L2CAP_CLT_CID) {
		/* Connectionless channel */

		if (p_filter(FILT_L2CAP))
			return;

		psm = le16toh(get_unaligned((uint16_t*)frm->ptr));
		frm->len -= 2;

		p_indent(level, frm);
		printf("L2CAP(c): cid 0x%x len %d psm %d\n", cid, dlen, psm);
		raw_dump(level, frm);
	} else {
		/* Connection oriented channel */
		uint16_t psm = get_psm(!frm->in, cid);
	
		if (!p_filter(FILT_L2CAP)) {
			p_indent(level, frm);
			printf("L2CAP(d): cid 0x%x len %d [psm %d]\n", 
				cid, dlen, psm);
			level++;
		}

		switch (psm) {
		case 0x01:
			if (!p_filter(FILT_SDP))
				sdp_dump(level+1, frm);
			else
				raw_dump(level+1, frm);
			break;

		case 0x03:
			if (!p_filter(FILT_RFCOMM))
				rfcomm_dump(level, frm);
			else
				raw_dump(level+1, frm);
			break;

		case 0x0f:
			if (!p_filter(FILT_BNEP))
				bnep_dump(level, frm);
			else
				raw_dump(level+1, frm);
			break;

		case 0x11:
		case 0x13:
			if (!p_filter(FILT_HIDP))
				hidp_dump(level, frm);
			else
				raw_dump(level+1, frm);
			break;

		case 4099:
			if (!p_filter(FILT_CMTP))
				cmtp_dump(level, frm);
			else
				raw_dump(level+1, frm);
			break;

		default:
			if (p_filter(FILT_L2CAP))
				break;

			raw_dump(level, frm);
			break;
		}
	}
}

void l2cap_dump(int level, struct frame *frm)
{
	struct frame *fr;
	ng_l2cap_hdr_t *hdr;
	uint16_t dlen;

	if (frm->flags & NG_HCI_PACKET_START) {
		hdr  = frm->ptr;
		dlen = le16toh(hdr->length);

		if (frm->len == (dlen + sizeof(*hdr))) {
			/* Complete frame */
			l2cap_parse(level, frm);
			return;
		}

		if (!(fr = get_frame(frm->handle))) {
			fprintf(stderr, "Not enough connection handles\n");
			raw_dump(level, frm);
			return;
		}

		if (fr->data) free(fr->data);

		if (!(fr->data = malloc(dlen + sizeof(*hdr)))) {
			perror("Can't allocate L2CAP reassembly buffer");
			return;
		}
		memcpy(fr->data, frm->ptr, frm->len);
		fr->data_len = dlen + sizeof(*hdr);
		fr->len = frm->len;
		fr->ptr = fr->data;
		fr->in  = frm->in;
		fr->ts  = frm->ts;
	} else {
		if (!(fr = get_frame(frm->handle))) {
			fprintf(stderr, "Not enough connection handles\n");
			raw_dump(level, frm);
			return;
		}

		if (!fr->data) {
			/* Unexpected fragment */
			raw_dump(level, frm);
			return;
		}
		
		if (frm->len > (fr->data_len - fr->len)) {
			/* Bad fragment */
			raw_dump(level, frm);
			free(fr->data); fr->data = NULL;
			return;
		}

		memcpy(fr->data + fr->len, frm->ptr, frm->len);
		fr->len += frm->len;

		if (fr->len == fr->data_len) {
			/* Complete frame */
			l2cap_parse(level, fr);

			free(fr->data); fr->data = NULL;
			return;
		}
	}
}
