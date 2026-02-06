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
 * Id: hci.c,v 1.14 2002/12/21 19:22:21 holtmann Exp
 * $Id: hci.c,v 1.5 2003/09/12 23:38:11 max Exp $
 */

#include <sys/types.h>
#include <sys/endian.h>
#include <netgraph/bluetooth/include/ng_hci.h>
#include <stdio.h>

#include "parser.h"

char *event_map[] = {
	"Unknown",
	"Inquiry Complete",
	"Inquiry Result",
	"Connect Complete",
	"Connect Request",
	"Disconn Complete",
	"Auth Complete",
	"Remote Name Req Complete",
	"Encrypt Change",
	"Change Connection Link Key Complete",
	"Master Link Key Complete",
	"Read Remote Supported Features",
	"Read Remote Ver Info Complete",
	"QoS Setup Complete",
	"Command Complete",
	"Command Status",
	"Hardware Error",
	"Flush Occurred",
	"Role Change",
	"Number of Completed Packets",
	"Mode Change",
	"Return Link Keys",
	"PIN Code Request",
	"Link Key Request",
	"Link Key Notification",
	"Loopback Command",
	"Data Buffer Overflow",
	"Max Slots Change",
	"Read Clock Offset Complete",
	"Connection Packet Type Changed",
	"QoS Violation",
	"Page Scan Mode Change",
	"Page Scan Repetition Mode Change"
};
#define EVENT_NUM	32

char *event_map_le[] = {
	"LE Unknown",
	"LE Connection Complete", /* 0x01 */
	"LE Advertising Report",
	"LE Connection Update Complete",
	"LE Read Remote Features Page0 Complete",
	"LE Long Term Key Request",
	"LE Remote Connection Parameter Request",
	"LE Data Length Change",
	"LE Read Local P256 Public Key Complete",
	"LE Generate DHKey Complete",
	"LE Enhanced Connection Complete v1", /* 0x0a */
	"LE Directed Advertising Report ",
	"LE PHY Update Complete",
	"LE Extended Advertising Report",
	"LE Periodic Advertising Sync Established v1",
	"LE Periodic Advertising Report v1",
	"LE Periodic Advertising Sync Lost", /* 0x10 */
	"LE Scan Timeout",
	"LE Advertising Set Terminated",
	"LE Scan Request Received",
	"LE Channel Selection Algorithm",
	"LE Connectionless IQ Report",
	"LE Connection IQ Report",
	"LE CTE Request Failed",
	"LE Periodic Advertising Sync Transfer Received v1",
	"LE CIS Established",
	"LE CIS Request", /* 0x1a */
	"LE Create BIG Complete",
	"LE Terminate BIG Complete",
	"LE BIG Sync Established",
	"LE BIG Sync Lost",
	"LE Request Peer SCA Complete",
	"LE Path Loss Threshold", /* 0x20 */
	"LE Transmit Power Reporting",
	"LE BIGInfo Advertising Report",
	"LE Subrate Change",
	"LE Periodic Advertising Sync Established v2",
	"LE Periodic Advertising Report v2",
	"LE Periodic Advertising Sync Transfer Received v2",
	"LE Periodic Advertising Subevent Data Request",
	"LE Periodic Advertising Response Report",
	"LE Enhanced Connection Complete v2",
	"LE CIS Established v2", /* 0x2a */
	"LE Read All Remote Features Complete",
	"LE CS Read Remote Supported Capabilities Complete",
	"LE CS Read Remote FAE Table Complete",
	"LE CS Security Enable Complete",
	"LE CS Config Complete",
	"LE CS Procedure Enable Complete", /* 0x30 */
	"LE CS Subevent Result",
	"LE CS Subevent Result Continue",
	"LE CS Test End Complete",
	"LE Monitored Advertisers Report",
	"LE Frame Space Update Complete",
	"LE UTP Receive",
	"LE Connection Rate Change"
};
#define EVENT_LE_NUM	55

char *cmd_linkctl_map[] = {
	"Unknown",
	"Inquiry",
	"Inquiry Cancel",
	"Periodic Inquiry Mode",
	"Exit Periodic Inquiry Mode",
	"Create Connection",
	"Disconnect",
	"Add SCO Connection",
	"Unknown",
	"Accept Connection Request",
	"Reject Connection Request",
	"Link Key Request Reply",
	"Link Key Request Negative Reply",
	"PIN Code Request Reply",
	"PIN Code Request Negative Reply",
	"Change Connection Packet Type",
	"Unknown",
	"Authentication Requested",
	"Unknown",
	"Set Connection Encryption",
	"Unknown",
	"Change Connection Link Key",
	"Unknown",
	"Master Link Key",
	"Unknown",
	"Remote Name Request",
	"Unknown",
	"Read Remote Supported Features",
	"Unknown",
	"Read Remote Version Information",
	"Unknown",
	"Read Clock offset"
};
#define CMD_LINKCTL_NUM	31

char *cmd_linkpol_map[] = {
	"Unknown",
	"Hold Mode",
	"Unknown",
	"Sniff Mode",
	"Exit Sniff Mode",
	"Park Mode",
	"Exit Park Mode",
	"QoS Setup",
	"Unknown",
	"Role Discovery",
	"Unknown",
	"Switch Role",
	"Read Link Policy Settings",
	"Write Link Policy Settings"
};
#define CMD_LINKPOL_NUM 13

char *cmd_hostctl_map[] = {
	"Unknown",
	"Set Event Mask",
	"Unknown",
	"Reset",
	"Unknown",
	"Set Event Filter",
	"Unknown",
	"Unknown",
	"Flush",
	"Read PIN Type ",
	"Write PIN Type",
	"Create New Unit Key",
	"Unknown",
	"Read Stored Link Key",
	"Unknown",
	"Unknown",
	"Unknown",
	"Write Stored Link Key",
	"Delete Stored Link Key",
	"Change Local Name",
	"Read Local Name",
	"Read Connection Accept Timeout",
	"Write Connection Accept Timeout",
	"Read Page Timeout",
	"Write Page Timeout",
	"Read Scan Enable",
	"Write Scan Enable",
	"Read Page Scan Activity",
	"Write Page Scan Activity",
	"Read Inquiry Scan Activity",
	"Write Inquiry Scan Activity",
	"Read Authentication Enable",
	"Write Authentication Enable",
	"Read Encryption Mode",
	"Write Encryption Mode",
	"Read Class of Device",
	"Write Class of Device",
	"Read Voice Setting",
	"Write Voice Setting",
	"Read Automatic Flush Timeout",
	"Write Automatic Flush Timeout",
	"Read Num Broadcast Retransmissions",
	"Write Num Broadcast Retransmissions",
	"Read Hold Mode Activity ",
	"Write Hold Mode Activity",
	"Read Transmit Power Level",
	"Read SCO Flow Control Enable",
	"Write SCO Flow Control Enable",
	"Unknown",
	"Set Host Controller To Host Flow Control",
	"Unknown",
	"Host Buffer Size",
	"Unknown",
	"Host Number of Completed Packets",
	"Read Link Supervision Timeout",
	"Write Link Supervision Timeout",
	"Read Number of Supported IAC",
	"Read Current IAC LAP",
	"Write Current IAC LAP",
	"Read Page Scan Period Mode",
	"Write Page Scan Period Mode",
	"Read Page Scan Mode",
	"Write Page Scan Mode"
};
#define CMD_HOSTCTL_NUM 62

char *cmd_info_map[] = {
	"Unknown",
	"Read Local Version Information",
	"Unknown",
	"Read Local Supported Features",
	"Unknown",
	"Read Buffer Size",
	"Unknown",
	"Read Country Code",
	"Unknown",
	"Read BD ADDR"
};
#define CMD_INFO_NUM 9

char *cmd_status_map[] = {
	"Unknown",
	"Read Failed Contact Counter",
	"Reset Failed Contact Counter",
	"Get Link Quality",
	"Unknown",
	"Read RSSI"
};
#define CMD_STATUS_NUM 5

static void command_dump(int level, struct frame *frm)
{
	ng_hci_cmd_pkt_t *hdr = frm->ptr;
	uint16_t opcode = le16toh(hdr->opcode);
	uint16_t ogf = NG_HCI_OGF(opcode);
	uint16_t ocf = NG_HCI_OCF(opcode);
	char *cmd;

	if (p_filter(FILT_HCI))
		return;

	switch (ogf) {
	case NG_HCI_OGF_INFO:
		if (ocf <= CMD_INFO_NUM)
			cmd = cmd_info_map[ocf];
		else
			cmd = "Unknown";
		break;

	case NG_HCI_OGF_HC_BASEBAND:
		if (ocf <= CMD_HOSTCTL_NUM)
			cmd = cmd_hostctl_map[ocf];
		else
			cmd = "Unknown";
		break;

	case NG_HCI_OGF_LINK_CONTROL:
		if (ocf <= CMD_LINKCTL_NUM)
			cmd = cmd_linkctl_map[ocf];
		else
			cmd = "Unknown";
		break;

	case NG_HCI_OGF_LINK_POLICY:
		if (ocf <= CMD_LINKPOL_NUM)
			cmd = cmd_linkpol_map[ocf];
		else
			cmd = "Unknown";
		break;

	case NG_HCI_OGF_STATUS:
		if (ocf <= CMD_STATUS_NUM)
			cmd = cmd_status_map[ocf];
		else
			cmd = "Unknown";
		break;

	case NG_HCI_OGF_BT_LOGO:
		cmd = "Testing";
		break;

	case NG_HCI_OGF_VENDOR:
		cmd = "Vendor";
		break;

	default:
		cmd = "Unknown";
		break;
	}

	p_indent(level, frm);

	printf("HCI Command: %s(0x%2.2x|0x%4.4x) plen %d\n", 
		cmd, ogf, ocf, hdr->length);

	frm->ptr += sizeof(*hdr);
	frm->len -= sizeof(*hdr);

	raw_dump(level, frm);
}

static void event_dump(int level, struct frame *frm)
{
	ng_hci_event_pkt_t *hdr = frm->ptr;

	if (p_filter(FILT_HCI))
		return;

	p_indent(level, frm);

	if (hdr->event <= EVENT_NUM)
		printf("HCI Event: %s(0x%2.2x) plen %d\n",
			event_map[hdr->event], hdr->event, hdr->length);
	else if (hdr->event == NG_HCI_EVENT_BT_LOGO)
		printf("HCI Event: Testing(0x%2.2x) plen %d\n", hdr->event, hdr->length);
	else if (hdr->event == NG_HCI_EVENT_VENDOR)
		printf("HCI Event: Vendor(0x%2.2x) plen %d\n", hdr->event, hdr->length);
	else
		printf("HCI Event: code 0x%2.2x plen %d\n", hdr->event, hdr->length);

	frm->ptr += sizeof(*hdr);
	frm->len -= sizeof(*hdr);

	raw_dump(level, frm);
}

static void acl_dump(int level, struct frame *frm)
{
	ng_hci_acldata_pkt_t *hdr = (void *) frm->ptr;
	uint16_t handle = le16toh(hdr->con_handle);
	uint16_t dlen = le16toh(hdr->length);
	uint8_t flags = (handle >> 12); /* flags */

	if (!p_filter(FILT_HCI)) {
		p_indent(level, frm);
		printf("ACL data: handle 0x%4.4x flags 0x%2.2x dlen %d\n",
			NG_HCI_CON_HANDLE(handle), flags, dlen);
		level++;
	}
		
	frm->ptr  += sizeof(*hdr);
	frm->len  -= sizeof(*hdr);
	frm->flags  = flags;
	frm->handle = NG_HCI_CON_HANDLE(handle);

	if (parser.filter & ~FILT_HCI)
		l2cap_dump(level, frm);
	else
		raw_dump(level, frm);
}

static void sco_dump(int level, struct frame *frm)
{
	ng_hci_scodata_pkt_t *hdr = (void *) frm->ptr;
	uint16_t handle = le16toh(hdr->con_handle);

	if (!p_filter(FILT_SCO)) {
		p_indent(level, frm);
		printf("SCO data: handle 0x%4.4x dlen %d\n",
			NG_HCI_CON_HANDLE(handle), hdr->length);
		level++;

		frm->ptr += sizeof(*hdr);
		frm->len -= sizeof(*hdr);
		raw_dump(level, frm);
	}
}

void hci_dump(int level, struct frame *frm)
{
	uint8_t type = *(uint8_t *)frm->ptr; 

	switch (type) {
	case NG_HCI_CMD_PKT:
		command_dump(level, frm);
		break;

	case NG_HCI_EVENT_PKT:
		event_dump(level, frm);
		break;

	case NG_HCI_ACL_DATA_PKT:
		acl_dump(level, frm);
		break;

	case NG_HCI_SCO_DATA_PKT:
		sco_dump(level, frm);
		break;
		
	default:
		if (p_filter(FILT_HCI))
			break;

		p_indent(level, frm);
		printf("Unknown: type 0x%2.2x len %d\n", type, frm->len);
		raw_dump(level, frm);
		break;
	}
}
