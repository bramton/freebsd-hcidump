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
#include <stdio.h>

#include "parser.h"

char *event_map[] = {
	"Unknown",
	"Inquiry Complete", /* 0x01 */
	"Inquiry Result",
	"Connect Complete",
	"Connect Request",
	"Disconn Complete",
	"Auth Complete",
	"Remote Name Req Complete",
	"Encrypt Change",
	"Change Connection Link Key Complete",
	"Master Link Key Complete", /* 0x0a */
	"Read Remote Supported Features",
	"Read Remote Ver Info Complete",
	"QoS Setup Complete",
	"Command Complete",
	"Command Status",
	"Hardware Error", /* 0x10 */
	"Flush Occurred",
	"Role Change",
	"Number of Completed Packets",
	"Mode Change",
	"Return Link Keys",
	"PIN Code Request",
	"Link Key Request",
	"Link Key Notification",
	"Loopback Command",
	"Data Buffer Overflow", /* 0x1a */
	"Max Slots Change",
	"Read Clock Offset Complete",
	"Connection Packet Type Changed",
	"QoS Violation",
	"Page Scan Mode Change",
	"Page Scan Repetition Mode Change", /* 0x20 */
	"Flow Specification Complete",
	"Inquiry Result with RSSI",
	"Read Remote Extended Features Complete",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown", /* 0x2a */
	"Unknown",
	"Synchronous Connection Complete",
	"Synchronous Connection Changed",
	"Sniff Subrating",
	"Extended Inquiry Result",
	"Encryption Key Refresh Complete", /* 0x30 */
	"IO Capability Request",
	"IO Capability Response",
	"User Confirmation Request",
	"User Passkey Request",
	"Remote OOB Data Request",
	"Simple Pairing Complete",
	"Unknown",
	"Link Supervision Timeout Changed",
	"Enhanced Flush Complete",
	"Unknown", /* 0x3a */
	"User Passkey Notification",
	"Keypress Notification",
	"Remote Host Supported Features Notification"
};
#define EVENT_NUM	61

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
	"Read LMP Handle", /* 0x0020 */
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Setup Synchronous Connection",
	"Accept Synchronous Connection Request",
	"Reject Synchronous Connection Request", /* 0x002a */
	"IO Capability Request Reply",
	"User Confirmation Request Reply",
	"User Confirmation Request Negative Reply",
	"User Passkey Request Reply",
	"User Passkey Request Negative Reply",
	"Remote OOB Data Request Reply", /* 0x0030 */
	"Unknown",
	"Unknown",
	"Remote OOB Data Request Negative Reply",
	"IO Capability Request Negative Reply",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown", /* 0x003a */
	"Unknown",
	"Unknown",
	"Enhanced Setup Synchronous Connection",
	"Enhanced Accept Synchronous Connection Request",
	"Truncated Page",
	"Truncated Page Cancel", /* 0x0040 */
	"Set Connectionless Peripheral Broadcast",
	"Set Connectionless Peripheral Broadcast Receive",
	"Start Synchronization Train",
	"Receive Synchronization Train",
	"Remote OOB Extended Data Request Reply"
};
#define CMD_LINKCTL_NUM	69

char *cmd_linkctl_le_map[] = {
	"Unknown",
	"LE Set Event Mask", /* 0x0001 */
	"LE Read Buffer Size v1",
	"LE Read Local Supported Features Page0",
	"Unknown",
	"LE Set Random Address",
	"LE Set Advertising Parameters",
	"LE Read Advertising Physical Channel Tx Power",
	"LE Set Advertising Data",
	"LE Set Scan Response Data",
	"LE Set Advertising Enable", /* 0x000a */
	"LE Set Scan Parameters",
	"LE Set Scan Enable",
	"LE Create Connection",
	"LE Create Connection Cancel",
	"LE Read Filter Accept List Size",
	"LE Clear Filter Accept List", /* 0x0010 */
	"LE Add Device To Filter Accept List",
	"LE Remove Device From Filter Accept List",
	"LE Connection Update",
	"LE Set Host Channel Classification",
	"LE Read Channel Map",
	"LE Read Remote Features Page0",
	"LE Encrypt",
	"LE Rand",
	"LE Enable Encryption",
	"LE Long Term Key Request Reply", /* 0x001a */
	"LE Long Term Key Request Negative Reply",
	"LE Read Supported States",
	"LE Receiver Test v1",
	"LE Transmitter Test v1",
	"LE Test End",
	"LE Remote Connection Parameter Request Reply", /* 0x0020 */
	"LE Remote Connection Parameter Request Negative Reply",
	"LE Set Data Length",
	"LE Read Suggested Default Data Length",
	"LE Write Suggested Default Data Length",
	"LE Read Local P256 Public Key",
	"LE Generate DHKey v1",
	"LE Add Device To Resolving List",
	"LE Remove Device From Resolving List",
	"LE Clear Resolving List",
	"LE Read Resolving List Size", /* 0x002a */
	"LE Read Peer Resolvable Address",
	"LE Read Local Resolvable Address",
	"LE Set Address Resolution Enable",
	"LE Set Resolvable Private Address Timeout v1",
	"LE Read Maximum Data Length",
	"LE Read PHY", /* 0x0030 */
	"LE Set Default PHY",
	"LE Set PHY",
	"LE Receiver Test v2",
	"LE Transmitter Test v2",
	"LE Set Advertising Set Random Address",
	"LE Set Extended Advertising Parameters v1",
	"LE Set Extended Advertising Data",
	"LE Set Extended Scan Response Data",
	"LE Set Extended Advertising Enable",
	"LE Read Maximum Advertising Data Length", /* 0x003a */
	"LE Read Number of Supported Advertising Sets",
	"LE Remove Advertising Set",
	"LE Clear Advertising Sets",
	"LE Set Periodic Advertising Parameters v1",
	"LE Advertising Data",
	"LE Set Periodic Advertising Enable", /* 0x0040 */
	"LE Set Extended Scan Parameters",    
	"LE Set Extended Scan Enable",
	"LE Extended Create Connection v1",
	"LE Periodic Advertising Create Sync",
	"LE Periodic Advertising Create Sync Cancel",
	"LE Periodic Advertising Terminate Sync",
	"LE Add Device To Periodic Advertiser List",
	"LE Remove Device From Periodic Advertiser List",
	"LE Clear Periodic Advertiser List",
	"LE Read Periodic Advertiser List Size", /* 0x004a */
	"LE Read Transmit Power",
	"LE Read RF Path Compensation",
	"LE Write RF Path Compensation",
	"LE Set Privacy Mode",
	"LE Receiver Test v3",
	"LE Transmitter Test v3", /* 0x0050 */
	"LE Set Connectionless CTE Transmit Parameters",
	"LE Set Connectionless CTE Transmit Enable",
	"LE Set Connectionless IQ Sampling Enable",
	"LE Set Connection CTE Receive Parameters",
	"LE Set Connection CTE Transmit Parameters",
	"LE Connection CTE Request Enable",
	"LE Connection CTE Response Enable",
	"LE Read Antenna Information",
	"LE Set Periodic Advertising Receive Enable",  
	"LE Periodic Advertising Sync Transfer", /* 0x005a */
	"LE Periodic Advertising Set Info Transfer",
	"LE Set Periodic Advertising Sync Transfer Parameters",
	"LE Set Default Periodic Advertising Sync Transfer Parameters",
	"LE Generate DHKey v2",
	"LE Modify Sleep Clock Accuracy",
	"LE Read Buffer Size v2", /* 0x0060 */
	"LE Read ISO TX Sync",
	"LE Set CIG Parameters",
	"LE Set CIG Parameters Test",
	"LE Create CIS",
	"LE Remove CIG",
	"LE Accept CIS Request",
	"LE Reject CIS Request",
	"LE Create BIG",
	"LE Create BIG Test",
	"LE Terminate BIG", /* 0x006a */
	"LE BIG Create Sync",
	"LE BIG Terminate Sync",
	"LE Request Peer SCA",
	"LE Setup ISO Data Path",
	"LE Remove ISO Data Path",
	"LE ISO Transmit Test", /* 0x0070 */
	"LE ISO Receive Test",
	"LE ISO Read Test Counters",
	"LE ISO Test End",
	"LE Set Host Feature",
	"LE Read ISO Link Quality",
	"LE Enhanced Read Transmit Power Level",
	"LE Read Remote Transmit Power Level",
	"LE Set Path Loss Reporting Parameters",
	"LE Set Path Loss Reporting Enable",    
	"LE Set Transmit Power Reporting Enable", /* 0x007a */
	"LE Transmitter Test v4",
	"LE Set Data Related Address Changes",
	"LE Set Default Subrate",
	"LE Subrate Request",
	"LE Set Extended Advertising Parameters v2",
	"LE Set Decision Data", /* 0x0080 */
	"LE Set Decision Instructions",
	"LE Set Periodic Advertising Subevent Data",
	"LE Set Periodic Advertising Response Data",
	"LE Set Periodic Sync Subevent",
	"LE Extended Create Connection v2",
	"LE Set Periodic Advertising Parameters v2",
	"LE Read All Local Supported Features",
	"LE Read All Remote Features",
	"LE CS Read Local Supported Capabilities",
	"LE CS Read Remote Supported Capabilities", /* 0x008a */
	"LE CS Write Cached Remote Supported Capabilities",
	"LE CS Security Enable",
	"LE CS Set Default Settings",
	"LE CS Read Remote FAE Table",
	"LE CS Write Cached Remote FAE Table",
	"LE CS Create Config", /* 0x0090 */
	"LE CS Remove Config",
	"LE CS Set Channel Classification",
	"LE CS Set Procedure Parameters",
	"LE CS Procedure Enable",
	"LE CS Test",
	"LE CS Test End",
	"LE Set Host Feature v2",
	"LE Add Device To Monitored Advertisers List",
	"LE Remove Device From Monitored Advertisers",
	"LE Clear Monitored Advertisers List", /* 0x009a */
	"LE Read Monitored Advertisers List Size",
	"LE Enable Monitoring Advertisers",
	"LE Frame Space Update",
	"LE Set Resolvable Private Address Timeout v2",
	"LE Enable UTP OTA",
	"LE UTP Send", /* 0x00a0 */
	"LE Connection Rate Request",
	"LE Set Default Rate Parameters",
	"LE Read Minimum Supported Connection Interval"
};
#define CMD_LINKCTL_LE_NUM	163

char *cmd_linkpol_map[] = {
	"Unknown",
	"Hold Mode", /* 0x0001 */
	"Unknown",
	"Sniff Mode",
	"Exit Sniff Mode",
	"Park Mode",
	"Exit Park Mode",
	"QoS Setup",
	"Unknown",
	"Role Discovery",
	"Unknown", /* 0x000a */
	"Switch Role",
	"Read Link Policy Settings",
	"Write Link Policy Settings",
	"Read Default Link Policy Settings",
	"Write Default Link Policy Settings",
	"Flow Specification", /* 0x0010 */
	"Sniff Subrating"
};
#define CMD_LINKPOL_NUM 17

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
	"Write Current IAC LAP", /* 0x003a */
	"Read Page Scan Period Mode",
	"Write Page Scan Period Mode",
	"Read Page Scan Mode",
	"Write Page Scan Mode",
	"Set AFH Host Channel Classification",    
	"Unknown", /* 0x0040 */
	"Unknown",
	"Read Inquiry Scan Type",
	"Write Inquiry Scan Type",
	"Read Inquiry Mode",
	"Write Inquiry Mode",
	"Read Page Scan Type",
	"Write Page Scan Type",
	"Read AFH Channel Assessment Mode",
	"Write AFH Channel Assessment Mode",
	"Unknown", /* 0x0050 */
	"Read Extended Inquiry Response",
	"Write Extended Inquiry Response",
	"Refresh Encryption Key",
	"Unknown",
	"Read Simple Pairing Mode",
	"Write Simple Pairing Mode",
	"Read Local OOB Data",
	"Read Inquiry Response Transmit Power Level",
	"Write Inquiry Transmit Power Level",
	"Read Default Erroneous Data Reporting", /* 0x005a */
	"Write Default Erroneous Data Reporting",
	"Unknown",
	"Unknown",
	"Unknown",
	"Enhanced Flush",
	"Send Keypress Notification", /* 0x0060 */
	"Unknown",
	"Unknown",
	"Set Event Mask Page2",
	"Unknown",
	"Unknown",
	"Read Flow Control Mode",
	"Write Flow Control Mode",
	"Read Enhanced Transmit Power Level",
	"Unknown",
	"Unknown", /* 0x006a */
	"Unknown",
	"Read LE Host Support",
	"Write LE Host Support",
	"Set MWS Channel Parameters",
	"Set External Frame Configuration",
	"Set MWS Signaling", /* 0x0070 */
	"Set MWS Transport Layer",
	"Set MWS Scan Frequency Table",
	"Set MWS_PATTERN Configuration",
	"Set Reserved LT_ADDR",
	"Delete Reserved LT_ADDR",
	"Set Connectionless Peripheral Broadcast Data",
	"Read Synchronization Train Parameters",
	"Write Synchronization Train Parameters",
	"Read Secure Connections Host Support",
	"Write Secure Connections Host Support", /* 0x007a */
	"Read Authenticated Payload Timeout",
	"Write Authenticated Payload Timeout",
	"Read Local OOB Extended Data",
	"Read Extended Page Timeout",
	"Write Extended Page Timeout",
	"Read Extended Inquiry Length", /* 0x0080 */
	"Write Extended Inquiry Length",
	"Set Ecosystem Base Interval",
	"Configure Data Path",
	"Set Min Encryption Key Size"
};
#define CMD_HOSTCTL_NUM 126

char *cmd_info_map[] = {
	"Unknown",
	"Read Local Version Information",
	"Read Local Supported Commands",
	"Read Local Supported Features",
	"Read Local Extended Features",
	"Read Buffer Size",
	"Unknown",
	"Read Country Code",
	"Unknown",
	"Read BD ADDR",
	"Read Data Block Size", /* 0x000a */
	"Read Local Supported Codecs v1",
	"Read Local Simple Pairing Options",
	"Read Local Supported Codecs v2",
	"Read Local Supported Codec Capabilities",
	"Read Local Supported Controller Delay"
};
#define CMD_INFO_NUM 15

char *cmd_status_map[] = {
	"Unknown",
	"Read Failed Contact Counter",
	"Reset Failed Contact Counter",
	"Read Link Quality",
	"Unknown",
	"Read RSSI",
	"Read AFH Channel Map",
	"Read Clock",
	"Read Encryption Key Size",
	"Unknown",
	"Unknown", /* 0x000a */
	"Unknown",    
	"Get MWS Transport Layer Configuration",
	"Set Triggered Clock Capture"
};
#define CMD_STATUS_NUM 13

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
