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
#include <sys/socket.h>

#include <bitstring.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define L2CAP_SOCKET_CHECKED

#include <netgraph/bluetooth/include/ng_hci.h>
#include <netgraph/bluetooth/include/ng_l2cap.h>
#include <netgraph/bluetooth/include/ng_btsocket.h>

#include "parser.h"
#include "hcidump.h"

/* Default options */
static char *device = NULL;
static int  snap_len = SNAP_LEN;
static int  defpsm = 0;
static int  mode = PARSE;
static long flags;
static long filter;
static char *dump_file;

static int read_n(int fd, char *buf, int len)
{
	register int t=0, w;

	while (len > 0) {
		if ((w = read(fd, buf, len)) < 0) {
			if( errno == EINTR || errno == EAGAIN )
				continue;
			return -1;
		}
		if (!w)
			return 0;
		len -= w; buf += w; t += w;
	}
	return t;
}   

static int write_n(int fd, char *buf, int len)
{
	register int t=0, w;

	while (len > 0) {
		if ((w = write(fd, buf, len)) < 0) {
			if( errno == EINTR || errno == EAGAIN )
				continue;
			return -1;
		}
		if (!w)
			return 0;
		len -= w; buf += w; t += w;
	}
	return t;
}

static void process_frames(char *dev, int sock, int file)
{
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec  iv;
	struct dump_hdr *dh;
	struct frame frm;
	char *buf, *ctrl;

	if (snap_len < SNAP_LEN)
		snap_len = SNAP_LEN;

	if (!(buf = malloc(snap_len + DUMP_HDR_SIZE))) {
		perror("Can't allocate data buffer");
		exit(1);
	}
	dh = (void *) buf;
	frm.data = buf + DUMP_HDR_SIZE;
	
	if (!(ctrl = malloc(100))) {
		perror("Can't allocate control buffer");
		exit(1);
	}
	
	printf("device: %s snap_len: %d filter: 0x%lx\n", 
		dev? dev : "any", snap_len, filter);

	if (getuid() != 0)
		printf(
"** WARNING: You are running hcidump as non-privileged user.\n" \
"** WARNING: You will not be able to see all data.\n\n");

	memset(&msg, 0, sizeof(msg));

	while (1) {
		iv.iov_base = frm.data;
		iv.iov_len  = snap_len;

		msg.msg_iov = &iv;
		msg.msg_iovlen = 1;
		msg.msg_control = ctrl;
		msg.msg_controllen = 100;

		if ((frm.data_len = recvmsg(sock, &msg, 0)) < 0) {
			perror("Receive failed");
			exit(1);
		}

		/* Process control message */
		frm.in = 0;
		cmsg = CMSG_FIRSTHDR(&msg);
		while (cmsg) {
			if (cmsg->cmsg_level == SOL_HCI_RAW &&
			    cmsg->cmsg_type == SCM_HCI_RAW_DIRECTION)
				memcpy(&frm.in,CMSG_DATA(cmsg),sizeof(frm.in));

			if (cmsg->cmsg_level == SOL_SOCKET &&
			    cmsg->cmsg_type == SCM_TIMESTAMP)
				memcpy(&frm.ts,CMSG_DATA(cmsg),sizeof(frm.ts));

			cmsg = CMSG_NXTHDR(&msg, cmsg);
		}

		frm.ptr = frm.data;
		frm.len = frm.data_len;

		switch (mode) {
		case WRITE:
			/* Save dump */	
			dh->len = htole16(frm.data_len);
			dh->in  = frm.in;
			dh->ts_sec  = htole32(frm.ts.tv_sec);
			dh->ts_usec = htole32(frm.ts.tv_usec);
			if (write_n(file, buf, frm.data_len + DUMP_HDR_SIZE) < 0) {
				perror("Write error");
				exit(1);
			}
			break;

		default:
			/* Parse and print */
			parse(&frm);
			break;
		}
	}
}

static void read_dump(int file)
{
	struct dump_hdr dh;
	struct frame frm;
	int err;

	if (!(frm.data = malloc(SNAP_LEN))) {
		perror("Can't allocate data buffer");
		exit(1);
	}
	
	while (1) {
		if ((err = read_n(file, (void *) &dh, DUMP_HDR_SIZE)) < 0)
			goto failed;
		if (!err) return;
		
		frm.data_len = le16toh(dh.len);

		if ((err = read_n(file, frm.data, frm.data_len)) < 0)
			goto failed;
		if (!err) return;

		frm.ptr = frm.data;
		frm.len = frm.data_len;
		frm.in  = dh.in;
		frm.ts.tv_sec  = le32toh(dh.ts_sec);
		frm.ts.tv_usec = le32toh(dh.ts_usec);
		
		parse(&frm);
	}

failed:
	perror("Read failed");
	exit(1);
}

static int open_file(char *file, int mode)
{
	int f, flags;

	if (mode == WRITE)
		flags = O_WRONLY | O_CREAT | O_APPEND;
	else
		flags = O_RDONLY;

	if ((f = open(file, flags, 0600)) < 0) {
		perror("Can't open output file");
		exit(1);
	}
	return f;
}

static int open_socket(char *dev)
{
	struct sockaddr_hci addr;
	struct ng_btsocket_hci_raw_filter flt;
	int s, opt;

	/* Create HCI socket */
	if ((s=socket(AF_BLUETOOTH, SOCK_RAW, BLUETOOTH_PROTO_HCI)) < 0) {
		perror("Can't create HCI socket");
		exit(1);
	}

	opt = 128 * 1024; /* 128 KB */
	if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) < 0) {
		perror("Can't set socket receive buffer size");
		exit(1);
	}

	opt = 1;
	if (setsockopt(s, SOL_HCI_RAW, SO_HCI_RAW_DIRECTION, &opt, sizeof(opt)) < 0) {
		perror("Can't enable data direction info");
		exit(1);
	}

	opt = 1;
	if (setsockopt(s, SOL_SOCKET, SO_TIMESTAMP, &opt, sizeof(opt)) < 0) {
		perror("Can't enable time stamp");
		exit(1);
	}

	/* Setup filter */
	memset(&flt, 0xff, sizeof(flt));
	if (setsockopt(s, SOL_HCI_RAW, SO_HCI_RAW_FILTER, (void const *) &flt, sizeof(flt)) < 0) {
		perror("Can't set HCI filter");
		exit(1);
	}

	/* Bind socket to the HCI device */
	memset(&addr, 0, sizeof(addr));
	addr.hci_len = sizeof(addr);
	addr.hci_family = AF_BLUETOOTH;
	if (dev != NULL) {
		strncpy(addr.hci_node, dev, sizeof(addr.hci_node));

		if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			printf("Can't attach to device %s. %s(%d)\n", 
					dev, strerror(errno), errno);
			exit(1);
		}
	}
	return s;
}

static struct {
	char *name;
	int  flag;
} filters[] = {
	{ "hci",    FILT_HCI    },
	{ "l2cap",  FILT_L2CAP  },
	{ "sco",    FILT_SCO    },
	{ "rfcomm", FILT_RFCOMM },
	{ "sdp",    FILT_SDP    },
	{ "bnep",   FILT_BNEP	},
	{ "cmtp",   FILT_CMTP	},
	{ "hidp",   FILT_HIDP   },
	{ NULL,     0           }
};

static void parse_filter(int argc, char **argv)
{
	int i,n;
	
	for (i=0; i<argc; i++) {
		for (n=0; filters[n].name; n++) {
			if (!strcmp(filters[n].name, argv[i])) {
				filter |= filters[n].flag;
				break;
			}
		}
	}
}

static void usage(void)
{
	printf(
	"Usage: hcidump [OPTION...] [filter]\n"
	"  -i, --device=hci_dev       HCI device\n"
	"  -p, --psm=psm              Default PSM\n"
	"  -s, --snap-len=len         Snap len (in bytes)\n"
	"  -r, --read-dump=file       Read dump from a file\n"
	"  -w, --save-dump=file       Save dump to a file\n"
	"  -a, --ascii                Dump data in ascii\n"
	"  -x, --hex                  Dump data in hex\n"
	"  -R, --raw                  Raw mode\n"
	"  -t, --ts                   Display time stamps\n"
	"  -?, --help                 Give this help list\n"
	"      --usage                Give a short usage message\n"
	);
}

static struct option main_options[] = {
	{"device",	1,0, 'i' },
	{"snap-len", 	1,0, 's' },
	{"psm", 	1,0, 'p' },
	{"save-dump",	1,0, 'w' },
	{"read-dump",	1,0, 'r' },
	{"ts", 		0,0, 't' },
	{"hex", 	0,0, 'x' },
	{"ascii", 	0,0, 'a' },
	{"raw", 	0,0, 'R' },
	{"help", 	0,0, 'h' },
	{ NULL,         0,0,  0  }
};

int main(int argc, char *argv[])
{
	int opt;

	printf("HCIDump - HCI packet analyzer ver %s\n", VERSION);

        while ((opt=getopt_long(argc, argv, "i:s:p:r:w:xathR", main_options, NULL)) != -1) {
                switch(opt) {
		case 'i':
			device = optarg;
			break;

		case 'x':
			flags |= DUMP_HEX;
			break;

		case 'a': 
			flags |= DUMP_ASCII;
			break;

		case 's': 
			snap_len = atoi(optarg);
			break;

		case 'p': 
			defpsm = atoi(optarg);
			break;

		case 't': 
			flags |= DUMP_TSTAMP;
			break;

		case 'R': 
			flags |= DUMP_RAW;
			break;

		case 'r':
			mode = READ;
			dump_file = strdup(optarg);
			break;

		case 'w':
			mode = WRITE;
			dump_file = strdup(optarg);
			break;

                case 'h':
                default:
                        usage();
                        exit(0);
                }
        }

        argc -= optind;
        argv += optind;
        optind = 0;


	if (argc > 0)
		parse_filter(argc, argv);

	/* Default settings */
	if (!filter)
		filter = ~0L;

	switch (mode) {
	case PARSE:
		init_parser(flags, filter, defpsm);
		process_frames(device, open_socket(device), -1);
		break;

	case WRITE:
		process_frames(device, open_socket(device), open_file(dump_file, mode));
		break;

	case READ:
		init_parser(flags, filter, defpsm);
		read_dump(open_file(dump_file, mode));
		break;
	}
	return 0;
}
