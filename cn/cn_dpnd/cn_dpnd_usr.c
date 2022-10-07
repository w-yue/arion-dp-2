// SPDX-License-Identifier: MIT
/**
 * @authors  Wei Yue           (@w-yue)
 *           Rio Zhu           (@zzxgzgz)
 *
 * @brief Compute Node XDP/eBPF module 
 *
 * @copyright Copyright (c) 2022 The Authors.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:The above copyright
 * notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.THE SOFTWARE IS PROVIDED "AS IS",
 * WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
 * FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR
 * THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <errno.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf_endian.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"

#define PORT        8300
#define checkmap    1  // check on eBPF map when eBPF module is loaded

typedef struct {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    __u8 vni[3];
} __attribute__((packed, aligned(4))) ipv4_flow_t;

typedef struct {
    // Destination Encap
    __u32 dip;
    __u32 dhip;
    __u8 dmac[6];
    __u8 dhmac[6];
    __u16 timeout;      // in seconds
    __u16 rsvd;
} dp_encap_opdata_t;

typedef struct {
    __u16 len;
    struct ethhdr eth;
    struct iphdr ip;
    struct udphdr udp;
    __u32 opcode;       // trn_xdp_flow_op_t

    // OAM OpData
    ipv4_flow_t flow;	// flow matcher

    union {
        dp_encap_opdata_t encap;
    } opdata;
} __attribute__((packed, aligned(8))) flow_ctx_t;

static inline void trn_set_mac(void *dst, unsigned char *mac)
{
    unsigned short *d = dst;
    unsigned short *s = (unsigned short *)mac;

    d[0] = s[0];
    d[1] = s[1];
    d[2] = s[2];
}

#if checkmap
#define CN_LOCAL_QUEUE_LEN 1024
static const struct option_wrapper long_options[] = {
	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"skb-mode",    no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},

	{{"auto-mode",   no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},

	{{"force",       no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"unload",      no_argument,		NULL, 'U' },
	 "Unload XDP program instead of loading"},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{"progsec",    required_argument,	NULL,  2  },
	 "Load program in <section> of the ELF file", "<section>"},

	{{0, 0, NULL,  0 }}
};

int find_map_fd(struct bpf_object *bpf_obj, const char *mapname)
{
	struct bpf_map *map;
	int map_fd = -1;

	map = bpf_object__find_map_by_name(bpf_obj, mapname);
        if (!map) {
		fprintf(stderr, "ERR: cannot find map by name: %s\n", mapname);
		goto out;
	}

	map_fd = bpf_map__fd(map);
 out:
	return map_fd;
}

static int __check_map_fd_info(int map_fd, struct bpf_map_info *info,
			       struct bpf_map_info *exp)
{
	__u32 info_len = sizeof(*info);
	int err;

	if (map_fd < 0)
		return EXIT_FAIL;

        /* BPF-info via bpf-syscall */
	err = bpf_obj_get_info_by_fd(map_fd, info, &info_len);
	if (err) {
		fprintf(stderr, "ERR: %s() can't get info - %s\n",
			__func__,  strerror(errno));
		return EXIT_FAIL_BPF;
	}

	if (exp->key_size && exp->key_size != info->key_size) {
		fprintf(stderr, "ERR: %s() "
			"Map key size(%d) mismatch expected size(%d)\n",
			__func__, info->key_size, exp->key_size);
		return EXIT_FAIL;
	}
	if (exp->value_size && exp->value_size != info->value_size) {
		fprintf(stderr, "ERR: %s() "
			"Map value size(%d) mismatch expected size(%d)\n",
			__func__, info->value_size, exp->value_size);
		return EXIT_FAIL;
	}
	if (exp->max_entries && exp->max_entries != info->max_entries) {
		fprintf(stderr, "ERR: %s() "
			"Map max_entries(%d) mismatch expected size(%d)\n",
			__func__, info->max_entries, exp->max_entries);
		return EXIT_FAIL;
	}
	if (exp->type && exp->type  != info->type) {
		fprintf(stderr, "ERR: %s() "
			"Map type(%d) mismatch expected type(%d)\n",
			__func__, info->type, exp->type);
		return EXIT_FAIL;
	}

	return 0;
}
#endif

int cn_dp_assistant(int handle, bool ckmap)
{
    flow_ctx_t sendbuf;
    int sockfd, rc;

    if (handle < 0) {
        printf("Invalid map handle, stop now\n");
        return -1;
    }

    rc = 0;

    struct sockaddr_in socket_receiver_address;
    memset(&socket_receiver_address, 0, sizeof(socket_receiver_address));
    socket_receiver_address.sin_family = AF_INET;
    socket_receiver_address.sin_port = htons(PORT);
    socket_receiver_address.sin_addr.s_addr = INADDR_ANY;
    printf("DPA ready!\n");

    /* Open RAW socket to send on */
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        printf("DPA failed to open raw socket! Err: %s\n", strerror(errno));
        return 1;
    }
    printf("Successfully created a socket.\n");
    for(;;){
        //printf("One round in the forever for loop...\n");
        dp_encap_opdata_t opdata;
        unsigned char src_mac[6] = {108,221,238,0,0,44}; //"6c:dd:ee:00:00:2c"
        unsigned char dst_mac[6] = {108,221,238,0,0,45}; //"6c:dd:ee:00:00:2d"

        memcpy(sendbuf.eth.h_dest, "00:00:01:0:0:3", sizeof(sendbuf.eth.h_dest));
        memcpy(sendbuf.eth.h_source, "00:00:01:0:0:2", sizeof(sendbuf.eth.h_source));

        sendbuf.eth.h_proto = bpf_htons(ETH_P_IP);
        sendbuf.opcode = 0; // insert flow

        opdata.dhip = inet_addr("172.16.17.74");
        trn_set_mac(opdata.dhmac, src_mac);

        opdata.dip = inet_addr("123.0.0.45");
        trn_set_mac(opdata.dmac, dst_mac);

        sendbuf.len = sizeof(sendbuf.opcode) + sizeof(sendbuf.flow)+ sizeof(sendbuf.opdata);
        sendbuf.opdata.encap = opdata;
        ipv4_flow_t flow;
        flow.sport = 0;
        flow.dport = 0;
        flow.daddr = inet_addr("123.0.0.45");
        flow.saddr = inet_addr("123.0.0.44");
        //flow.protocol = IPPROTO_ICMP;
	    flow.protocol =   IPPROTO_TCP;
        uint32_t vni = 888;
        flow.vni[0] = (__u8)(vni >> 16);
        flow.vni[1] = (__u8)(vni >> 8);
        flow.vni[2] = (__u8)vni;

//      sprintf(flow.vni, "%ld", 21);

        sendbuf.flow = flow;

        //printf("Assigned values to sendbuf...\n");

        if(ckmap) {
            // change following line to read from some kinds of file/array
            rc = bpf_map_lookup_and_delete_elem(handle, NULL, (void *)&sendbuf);
        }

        if (rc) {
            /* No more to send */
            //usleep(500);
            //printf("No need to send, sleep a little bit...\n");
            //nanosleep((const struct timespec[]){{0, 500*1000L}}, NULL);
            sleep(1);
        } else {
            printf("DO need to send message.\n");

	    // dummy test
        /*
        sendbuf.opdata.encap.dip = inet_addr("123.0.0.45");
        trn_set_mac(sendbuf.opdata.encap.dmac, dst_mac);
        sendbuf.flow.sport = 0;
        sendbuf.flow.dport = 0;
        sendbuf.flow.daddr = inet_addr("123.0.0.45");
        sendbuf.flow.saddr = inet_addr("123.0.0.44");
	    */
        if (sendto(sockfd, &sendbuf.opcode, sendbuf.len, 0,
                       (struct sockaddr*)&socket_receiver_address/*&socket_address*/, sizeof(socket_receiver_address/*sockaddr_ll*/)) < 0) {
                printf("DPA failed to send oam packet to 0x%08x, err: %s\n",
                              socket_receiver_address.sin_addr.s_addr, strerror(errno));
            }
            printf("Message sent!\n");
        }
    }

    return 0;
}


int main(int argc, char **argv) 
{

#if checkmap
    static const char *default_filename = "cn_dpnd_xdp.o";
    static const char *default_progsec = "cn_dpnd";
    static const char *__desc__ = "DPND XDP loader and update \n"
            " - Allows selecting BPF section --progsec name to XDP-attach to --dev\n";

    struct bpf_map_info map_expect = { 0 };
    struct bpf_map_info info = { 0 };
    struct bpf_object *bpf_obj;
    int oam_map_fd;
    int err;

    struct config cfg = {
        .xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
        .ifindex   = -1,
        .do_unload = false,
    };

	/* Set default BPF-ELF object file and BPF program name */
	strncpy(cfg.filename, default_filename, sizeof(cfg.filename));
	strncpy(cfg.progsec,  default_progsec,  sizeof(cfg.progsec));
	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __desc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n");
		usage(argv[0], __desc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}
	if (cfg.do_unload)
		return xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);

	bpf_obj = load_bpf_and_xdp_attach(&cfg);
	if (!bpf_obj)
		return EXIT_FAIL_BPF;

	if (verbose) {
		printf("Success: Loaded BPF-object(%s) and used section(%s)\n",
		       cfg.filename, cfg.progsec);
		printf(" - XDP prog attached on device:%s(ifindex:%d)\n",
		       cfg.ifname, cfg.ifindex);
	}

    oam_map_fd = find_map_fd(bpf_obj, "local_queue_map");
    if(oam_map_fd < 0) {
        xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
        return EXIT_FAIL_BPF;
    }

	map_expect.key_size    = 0;
	map_expect.value_size  = sizeof(flow_ctx_t);
	map_expect.max_entries = CN_LOCAL_QUEUE_LEN;

	err = __check_map_fd_info(oam_map_fd, &info, &map_expect);
	if (err) {
		fprintf(stderr, "ERR: map via FD not compatible\n");
		return err;
	}

    cn_dp_assistant(oam_map_fd, true);
#else
    cn_dp_assistant(0, false);
#endif
    exit(1);
}
