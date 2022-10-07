// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * @file cn_dpnd.h
 * @author Wei Yue           (@w-yue)
 *
 * @brief Defines XDP/eBPF maps
 *
 * @copyright Copyright (c) 2022 The Authors.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TRAN_DP_FLOW_TIMEOUT 30     // In seconds
#define CN_LOCAL_QUEUE_LEN 1024

//#define GEN_DSTPORT 0xc117 // UDP dport 6081(0x17c1) for Geneve overlay
#define VXL_DSTPORT 0xb512 // UDP dport 4789(0x12b5) for VxLAN overlay

#define __ALWAYS_INLINE__ __attribute__((__always_inline__))

/* helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by elf_bpf loader
 */
#define SEC(NAME) __attribute__((section(NAME), used))

// Associate map with its key/value types for QUEUE/STACK map types
#define BPF_ANNOTATE_KV_PAIR_QUEUESTACK(name, type_val)                    \
  struct ____btf_map_##name {                                              \
    type_val value;                                                        \
  };                                                                       \
  struct ____btf_map_##name __attribute__((section(".maps." #name), used)) \
    ____btf_map_##name = {}

typedef struct {
    __u32 ip;
    __u32 iface_index;
    __u16 ibo_port;
    __u8 protocol;     // value from trn_xdp_tunnel_protocol_t
    __u8 role;         // value from trn_xdp_role_t
    __u8 mac[6];       // MAC of physical interface
} trn_iface_t;

/* Flow Verdict */
enum trn_xdp_flow_op_t {
	XDP_FLOW_OP_ENCAP = 0,
	XDP_FLOW_OP_DELETE,
	XDP_FLOW_OP_DROP,
	XDP_FLOW_OP_MAX
};

typedef struct {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    __u8 vni[3];
} __attribute__((packed, aligned(4))) ipv4_flow_t;

/* Direct Path oam op data */
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

typedef struct {
	__u32 vni;
	__u32 ip;
} __attribute__((packed, aligned(4))) endpoint_key_t;

typedef struct {
	__u32 hip;
	unsigned char mac[6];
	unsigned char hmac[6];
} __attribute__((packed, aligned(4))) endpoint_t;

struct vxlanhdr {
	/* Big endian! */
	__u8 rsvd1 : 3;
	__u8 i_flag : 1;
	__u8 rsvd2 : 4;
	__u8 rsvd3[3];
	__u8 vni[3];
	__u8 rsvd4;
};

struct transit_packet {
	void *data;
	void *data_end;

	/* interface index */
	struct tunnel_iface_t *itf;

	__u32 itf_idx;
	__u32 itf_ipv4;

	__u16 ent_idx;       // entrance index in tunnel_iface_t
	__u8 itf_mac[6];

	/* xdp*/
	struct xdp_md *xdp;

	/* Ether */
	struct ethhdr *eth;

	/* IP */
	struct iphdr *ip;

	/* UDP */
	struct udphdr *udp;

	union {
		struct {
			/* Geneve */
			struct genevehdr *hdr;
			struct trn_gnv_rts_opt *rts_opt;
			struct trn_gnv_scaled_ep_opt *scaled_ep_opt;
			__u32 gnv_hdr_len;
			__u32 gnv_opt_len;
		} geneve;
		struct vxlanhdr *vxlan;
	} overlay;
	
	/* overlay network ID */
	__u32 vni;
	__u32 pad1;

	/* Inner ethernet */
	struct ethhdr *inner_eth;

	/* Inner arp */
	struct arphdr *inner_arp;

	/* Inner IP */
	struct iphdr *inner_ip;

	/* Inner udp */
	struct udphdr *inner_udp;

	/* Inner tcp */
	struct tcphdr *inner_tcp;

	flow_ctx_t fctx;	// keep this at last

	// TODO: Inner UDP or TCP
} __attribute__((packed, aligned(8)));

struct xdp_hints_src {
	__u16 flags;   //
	__u32 vni;
	__u32 saddr;
	unsigned char h_source[6];
} __attribute__((aligned(4))) __attribute__((packed));

static inline void trn_set_mac(void *dst, unsigned char *mac)
{
    unsigned short *d = dst;
    unsigned short *s = (unsigned short *)mac;

    d[0] = s[0];
    d[1] = s[1];
    d[2] = s[2];
}