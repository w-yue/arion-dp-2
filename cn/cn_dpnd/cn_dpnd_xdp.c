// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * @file cn_dpnd_xdp.c
 * @author Wei Yue           (@w-yue)
 *
 * @brief Implements the compute node XDP program (CN DP OAM pick up logic)
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
 *
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <stdbool.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <string.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "cn_dpnd.h"

struct bpf_map_def SEC("maps") local_queue_map = {
	.type = BPF_MAP_TYPE_QUEUE,
	.key_size = 0,
	.value_size = sizeof(flow_ctx_t),
	.max_entries = CN_LOCAL_QUEUE_LEN,
};

#define DEBUG 1
#ifdef DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
* end-up in /sys/kernel/debug/tracing/trace_pipe
*/
#define bpf_debug(fmt, ...) \
({ 							\
	char ____fmt[] = fmt; \
	bpf_trace_printk(____fmt, sizeof(____fmt), \
		##__VA_ARGS__); \
})
#else
#define bpf_debug(fmt, ...) { } while (0)
#endif

int _version SEC("version") = 1;

/* to u64 in host order */
#if 0
static inline __u64 ether_addr_to_u64(const __u8 *addr)
{
        __u64 u = 0;
        int i;

        for (i = ETH_ALEN - 1; i >= 0; i--)
                u = u << 8 | addr[i];
        return u;
}
#endif

__ALWAYS_INLINE__
static __be32 trn_get_vni(const __u8 *vni)
{
	/* Big endian! */
	return (vni[0] << 16) | (vni[1] << 8) | vni[2];
}

static void trn_set_vni(__be32 src, __u8 *vni)
{
	/* Big endian! */
	vni[0] = (__u8)(src >> 16);
	vni[1] = (__u8)(src >> 8);
	vni[2] = (__u8)src;
}

__ALWAYS_INLINE__
static inline void trn_set_src_ip(void *data, void *data_end, __u32 saddr)
{
	int off = offsetof(struct iphdr, saddr);
	__u32 *addr = data + off;
	if ((void *)addr > data_end)
		return;

	*addr = saddr;
}

__ALWAYS_INLINE__
static inline void trn_set_dst_ip(void *data, void *data_end, __u32 daddr)
{
	int off = offsetof(struct iphdr, daddr);
	__u32 *addr = data + off;
	if ((void *)addr > data_end)
		return;

	*addr = daddr;
}

__ALWAYS_INLINE__
static inline __u16 trn_csum_fold_helper(__u64 csum)
{
	int i;
#pragma unroll
	for (i = 0; i < 4; i++) {
		if (csum >> 16)
			csum = (csum & 0xffff) + (csum >> 16);
	}
	return ~csum;
}

__ALWAYS_INLINE__
static inline void trn_ipv4_csum_inline(void *iph, __u64 *csum)
{
	__u16 *next_iph_u16 = (__u16 *)iph;
#pragma clang loop unroll(full)
	for (int i = 0; i<sizeof(struct iphdr)>> 1; i++) {
		*csum += *next_iph_u16++;
	}
	*csum = trn_csum_fold_helper(*csum);
}

__ALWAYS_INLINE__
static inline void trn_set_src_dst_ip_csum(struct iphdr *ip,
					   __u32 saddr, __u32 daddr, void *data_end)
{
	/* Since the packet destination is being rewritten we also
	decrement the TTL */
	ip->ttl--;

	__u64 csum = 0;
	trn_set_src_ip(ip, data_end, saddr);
	trn_set_dst_ip(ip, data_end, daddr);
	csum = 0;
	ip->check = 0;
	trn_ipv4_csum_inline(ip, &csum);
	ip->check = csum;

	bpf_debug("Modified IP Address, src: 0x%x, dst: 0x%x, csum: 0x%x\n",
		  ip->saddr, ip->daddr, ip->check);
}

__ALWAYS_INLINE__
static inline void trn_set_dst_mac(void *data, unsigned char *dst_mac)
{
	trn_set_mac(data, dst_mac);
}

__ALWAYS_INLINE__
static inline void trn_set_src_mac(void *data, unsigned char *src_mac)
{
	trn_set_mac(data + 6, src_mac);
}

static __inline int trn_process_inner_ip(struct transit_packet *pkt)
{
	ipv4_flow_t *flow = &pkt->fctx.flow;
	__u16 len = 0;
	int ret = 0;
	
	pkt->inner_ip = (void *)pkt->inner_eth + sizeof(*pkt->inner_eth);

	if (pkt->inner_ip + 1 > pkt->data_end) {
		bpf_debug("[Dpnd:%d] ABORTED: Bad inner IP frame\n", pkt->itf_idx);
		return XDP_ABORTED;
	}

	memset((void *)&pkt->fctx, 0, sizeof(flow_ctx_t));

	/* Update flow info */
	trn_set_vni(pkt->vni, flow->vni);
	flow->saddr = pkt->inner_ip->daddr;
	flow->daddr = pkt->inner_ip->saddr;
	flow->protocol = pkt->inner_ip->protocol;

	if (flow->protocol == IPPROTO_TCP) {
		pkt->inner_tcp = (void *)pkt->inner_ip + sizeof(*pkt->inner_ip);

		if (pkt->inner_tcp + 1 > pkt->data_end) {
			bpf_debug("[Dpnd:%d] ABORTED: Bad inner TCP frame\n",
				pkt->itf_idx);
			return XDP_ABORTED;
		}

		flow->sport = pkt->inner_tcp->source;
		flow->dport = pkt->inner_tcp->dest;
	} else if (flow->protocol == IPPROTO_UDP) {
		pkt->inner_udp = (void *)pkt->inner_ip + sizeof(*pkt->inner_ip);

		if (pkt->inner_udp + 1 > pkt->data_end) {
			bpf_debug("[Dpnd:%d] ABORTED: Bad inner UDP oframe\n",
				  pkt->itf_idx);
			return XDP_ABORTED;
		}

		flow->sport = pkt->inner_udp->source;
		flow->dport = pkt->inner_udp->dest;
	}

	flow->sport = 0;
	flow->dport = 0;
	if (flow->protocol != IPPROTO_ICMP) {
		struct xdp_hints_src *h_src;
		__u8 offset = sizeof(*h_src);

		__u16 ip_tot_len = bpf_ntohs(pkt->ip->tot_len);

		if (ip_tot_len < 2) {
			return XDP_DROP;
		}

		ip_tot_len &= 0xFFF; // Max 4095
		if ((void *)pkt->data + ip_tot_len + offset + sizeof(struct ethhdr) > pkt->data_end) {
			bpf_debug("[Dpnd::%d] XXXXX TX: not enough extra space %d.\n",
					__LINE__, ip_tot_len);
			return XDP_PASS;  // No extra fields, not relavant to us
		}

		h_src = (void *)pkt->data + ip_tot_len + sizeof(struct ethhdr);
	    // signature check
		if (h_src->flags != 0x5354 || h_src->vni != pkt->vni) {
			bpf_debug("[Dpnd::%d] XXXXX TX: extra fields not recognized flags: %d -- vni: %d.\n",
					__LINE__, h_src->flags, h_src->vni);
			// not something we recognize
			return XDP_PASS;
		}

		/* Generate Direct Path request */
		pkt->fctx.opcode = bpf_htonl(XDP_FLOW_OP_ENCAP);
		pkt->fctx.opdata.encap.dip = pkt->inner_ip->saddr;
		
		pkt->fctx.opdata.encap.dhip = h_src->saddr;
		
		trn_set_mac(pkt->fctx.opdata.encap.dmac, pkt->inner_eth->h_source);
		trn_set_mac(pkt->fctx.opdata.encap.dhmac, h_src->h_source);

		pkt->fctx.opdata.encap.timeout = bpf_htons(TRAN_DP_FLOW_TIMEOUT);
		len = sizeof(struct udphdr) + sizeof(pkt->fctx.opcode) +
		sizeof(pkt->fctx.flow) + sizeof(dp_encap_opdata_t);
		pkt->fctx.udp.len = bpf_htons(len);

		pkt->fctx.ip.version = IPVERSION;
		pkt->fctx.ip.ihl = sizeof(struct iphdr) >> 2;
		len += sizeof(struct iphdr);
		pkt->fctx.ip.tot_len = bpf_htons(len);
		pkt->fctx.ip.id = bpf_htons(54321);  // ???
		pkt->fctx.ip.ttl = IPDEFTTL;
		pkt->fctx.ip.protocol = IPPROTO_UDP;

		trn_set_src_dst_ip_csum(&pkt->fctx.ip, pkt->ip->daddr, pkt->ip->saddr,
			(void *)&pkt->fctx.opcode);

		trn_set_dst_mac(&pkt->fctx.eth, pkt->eth->h_source);
		trn_set_src_mac(&pkt->fctx.eth, pkt->eth->h_dest);
		pkt->fctx.eth.h_proto = bpf_htons(ETH_P_IP);
		pkt->fctx.len = sizeof(struct ethhdr) + len;

		bpf_debug("[Dpnd] XXXX : push map dip:0x%x dhip:0x%x,  dhmac:0x%x, \n",
					bpf_ntohl(pkt->fctx.opdata.encap.dip),
					bpf_ntohl(h_src->saddr),
					bpf_ntohl(*(__u32 *)pkt->fctx.opdata.encap.dhmac));
	
		ret = bpf_map_push_elem(&local_queue_map, &pkt->fctx, BPF_EXIST);
		if (ret < 0) {
			bpf_debug("[DPND] XXXX : bpf_map_push_elem failed %d\n", ret);
		}

	}

	bpf_debug("[Dpnd] XXXX To ip:0x%x host:0x%x mac:%x ..\n",
		bpf_ntohl(pkt->inner_ip->daddr), bpf_ntohl(pkt->ip->daddr),
		bpf_ntohl(*(__u32 *)pkt->eth));

	return XDP_PASS;
}

static __inline int trn_process_inner_eth(struct transit_packet *pkt)
{
	if (pkt->inner_eth + 1 > pkt->data_end) {
		bpf_debug("[Dpnd:%d] ABORTED: Bad inner Ethernet frame\n",
			pkt->itf_idx);
		return XDP_ABORTED;
	}

	if (pkt->inner_eth->h_proto != bpf_htons(ETH_P_IP)) {
		bpf_debug(
			"[Dpnd:%d] XXX PASS: non-IP/ARP inner packet, protocol %d\n",
			pkt->itf_idx, bpf_ntohs(pkt->eth->h_proto));
		return XDP_PASS;
	}

	bpf_debug("[Dpnd:%d] XXXX Processing inner IP at %d, protocol %d \n", 
			__LINE__, pkt->itf_idx, bpf_ntohs(pkt->eth->h_proto));
	return trn_process_inner_ip(pkt);
}

static __inline int trn_process_vxlan(struct transit_packet *pkt)
{
	pkt->overlay.vxlan = (void *)pkt->udp + sizeof(*pkt->udp);
	if (pkt->overlay.vxlan + 1 > pkt->data_end) {
		bpf_debug("[Dpnd:%d] ABORTED: Bad VxLan frame\n", pkt->itf_idx);
		return XDP_ABORTED;
	}

	pkt->vni = trn_get_vni(pkt->overlay.vxlan->vni);

	pkt->inner_eth = (void *)(pkt->overlay.vxlan + 1);

	//bpf_debug("[Dpnd:%d] XXXX received packet at %d(vni = %d)\n",
	//		  __LINE__, pkt->itf_idx, pkt->vni);
	return trn_process_inner_eth(pkt);
}

static __inline int trn_process_udp(struct transit_packet *pkt)
{
	/* Get the UDP header */
	pkt->udp = (void *)pkt->ip + sizeof(*pkt->ip);

	if (pkt->udp + 1 > pkt->data_end) {
		bpf_debug("[Dpnd:%d] ABORTED: Bad UDP frame\n", pkt->itf_idx);
		return XDP_ABORTED;
	}
	
	if (pkt->udp->dest == VXL_DSTPORT) {
		return trn_process_vxlan(pkt);
	}

	bpf_debug("[Dpnd:%d] XX PASS non-overlay UDP packet, trn_iface_t %d\n", 
			__LINE__, bpf_ntohs(pkt->udp->dest));
	return XDP_PASS;
}

static __inline int trn_process_ip(struct transit_packet *pkt)
{
	/* Get the IP header */
	pkt->ip = (void *)pkt->eth + sizeof(*pkt->eth);

	if (pkt->ip + 1 > pkt->data_end) {
		bpf_debug("[Dpnd:%d] ABORTED: Bad IP frame\n", pkt->itf_idx);
		return XDP_ABORTED;
	}

	if (!pkt->ip->ttl) {
		bpf_debug("[Dpnd:%d] DROP: IP ttl\n", pkt->itf_idx);
		return XDP_DROP;
	}

	/* Allow host stack processing */
	if (pkt->ip->protocol != IPPROTO_UDP) {
		bpf_debug("[Dpnd:%d] PASS: non-UDP frame, proto: %d\n",
			pkt->itf_idx, pkt->ip->protocol);
		return XDP_PASS;
	}

	return trn_process_udp(pkt);
}

static __inline int trn_process_eth(struct transit_packet *pkt)
{
	pkt->eth = pkt->data;

	if (pkt->eth + 1 > pkt->data_end) {
		bpf_debug("[Dpnd:%d] ABORTED: Bad Ethernet frame\n", pkt->itf_idx);
		return XDP_ABORTED;
	}

	/* Allow host stack processing non-IPv4 */
	if (pkt->eth->h_proto != bpf_htons(ETH_P_IP)) {
		bpf_debug("[Dpnd:%d] PASS: Non-IP Ethernet frame:0x%x\n",
			pkt->itf_idx, bpf_ntohs(pkt->eth->h_proto));
		return XDP_PASS;
	}

	//bpf_debug("[Dpnd:%d] XXX received packet at %d\n",
	//		  __LINE__, pkt->itf_idx);

	return trn_process_ip(pkt);
}

SEC("cn_dpnd")
int _transit(struct xdp_md *ctx)
{

	struct transit_packet pkt;
	pkt.data = (void *)(long)ctx->data;
	pkt.data_end = (void *)(long)ctx->data_end;
	pkt.xdp = ctx;
	pkt.itf_idx = ctx->ingress_ifindex;  //???

	struct ethhdr *eth = pkt.data;
	__u64 offset = sizeof(*eth);

	if ((void *)eth + offset > pkt.data_end)
		return 0;

	return trn_process_eth(&pkt);
}

char _license[] SEC("license") = "GPL";
