// SPDX-License-Identifier: GPL-2.0-or-later
// The base of the following code is derived from Zeta project
/**
 * @file trn_transit_xdp.c
 * @author Sherif Abdelwahab (@zasherif)
 *         Phu Tran          (@phudtran)
 *         Wei Yue           (@w-yue)
 *
 * @brief Implements the Transit XDP program (switching and routing logic)
 *
 * @copyright Copyright (c) 2019-2022 The Authors.
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
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <stddef.h>
#include <string.h>

#include "extern/bpf_endian.h"
#include "extern/bpf_helpers.h"

#include "trn_datamodel.h"
#include "trn_transit_xdp_maps.h"
#include "trn_kern.h"

int _version SEC("version") = 1;

int pkt_not_add_tail = 1;
int pkt_not_add_head = 1;

const int EP_NOT_FOUND = 5; // use this const as a new xdp_action, which indicates this packet shall be forwarded to the user space via AF_XDP.

static __inline int trn_rewrite_remote_mac(struct transit_packet *pkt)
{
	/* The TTL must have been decremented before this step, Drop the
	packet if TTL is zero */
	if (!pkt->ip->ttl)
		return XDP_DROP;

	endpoint_t *remote_ep;
	endpoint_key_t epkey;
	epkey.vni = 0;
	epkey.ip = pkt->ip->daddr;
	/* Get the remote_mac address based on the value of the outer dest IP */
	remote_ep = bpf_map_lookup_elem(&endpoints_map, &epkey);

	if (!remote_ep) {
		bpf_debug("[Transit:%d:] DROP: "
			  "Failed to find remote MAC address\n",
			  __LINE__);
		return XDP_DROP;
	}

	trn_set_src_mac(pkt->data, pkt->eth->h_dest);
	trn_set_dst_mac(pkt->data, remote_ep->mac);
	return XDP_TX;
}

#if turnOn
static __inline void trn_update_ep_host_cache(struct transit_packet *pkt,
					      __be64 tunnel_id,
					      __u32 inner_src_ip)
{
	/* If RTS option is present, it always refer to the source endpoint's host.
	 * If the source endpoint is not known to this host, cache the host ip/mac in the
	 * en_host_cache.
	*/

	endpoint_t *src_ep;
	endpoint_key_t src_epkey;

	if (pkt->overlay.geneve.rts_opt->type == TRN_GNV_RTS_OPT_TYPE) {
		src_epkey.vni = tunnel_id;
		src_epkey.ip = inner_src_ip;
		src_ep = bpf_map_lookup_elem(&endpoints_map, &src_epkey);

		if (!src_ep) {
			/* Add the RTS info to the ep_host_cache */
			bpf_map_update_elem(&ep_host_cache, &src_epkey,
					    &pkt->overlay.geneve.rts_opt->rts_data.host, 0);
		}
	}
}
#endif

static __inline int trn_decapsulate_and_redirect(struct transit_packet *pkt,
						 int ifindex)
{
	int outer_header_size = sizeof(*pkt->overlay.geneve.hdr) + pkt->overlay.geneve.gnv_hdr_len +
				sizeof(*pkt->udp) + sizeof(*pkt->ip) +
				sizeof(*pkt->eth);

	if (bpf_xdp_adjust_head(pkt->xdp, 0 + outer_header_size)) {
		bpf_debug(
			"[Transit:%d:0x%x] DROP: failed to adjust packet head.\n",
			__LINE__, bpf_ntohl(pkt->itf_ipv4));
		return XDP_DROP;
	}

	bpf_debug("[Transit:%d:0x%x] REDIRECT: itf=[%d].\n", __LINE__,
		  bpf_ntohl(pkt->itf_ipv4), ifindex);

	return bpf_redirect_map(&interfaces_map, ifindex, 0);
}

#if sgSupport
static __inline int trn_sg_check(struct transit_packet *pkt) {

	sg_cidr_key_t sgkey;
	struct security_group_t *sg_entry = NULL;

	sgkey.vni = pkt->vni;
	sgkey.src_ip = pkt->inner_ip->saddr;
	sgkey.dst_ip = pkt->inner_ip->daddr;
	sgkey.protocol = pkt->inner_ip->protocol;
	sgkey.prefixlen = SG_IPV4_PREFIX; // ??

	// check egress
	sgkey.direction = 0;
	sgkey.port = 30011;

	bpf_debug("[Transit:%d] XXXXX port=%d, prefixlen=%d",
			sgkey.vni, sgkey.port, sgkey.prefixlen);
	bpf_debug("  XXXXX proto=%d, src_ip:0x%x, dst_ip:0x%x ",
			sgkey.protocol,
			bpf_ntohl(sgkey.src_ip),
			bpf_ntohl(sgkey.dst_ip));
	sg_entry = bpf_map_lookup_elem(&sg_cidr_map, &sgkey);
	if (sg_entry == NULL) {
		bpf_debug("[Transit:%d XXXXX] Drop: no matching sg entry found: %d - %d\n",
			pkt->itf_idx, sgkey.port, sgkey.vni);
		return XDP_DROP;
	}

   // check ingress;
	sgkey.direction = 1;
	sgkey.src_ip = sgkey.dst_ip;
	sgkey.dst_ip = pkt->inner_ip->saddr;

	if (sgkey.protocol == IPPROTO_TCP) {
		pkt->inner_tcp = (void *)pkt->inner_ip + sizeof(*pkt->inner_ip);

		if (pkt->inner_tcp + 1 > pkt->data_end) {
			bpf_debug("[Transit:%d] ABORTED: Bad inner TCP frame\n",
				pkt->itf_idx);
			return XDP_ABORTED;
		}
		sgkey.port = pkt->inner_tcp->dest; // check dst first
	} else if (sgkey.protocol == IPPROTO_UDP) {
		pkt->inner_udp = (void *)pkt->inner_ip + sizeof(*pkt->inner_ip);

		if (pkt->inner_udp + 1 > pkt->data_end) {
			bpf_debug("[Transit:%d] ABORTED: Bad inner UDP oframe\n",
				  pkt->itf_idx);
			return XDP_ABORTED;
		}
		sgkey.port = pkt->inner_udp->dest;
	} else {
		bpf_debug("[Transit:%d] PASS: Non supported frame, proto: %d\n",
			pkt->itf_idx, sgkey.protocol);
		return XDP_PASS;
	}

	bpf_debug("[Transit:%d] XXXXX port=%d, prefixlen=%d",
			sgkey.vni, sgkey.port, sgkey.prefixlen);
	bpf_debug("  XXXXX proto=%d, src_ip:0x%x, dst_ip:0x%x ",
			sgkey.protocol,
			bpf_ntohl(sgkey.src_ip),
			bpf_ntohl(sgkey.dst_ip));
	sg_entry = bpf_map_lookup_elem(&sg_cidr_map, &sgkey);
	if (sg_entry == NULL) {
		// other follow up logic should be added here
		bpf_debug("[Transit:%d XXXXX] Drop: no matching sg entry found: %d - %d\n",
			pkt->itf_idx, sgkey.port, sgkey.vni);
		return XDP_DROP;
	}

	bpf_debug("[Transit:%d XXXXX] Pass: matching sg entry found: %d - 0x%x\n",
		sgkey.vni, sgkey.port, bpf_ntohl(pkt->inner_ip->daddr));
	return XDP_PASS;
}
#endif

static __inline int trn_process_inner_ip(struct transit_packet *pkt)
{
	endpoint_t *ep;
	endpoint_key_t epkey;
	int action = XDP_PASS;
	ipv4_flow_t *flow = &pkt->fctx.flow;
	__u64 csum = 0;
	__u16 len = 0;
	__be32 tip = 0;

	pkt->inner_ip = (void *)pkt->inner_eth + sizeof(*pkt->inner_eth);

	if (pkt->inner_ip + 1 > pkt->data_end) {
		bpf_debug("[Transit:%d] ABORTED: Bad inner IP frame\n", pkt->itf_idx);
		return XDP_ABORTED;
	}

#if sgSupport
	action = trn_sg_check(pkt);
	if (action != XDP_PASS) {
		bpf_debug("[Transit:%d XXXX] No SG entry found, drop it: \n", pkt->itf_idx);
		return action;
	}
#endif

	/* Look up target endpoint */
	epkey.vni = pkt->vni;
	epkey.ip = pkt->inner_ip->daddr;
	ep = bpf_map_lookup_elem(&endpoints_map, &epkey);
	if (!ep) {
		bpf_debug("[Transit:%d] DROP: inner IP forwarding failed to find endpoint "
			"vni:0x%x ip:0x%x\n", pkt->itf_idx, epkey.vni, bpf_ntohl(epkey.ip));
		return EP_NOT_FOUND;
	}

	bpf_debug("[Transit]: XXXX found endpoint: vni:0x%x ip:0x%x, hip: 0x%x\n", 
			epkey.vni, bpf_ntohl(epkey.ip), bpf_ntohl(ep->hip));

	memset((void *)&pkt->fctx, 0, sizeof(flow_ctx_t));

	/* Update flow info */
	trn_set_vni(pkt->vni, flow->vni);
	flow->saddr = pkt->inner_ip->saddr;
	flow->daddr = pkt->inner_ip->daddr;
	flow->protocol = pkt->inner_ip->protocol;

	if (flow->protocol == IPPROTO_TCP) {
		pkt->inner_tcp = (void *)pkt->inner_ip + sizeof(*pkt->inner_ip);

		if (pkt->inner_tcp + 1 > pkt->data_end) {
			bpf_debug("[Transit:%d] ABORTED: Bad inner TCP frame\n",
				pkt->itf_idx);
			return XDP_ABORTED;
		}

		flow->sport = pkt->inner_tcp->source;
		flow->dport = pkt->inner_tcp->dest;
	} else if (flow->protocol == IPPROTO_UDP) {
		pkt->inner_udp = (void *)pkt->inner_ip + sizeof(*pkt->inner_ip);

		if (pkt->inner_udp + 1 > pkt->data_end) {
			bpf_debug("[Transit:%d] ABORTED: Bad inner UDP oframe\n",
				  pkt->itf_idx);
			return XDP_ABORTED;
		}

		flow->sport = pkt->inner_udp->source;
		flow->dport = pkt->inner_udp->dest;
	}

/* get rid of this direct path logic for now.  --wyue 4/1/2022 */
#if turnOn
	/* Generate Direct Path request */
	pkt->fctx.opcode = bpf_htonl(XDP_FLOW_OP_ENCAP);
	pkt->fctx.opdata.encap.dip = epkey.ip;
	pkt->fctx.opdata.encap.dhip = ep->hip;
	trn_set_mac(pkt->fctx.opdata.encap.dmac, ep->mac);
	trn_set_mac(pkt->fctx.opdata.encap.dhmac, ep->hmac);
	pkt->fctx.opdata.encap.timeout = bpf_htons(TRAN_DP_FLOW_TIMEOUT);

	pkt->fctx.udp.dest = pkt->itf->ibo_port;
	len = sizeof(struct udphdr) + sizeof(pkt->fctx.opcode) +
		sizeof(pkt->fctx.flow) + sizeof(dp_encap_opdata_t);
	pkt->fctx.udp.len = bpf_htons(len);

	pkt->fctx.ip.version = IPVERSION;
	pkt->fctx.ip.ihl = sizeof(struct iphdr) >> 2;
	len += sizeof(struct iphdr);
	pkt->fctx.ip.tot_len = bpf_htons(len);
	pkt->fctx.ip.id = bpf_htons(54321);
	pkt->fctx.ip.ttl = IPDEFTTL;
	pkt->fctx.ip.protocol = IPPROTO_UDP;
	trn_set_src_dst_ip_csum(&pkt->fctx.ip, pkt->ip->daddr, pkt->ip->saddr,
		(void *)&pkt->fctx.opcode);

	trn_set_dst_mac(&pkt->fctx.eth, pkt->eth->h_source);
	trn_set_src_mac(&pkt->fctx.eth, pkt->eth->h_dest);
	pkt->fctx.eth.h_proto = bpf_htons(ETH_P_IP);
	pkt->fctx.len = sizeof(struct ethhdr) + len;

	bpf_map_push_elem(&oam_queue_map, &pkt->fctx, BPF_EXIST);
#endif
	/* Modify inner EtherHdr */
	trn_set_dst_mac(pkt->inner_eth, ep->mac);

	/* Keep overlay header, update outer header destinations */
	if (appendTail && flow->protocol != IPPROTO_ICMP && !pkt_not_add_tail) {
        //trn_mod_vni(pkt->overlay.vxlan);
		tip = pkt->ip->saddr;
    }
	trn_set_src_dst_ip_csum(pkt->ip, pkt->ip->daddr, ep->hip, pkt->data_end);
	trn_set_src_mac(pkt->eth, pkt->eth->h_dest);
	trn_set_dst_mac(pkt->eth, ep->hmac);

	if (appendTail && flow->protocol != IPPROTO_ICMP && !pkt_not_add_tail) {
		struct xdp_hints_src *h_src;
		__u8 offset = sizeof(*h_src);

		__u16 ip_tot_len = bpf_ntohs(pkt->ip->tot_len);

		if (ip_tot_len < 2) {
			return XDP_DROP;
		}

#if 0
		pkt_not_add_tail = bpf_xdp_adjust_tail(pkt->xdp, sizeof(struct xdp_hints_src));
		if (pkt_not_add_tail) {
			bpf_debug("[Transit:%d] XXXX TX: bpf_xdp_adjust_tail failed", __LINE__);
			return XDP_DROP;
		}
#endif

		ip_tot_len &= 0xFFF; // Max 4095
		if ((void *)pkt->data + ip_tot_len + sizeof(struct xdp_hints_src) + sizeof(struct ethhdr) > pkt->data_end) {
			return XDP_ABORTED;
		}

		h_src = (void *)pkt->data + ip_tot_len + sizeof(struct ethhdr);
		h_src->vni = pkt->vni;
		h_src->saddr = tip;
		h_src->flags = 0x5354;

		h_src->h_source[0] = pkt->eth->h_source[0];
		h_src->h_source[1] = pkt->eth->h_source[1];
		h_src->h_source[2] = pkt->eth->h_source[2];
		h_src->h_source[3] = pkt->eth->h_source[3];
		h_src->h_source[4] = pkt->eth->h_source[4];
		h_src->h_source[5] = pkt->eth->h_source[5];
		
		bpf_debug("   XXXX appendInfo   vni: %d saddr:0x%x h_source:%x ..\n",
				h_src->vni,
				bpf_ntohl(h_src->saddr), 
				bpf_ntohl(*(__u32 *)h_src->h_source));
	}

	bpf_debug("[Transit:%d] XXXX TX: Forward IP pkt from vni:%d ip:0x%x\n",
		pkt->itf_idx, pkt->vni, bpf_ntohl(pkt->inner_ip->saddr));
	bpf_debug("   XXXX             To ip:0x%x host:0x%x mac:%x ..\n",
		bpf_ntohl(pkt->inner_ip->daddr), bpf_ntohl(pkt->ip->daddr),
		bpf_ntohl(*(__u32 *)pkt->eth));

	return XDP_TX;
}

static __inline int trn_process_inner_arp(struct transit_packet *pkt)
{
	unsigned char *sha;
	unsigned char *tha = NULL;
	endpoint_t *ep;
	endpoint_key_t epkey;
	__u32 *sip, *tip;
	__u64 csum = 0;

	pkt->inner_arp = (void *)pkt->inner_eth + sizeof(*pkt->inner_eth);

	if (pkt->inner_arp + 1 > pkt->data_end) {
		bpf_debug("[Transit:%d] ABORTED: Bad inner ARP frame\n", pkt->itf_idx);
		return XDP_ABORTED;
	}

	if (pkt->inner_arp->ar_pro != bpf_htons(ETH_P_IP) ||
	    pkt->inner_arp->ar_hrd != bpf_htons(ARPHRD_ETHER)) {
		bpf_debug("[Transit:%d] DROP: inner ARP unsupported protocol"
			  " or Hardware type!\n", pkt->itf_idx);
		return XDP_DROP;
	}

	if (pkt->inner_arp->ar_op != bpf_htons(ARPOP_REQUEST)) {
		bpf_debug("[Transit:%d] DROP: not inner ARP REQUEST\n",
			pkt->itf_idx);
		return XDP_DROP;
	}

	sha = (unsigned char *)(pkt->inner_arp + 1);

	if (sha + ETH_ALEN > pkt->data_end) {
		bpf_debug("[Transit:%d] ABORTED: Bad inner ARP frame, sender ha overrun\n",
			  pkt->itf_idx);
		return XDP_ABORTED;
	}

	sip = (__u32 *)(sha + ETH_ALEN);

	if (sip + 1 > pkt->data_end) {
		bpf_debug("[Transit:%d] ABORTED: Bad inner ARP frame, sender ip overrun\n",
			  pkt->itf_idx);
		return XDP_ABORTED;
	}

	tha = (unsigned char *)sip + sizeof(__u32);

	if (tha + ETH_ALEN > pkt->data_end) {
		bpf_debug("[Transit:%d] ABORTED: Bad inner ARP frame, target ha overrun\n",
			  pkt->itf_idx);
		return XDP_ABORTED;
	}

	tip = (__u32 *)(tha + ETH_ALEN);

	if (tip + 1 > pkt->data_end) {
		bpf_debug("[Transit:%d] ABORTED: Bad inner ARP frame, target ip overrun\n",
			  pkt->itf_idx);
		return XDP_ABORTED;
	}

	/* Valid inner ARP request, look up target endpoint */
	epkey.vni = pkt->vni;
	epkey.ip = *tip;
	ep = bpf_map_lookup_elem(&endpoints_map, &epkey);
	if (!ep) {
		bpf_debug("[Transit:%d] DROP: inner ARP Request failed to find endpoint "
			"vni:0x%x ip:0x%x\n", pkt->itf_idx, epkey.vni, bpf_ntohl(epkey.ip));
		return EP_NOT_FOUND;
	}

	/* Modify pkt for inner ARP response */
	pkt->inner_arp->ar_op = bpf_htons(ARPOP_REPLY);
	trn_set_mac(tha, sha);
	trn_set_mac(sha, ep->mac);

	__u32 tmp_ip = *sip;
	*sip = *tip;
	*tip = tmp_ip;

	/* Modify inner EitherHdr, pretend it's from target */
	trn_set_dst_mac(pkt->inner_eth, pkt->inner_eth->h_source);
	trn_set_src_mac(pkt->inner_eth, ep->mac);

	/* Keep overlay header, swap outer IP header */
	trn_set_src_dst_ip_csum(pkt->ip, pkt->ip->daddr, pkt->ip->saddr, pkt->data_end);
	trn_swap_src_dst_mac(pkt->data);

	bpf_debug("[Transit:%d] TX: ARP respond for vni:%d ip:0x%x\n",
		pkt->itf_idx, pkt->vni, bpf_ntohl(*sip));
	bpf_debug("[Transit:%d] TX:     To ip:0x%x host:0x%x\n",
		pkt->itf_idx, bpf_ntohl(*tip), bpf_ntohl(pkt->ip->daddr));

	return XDP_TX;
}

static __inline int trn_process_inner_eth(struct transit_packet *pkt)
{
	if (pkt->inner_eth + 1 > pkt->data_end) {
		bpf_debug("[Transit:%d] ABORTED: Bad inner Ethernet frame\n",
			pkt->itf_idx);
		return XDP_ABORTED;
	}

	/* Respond to tenant ARP request if needed */
	if (pkt->itf->role == XDP_FWD &&
		pkt->inner_eth->h_proto == bpf_htons(ETH_P_ARP)) {
		bpf_debug("[Transit:%d] Processing inner ARP\n", pkt->itf_idx);
		return trn_process_inner_arp(pkt);
	}

	if (pkt->inner_eth->h_proto != bpf_htons(ETH_P_IP)) {
		bpf_debug(
			"[Transit:%d] DROP: non-IP/ARP inner packet, protocol %d\n",
			pkt->itf_idx, bpf_ntohs(pkt->eth->h_proto));
		return XDP_DROP;
	}

	bpf_debug("[Transit:%d] Processing inner IP \n", pkt->itf_idx);
	return trn_process_inner_ip(pkt);
}

static __inline int trn_process_geneve(struct transit_packet *pkt)
{
	pkt->overlay.geneve.hdr = (void *)pkt->udp + sizeof(*pkt->udp);
	if (pkt->overlay.geneve.hdr + 1 > pkt->data_end) {
		bpf_debug("[Transit:%d] ABORTED: Bad Geneve frame\n", pkt->itf_idx);
		return XDP_ABORTED;
	}

	if (pkt->overlay.geneve.hdr->proto_type != bpf_htons(ETH_P_TEB)) {
		bpf_debug(
			"[Transit:%d] ABORTED: unrecognized Geneve proto_type: [0x%x]\n",
			pkt->itf_idx, bpf_ntohl(pkt->overlay.geneve.hdr->proto_type));
		return XDP_ABORTED;
	}

	pkt->overlay.geneve.gnv_opt_len = pkt->overlay.geneve.hdr->opt_len * 4;
	pkt->overlay.geneve.rts_opt = (void *)&pkt->overlay.geneve.hdr->options[0];

	if (pkt->overlay.geneve.rts_opt + 1 > pkt->data_end) {
		bpf_debug("[Transit:%d] ABORTED: Bad Geneve rts_opt offset\n", pkt->itf_idx);
		return XDP_ABORTED;
	}

	if (pkt->overlay.geneve.rts_opt->opt_class != TRN_GNV_OPT_CLASS) {
		bpf_debug(
			"[Transit:%d] ABORTED: Unsupported Geneve rts_opt option class 0x%x\n",
			pkt->itf_idx, bpf_ntohs(pkt->overlay.geneve.rts_opt->opt_class));
		return XDP_ABORTED;
	}
	pkt->overlay.geneve.gnv_hdr_len = sizeof(*pkt->overlay.geneve.rts_opt);

	// TODO: process options
	pkt->overlay.geneve.scaled_ep_opt = (void *)pkt->overlay.geneve.rts_opt + sizeof(*pkt->overlay.geneve.rts_opt);

	if (pkt->overlay.geneve.scaled_ep_opt + 1 > pkt->data_end) {
		bpf_debug("[Transit:%d] ABORTED: Bad Geneve sep_opt offset\n", pkt->itf_idx);
		return XDP_ABORTED;
	}

	if (pkt->overlay.geneve.scaled_ep_opt->opt_class != TRN_GNV_OPT_CLASS) {
		bpf_debug(
			"[Transit:%d] ABORTED: Unsupported Geneve sep_opt option class 0x%x\n",
			pkt->itf_idx, bpf_ntohs(pkt->overlay.geneve.scaled_ep_opt->opt_class));
		return XDP_ABORTED;
	}
	pkt->overlay.geneve.gnv_hdr_len += sizeof(*pkt->overlay.geneve.scaled_ep_opt);

	if (pkt->overlay.geneve.gnv_hdr_len != pkt->overlay.geneve.gnv_opt_len) {
		bpf_debug("[Transit:%d] ABORTED: Bad Geneve option size\n", pkt->itf_idx);
		return XDP_ABORTED;
	}
	pkt->overlay.geneve.gnv_hdr_len += sizeof(*pkt->overlay.geneve.hdr);

	pkt->vni = trn_get_vni(pkt->overlay.geneve.hdr->vni);

	pkt->inner_eth = (void *)pkt->overlay.geneve.hdr + pkt->overlay.geneve.gnv_hdr_len;

	bpf_debug("[Transit:%d] XXX received packet at %d(vni = %d)\n",
			  __LINE__, pkt->itf_idx, pkt->vni);

	return trn_process_inner_eth(pkt);
}

static __inline int trn_process_vxlan(struct transit_packet *pkt)
{
	pkt->overlay.vxlan = (void *)pkt->udp + sizeof(*pkt->udp);
	if (pkt->overlay.vxlan + 1 > pkt->data_end) {
		bpf_debug("[Transit:%d] ABORTED: Bad VxLan frame\n", pkt->itf_idx);
		return XDP_ABORTED;
	}

	pkt->vni = trn_get_vni(pkt->overlay.vxlan->vni);

	pkt->inner_eth = (void *)(pkt->overlay.vxlan + 1);

	bpf_debug("[Transit:%d] XXX received packet at %d(vni = %d)\n",
			  __LINE__, pkt->itf_idx, pkt->vni);

	return trn_process_inner_eth(pkt);
}

static __inline int trn_process_udp(struct transit_packet *pkt)
{
	/* Get the UDP header */
	pkt->udp = (void *)pkt->ip + sizeof(*pkt->ip);

	if (pkt->udp + 1 > pkt->data_end) {
		bpf_debug("[Transit:%d] ABORTED: Bad UDP frame\n", pkt->itf_idx);
		return XDP_ABORTED;
	}

	if (pkt->udp->dest == GEN_DSTPORT && pkt->itf->role == XDP_FTN) {
		return trn_process_geneve(pkt);
	} else if (pkt->udp->dest == VXL_DSTPORT && pkt->itf->role == XDP_FWD) {
		return trn_process_vxlan(pkt);
	}

	bpf_debug("[Transit:%d] PASS non-overlay UDP packet, port %d\n",
		pkt->itf_idx, bpf_ntohs(pkt->udp->dest));
	return XDP_PASS;
}

static __inline int trn_process_ip(struct transit_packet *pkt)
{
	/* Get the IP header */
	pkt->ip = (void *)pkt->eth + sizeof(*pkt->eth);

	if (pkt->ip + 1 > pkt->data_end) {
		bpf_debug("[Transit:%d] ABORTED: Bad IP frame\n", pkt->itf_idx);
		return XDP_ABORTED;
	}

	if (pkt->ip->daddr != pkt->itf->entrances[pkt->ent_idx].ip) {
		bpf_debug("[Transit:%d] ABORTED: IP frame mismatch 0x%x-0x%x\n",
			pkt->itf_idx, pkt->ip->daddr, pkt->itf->entrances[pkt->ent_idx].ip);
		return XDP_ABORTED;
	}

	if (!pkt->ip->ttl) {
		bpf_debug("[Transit:%d] DROP: IP ttl\n", pkt->itf_idx);
		return XDP_DROP;
	}

	/* Allow host stack processing */
	if (pkt->ip->protocol != IPPROTO_UDP) {
		bpf_debug("[Transit:%d] PASS: non-UDP frame, proto: %d\n",
			pkt->itf_idx, pkt->ip->protocol);
		return XDP_PASS;
	}

	pkt->itf_ipv4 = pkt->ip->daddr;

	return trn_process_udp(pkt);
}

static __inline int trn_process_eth(struct transit_packet *pkt)
{
	__u16 i;
	pkt->eth = pkt->data;

	if (pkt->eth + 1 > pkt->data_end) {
		bpf_debug("[Transit:%d] ABORTED: Bad Ethernet frame\n", pkt->itf_idx);
		return XDP_ABORTED;
	}

	/* Allow host stack processing non-IPv4 */
	if (pkt->eth->h_proto != bpf_htons(ETH_P_IP)) {
		bpf_debug("[Transit:%d] PASS: Non-IP Ethernet frame:0x%x\n",
			pkt->itf_idx, bpf_ntohs(pkt->eth->h_proto));
		return XDP_PASS;
	}

	bpf_debug("[Transit:%d] XXX received packet at %d(%d)\n",
			  __LINE__, pkt->itf_idx, pkt->itf->num_entrances);

	// there's some logic error in assigning entrances for each itf
	for (i = 0; i < pkt->itf->num_entrances && i < TRAN_MAX_ZGC_ENTRANCES; i++) {
		if (trn_is_mac_equal(pkt->eth->h_dest, pkt->itf->entrances[i].mac)) {

			bpf_debug("[Transit:%d] XXX received packet at mac:%x..%x\n",
					i, pkt->eth->h_dest[0], pkt->eth->h_dest[5]);

			pkt->ent_idx = i;/* Packet is destinated to us */
			trn_set_mac(pkt->itf_mac, pkt->eth->h_dest);
			return trn_process_ip(pkt);
		} 
	}

	bpf_debug("[Transit:%d] ABORTED: Ethernet frame not for us, mac:%x..%x\n",
		pkt->itf_idx, pkt->eth->h_dest[0], pkt->eth->h_dest[5]);
	return XDP_ABORTED;
}

SEC("transit")
int _transit(struct xdp_md *ctx)
{
	if (appendTail) {
		//__u8 apendlen = sizeof(struct xdp_hints_src);
		//bpf_debug("[Transit::%d] XXXX Tx: addr: %x, len=%d\n", 
		//		__LINE__, ctx->data, ctx->data_end - ctx->data);
		pkt_not_add_tail = bpf_xdp_adjust_tail(ctx, sizeof(struct xdp_hints_src));
		if (pkt_not_add_tail) {
			bpf_debug("[Transit:%d] XXXX TX: Appending IP pkt failed.\n", __LINE__);
		} else {
			//__u16 len = ctx->data_end - ctx->data;
			//bpf_debug("[Transit:%d] XXXX TX: Appending IP pkt succeeded(len=%d -- %d).\n", 
			//	__LINE__, len, apendlen);
		}
	}

	struct transit_packet pkt;
	pkt.data = (void *)(long)ctx->data;
	pkt.data_end = (void *)(long)ctx->data_end;
	pkt.xdp = ctx;
	pkt.itf_idx = ctx->ingress_ifindex;
	
	// maybe get rid of this check?
	pkt.itf = bpf_map_lookup_elem(&if_config_map, &pkt.itf_idx);
	if (!pkt.itf) {
		bpf_debug("[Transit:%d] ABORTED: Failed to lookup ingress config for %d\n",
			  __LINE__, pkt.itf_idx);
		return XDP_ABORTED;
	}

	//bpf_debug("[Transit:%d] XXX received packet at %d\n",
	//		  __LINE__, pkt.itf_idx);

	int action = trn_process_eth(&pkt);

	/* The agent may tail-call this program, override XDP_TX to
	 * redirect to egress instead */
/*	if (action == XDP_TX)
		action = bpf_redirect_map(&interfaces_map, pkt.itf_idx, 0);
*/
	if (action == XDP_PASS) {
		__u32 key = TRAN_PASS_PROG;
		bpf_tail_call(pkt.xdp, &jmp_table, key);
		return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);
	}

    if (action == EP_NOT_FOUND) {
        /*
         * A set entry here means that the corresponding quie_id
         * has an active AF_XDP socket bound to it.
         */
        __u32 rx_q_index = ctx->rx_queue_index;
        bpf_debug("Going to send packet to rx_queue with index: %u", __LINE__, rx_q_index);
        if (bpf_map_lookup_elem(&xsks_map, &(rx_q_index))) {
            bpf_debug("Sending packet to user space via AF_XDP\n",
                      __LINE__);
            return bpf_redirect_map(&xsks_map, rx_q_index, 0);
        }
        // if the packet forwarding to the userspace fails, drop the packet.
        action = XDP_DROP;
    }
	if (action == XDP_DROP) {
		__u32 key = TRAN_DROP_PROG;
		bpf_tail_call(pkt.xdp, &jmp_table, key);
		return xdpcap_exit(ctx, &xdpcap_hook, XDP_DROP);
	}

	if (action == XDP_TX) {
		__u32 key = TRAN_TX_PROG;
		bpf_tail_call(pkt.xdp, &jmp_table, key);
		return xdpcap_exit(ctx, &xdpcap_hook, XDP_TX);
	}

	if (action == XDP_ABORTED)
		return xdpcap_exit(ctx, &xdpcap_hook, XDP_ABORTED);

	if (action == XDP_REDIRECT) {
		__u32 key = TRAN_REDIRECT_PROG;
		bpf_tail_call(pkt.xdp, &jmp_table, key);
		return xdpcap_exit(ctx, &xdpcap_hook, XDP_REDIRECT);
	}

	return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
