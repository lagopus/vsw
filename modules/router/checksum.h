/*
 * Copyright 2019 Nippon Telegraph and Telephone Corporation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef VSW_MODULE_ROUTER_CHECKSUM_H_
#define VSW_MODULE_ROUTER_CHECKSUM_H_

/*
 * Quoted from RFC 1624:
 *
 * HC' = ~(C + (-m) + m')    --    [Eqn. 3]
 *     = ~(~HC + ~m + m')
 *
 * where
 *   HC  - old checksum in header
 *   C   - one's complement sum of old header
 *   HC' - new checksum in header
 *   C'  - one's complement sum of new header
 *   m   - old value of a 16-bit field
 *   m'  - new value of a 16-bit field
 */

static inline uint32_t
calc_chksum_diff_2byte(uint16_t o, uint16_t n) {
	return (~ntohs(o) & 0xffff) + ntohs(n);
}

static inline uint32_t
calc_chksum_diff_4byte(uint32_t o, uint32_t n) {
	uint16_t o16 = o & 0xffff;
	uint16_t n16 = n & 0xffff;

	uint32_t sum = (~ntohs(o16) & 0xffff) + ntohs(n16);
	o16 = o >> 16;
	n16 = n >> 16;
	return sum + (~ntohs(o16) & 0xffff) + ntohs(n16);
}

/*
 * Update checksum based on diff provided by sum.
 * Returns the diff of checksum based on the new and old
 * checksum value.
 *
 * This is useful when we have to update checksum of
 * ICMP based on the inner IP header and L4 header in
 * ICMP time exceed and destination unreachable.
 *
 * The diff is reflected to the checksum in ICMP header,
 * for instance.
 *
 * SIMPLE USAGE:
 *	// Rewrite IP Header Source Address
 *	//
 *	// ip_hdr	        : a pointer to the original IPv4 Header.
 *	// ip_hdr->src_addr     : old source address.
 *	// ip_hdr->hdr_checksum : IPv4 header checksum. 
 *	// wan_addr	        : new source address in big endian.
 *	uint32_t diff = calc_chksum_diff_4byte(ip_hdr->src_addr, wan_addr);
 *	update_cksum(&ip_hdr->hdr_checksum, diff);
 *	ip_hdr->src_addr = wan_addr;
 */

static inline uint32_t
update_cksum(uint16_t *cksum, uint32_t sum) {
	uint16_t o = *cksum;

	uint32_t c;
	c = (~ntohs(*cksum) & 0xffff) + sum;
	c = (c & 0xffff) + (c >> 16);
	*cksum = ~htons(c + (c >> 16)) & 0xffff;

	return calc_chksum_diff_2byte(o, *cksum);
}

#endif /* !VSW_MODULE_ROUTER_CHECKSUM_H_ */
