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
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include <netinet/in.h>

#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_ip.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_mempool.h>

#include <rte_icmp.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "checksum.h"
#include "napt.h"
#include "router_log.h"

/* From Private to External */
struct napt_outbound_hash_key {
	uint32_t src_addr;   /**< source address */
	uint32_t dst_addr;   /**< destination address */
	uint16_t src_port;   /**< source port / query ID */
	uint16_t dst_port;   /**< destination port */
	uint8_t protocol_id; /**< protocol ID */
	uint8_t padding[3];  /**< must be zeroed */
} __attribute__((__packed__));

/* From External to Private */
struct napt_inbound_hash_key {
	uint32_t src_addr;   /**< source address */
	uint16_t src_port;   /**< source port / query ID */
	uint16_t dst_port;   /**< destination port */
	uint8_t protocol_id; /**< protocol ID */
	uint8_t padding[3];  /**< must be zeroed */
} __attribute__((__packed__));

struct napt_dst_ports;

struct napt_entry {
	struct napt_dst_ports *ports;
	time_t expire;
	uint16_t ext_port;  /**< external port */
	uint16_t priv_port; /**< private port */
	uint32_t priv_addr; /**< private source address */
	bool fin_rst;       /**< closed entry (For TCP) */
};

struct napt_dst_key {
	uint32_t dst_addr;
	uint16_t dst_port;
	uint8_t protocol_id;
	uint8_t padding; /* must be zeroed */
} __attribute__((__packed__));

struct napt_dst_ports {
	uint64_t *ports; // bit masks for used ports
	int16_t len;     // length of napt_dst.ports
	int16_t offset;  // offsets of port number
	int count;	 // number of ports allocated
};

struct fragment_key {
	uint32_t src_addr;   /**< source address */
	uint16_t packet_id;  /**< packet ID */
	uint8_t protocol_id; /**< protocol ID */
	uint8_t padding;     /**< must be zeroed */
} __attribute__((__packed__));

struct fragment_info {
	uint32_t priv_addr; /**< private source address */
	time_t expire;      /**< expiration */
};

struct napt {
	struct napt_config config;
	struct rte_hash *outbound_hash;
	struct rte_hash *inbound_hash;
	struct rte_hash *dst_hash;
	struct rte_hash *fragment_hash;

	struct rte_mempool *pool;
	struct rte_mempool *fragment_pool;

	int max_ports;
	int max_dst_buckets;
};

// RFC6335 defines the port range that NAPT may use.
// The effective range is 14bits.
#define DYNAMIC_PORTS_MIN 49152
#define DYNAMIC_PORTS_MAX 65535

// RFC1035 defines DNS server port
#define DNS_PORT (htons(53))

// RFC792 ICMP
// ICMP Echo Request and Reply are defined in rte_icmp.h.
#define IP_ICMP_DESTINATION_UNREACHABLE 3
#define IP_ICMP_TIME_EXCEEDED 11

// RFC793 TCP
#define IP_TCP_FIN_RST 0x5

/**
 * NAPT Core
 */

static uint32_t
napt_outbound_hash_func(const void *key, uint32_t length, uint32_t initval) {
	const uint64_t *p = (const uint64_t *)key;
	uint32_t v;

	/*
	 * Passed key shall be the type struct napt_outbound_hash_key
	 * which should be 16 bytes. If the key length has changed
	 * this function must be fixed too.
	 */
	assert(length == 16);

	v = rte_hash_crc_8byte(p[0], initval);
	v = rte_hash_crc_8byte(p[1], v);

	return v;
}

static struct rte_hash *
napt_create_outbound_hash_table(struct napt_config *config) {
	char hash_name[RTE_HASH_NAMESIZE];

	snprintf(hash_name, sizeof(hash_name), "napt-out-%u", config->vif);

	struct rte_hash_parameters hash_params = {
	    .name = hash_name,
	    .entries = config->max_entries,
	    .key_len = sizeof(struct napt_outbound_hash_key),
	    .hash_func = napt_outbound_hash_func,
	    .hash_func_init_val = 0,
	    .socket_id = rte_socket_id(),
	};

	return rte_hash_create(&hash_params);
}

static uint32_t
napt_inbound_hash_func(const void *key, uint32_t length, uint32_t initval) {
	const uint32_t *p = (const uint32_t *)key;
	uint32_t v;

	/*
	 * Passed key shall be the type struct napt_inbound_hash_key
	 * which should be 12 bytes. If the key length has changed
	 * this function must be fixed too.
	 */
	assert(length == 12);

	v = rte_hash_crc_4byte(p[0], initval);
	v = rte_hash_crc_4byte(p[1], v);
	v = rte_hash_crc_4byte(p[2], v);

	return v;
}

static struct rte_hash *
napt_create_inbound_hash_table(struct napt_config *config) {
	char hash_name[RTE_HASH_NAMESIZE];

	snprintf(hash_name, sizeof(hash_name), "napt-in-%u", config->vif);

	struct rte_hash_parameters hash_params = {
	    .name = hash_name,
	    .entries = config->max_entries,
	    .key_len = sizeof(struct napt_inbound_hash_key),
	    .hash_func = napt_inbound_hash_func,
	    .hash_func_init_val = 0,
	    .socket_id = rte_socket_id(),
	};

	return rte_hash_create(&hash_params);
}

static uint32_t
napt_8byte_hash_func(const void *key, uint32_t length, uint32_t initval) {
	assert(length == 8);
	return rte_hash_crc_8byte(*(uint64_t *)key, initval);
}

static struct rte_hash *
napt_create_dst_hash_table(struct napt_config *config) {
	char hash_name[RTE_HASH_NAMESIZE];

	snprintf(hash_name, sizeof(hash_name), "napt-dst-%u", config->vif);

	struct rte_hash_parameters hash_params = {
	    .name = hash_name,
	    .entries = config->max_entries,
	    .key_len = sizeof(struct napt_dst_key),
	    .hash_func = napt_8byte_hash_func,
	    .hash_func_init_val = 0,
	    .socket_id = rte_socket_id(),
	};

	return rte_hash_create(&hash_params);
}

static struct rte_hash *
napt_create_fragment_hash_table(struct napt_config *config) {
	char hash_name[RTE_HASH_NAMESIZE];

	snprintf(hash_name, sizeof(hash_name), "napt-frag-%u", config->vif);

	struct rte_hash_parameters hash_params = {
	    .name = hash_name,
	    .entries = config->frag_entries,
	    .key_len = sizeof(struct fragment_key),
	    .hash_func = napt_8byte_hash_func,
	    .hash_func_init_val = 0,
	    .socket_id = rte_socket_id(),
	};

	return rte_hash_create(&hash_params);
}

static bool
napt_check_config(struct napt_config *config) {
	if (config == NULL)
		return false;

	if (config->vif == VIF_INVALID_INDEX)
		return false;

	if (config->port_min > config->port_max)
		return false;

	if (config->port_min < DYNAMIC_PORTS_MIN)
		return false;

	if (config->frag_entries == 0)
		config->frag_entries = 100; // FIXME: Magic number for now

	return true;
}

static struct rte_mempool *
napt_alloc_mempool(struct napt_config *config) {
	char name[RTE_MEMPOOL_NAMESIZE];
	snprintf(name, sizeof name, "mp-napt-%u", config->vif);
	return rte_mempool_create(name,
				  config->max_entries, sizeof(struct napt_entry), 0, 0,
				  NULL, NULL, NULL, NULL,
				  rte_socket_id(),
				  MEMPOOL_F_NO_CACHE_ALIGN | MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET);
}

static struct rte_mempool *
napt_alloc_fragment_mempool(struct napt_config *config) {
	char name[RTE_MEMPOOL_NAMESIZE];
	snprintf(name, sizeof name, "mp-frag-%u", config->vif);
	return rte_mempool_create(name,
				  config->frag_entries, sizeof(struct fragment_info), 0, 0,
				  NULL, NULL, NULL, NULL,
				  rte_socket_id(),
				  MEMPOOL_F_NO_CACHE_ALIGN | MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET);
}

/**
 * Create NAPT instance.
 */
struct napt *
napt_create(struct napt_config *config) {
	struct napt *napt;

	if (!napt_check_config(config))
		return NULL;

	if ((napt = rte_zmalloc(NULL, sizeof(struct napt), 0)) == NULL)
		return NULL;

	napt->pool = napt_alloc_mempool(config);
	if (napt->pool == NULL)
		goto error;

	napt->fragment_pool = napt_alloc_fragment_mempool(config);
	if (napt->fragment_pool == NULL)
		goto error;

	napt->outbound_hash = napt_create_outbound_hash_table(config);
	if (napt->outbound_hash == NULL)
		goto error;

	napt->inbound_hash = napt_create_inbound_hash_table(config);
	if (napt->inbound_hash == NULL)
		goto error;

	napt->dst_hash = napt_create_dst_hash_table(config);
	if (napt->dst_hash == NULL)
		goto error;

	napt->fragment_hash = napt_create_fragment_hash_table(config);
	if (napt->fragment_hash == NULL)
		goto error;

	napt->config = *config;
	napt->config.wan_addr = htonl(napt->config.wan_addr);

	napt->max_ports = (int)napt->config.port_max - (int)napt->config.port_min + 1;
	napt->max_dst_buckets = (napt->max_ports + 63) / 64;

	return napt;

error:
	// TODO: output rte_strerror(rte_errno)
	napt_free(napt);
	return NULL;
}

void
napt_free(struct napt *napt) {
	rte_hash_free(napt->outbound_hash);
	rte_hash_free(napt->inbound_hash);
	rte_hash_free(napt->dst_hash);
	rte_hash_free(napt->fragment_hash);
	rte_mempool_free(napt->pool);
	rte_mempool_free(napt->fragment_pool);
	rte_free(napt);
}

static int
napt_purge_expired_entries(struct napt *napt);

static bool
napt_allocate_port(struct napt *napt, struct napt_outbound_hash_key *nkey, struct napt_entry *entry) {
	struct napt_dst_ports *dp = entry->ports;
	int offset; // we must declare offset variable here for possbile goto.

	if (dp == NULL) {
		struct napt_dst_key key = {
		    .dst_addr = nkey->dst_addr,
		    .dst_port = nkey->dst_port,
		    .protocol_id = nkey->protocol_id,
		};

		int rc = rte_hash_lookup_data(napt->dst_hash, &key, (void **)&dp);
		if (rc == -ENOENT) {
			// allocate napt_dst_ports
			dp = rte_zmalloc(NULL, sizeof(struct napt_dst_ports), 0);

			// TODO: log no memory
			if (dp == NULL)
				return false;

			if (rte_hash_add_key_data(napt->dst_hash, &key, dp) != 0) {
				// TODO: log error
				rte_free(dp);
				return false;
			}
		} else {
			assert(rc >= 0);
		}
		entry->ports = dp;
	}

	if (dp->count == napt->max_ports) {
		if (napt_purge_expired_entries(napt) == 0)
			return false;
	}

	int n; // bucket #

	// search empty bucket
	for (n = 0; n < dp->len; n++) {
		if (dp->ports[n] != 0UL)
			goto port_allocation; // found one
	}

	// No space left. Expand if possible.
	if (dp->len == napt->max_dst_buckets) {
		// can't expand anymore
		return false;
	}

	size_t nsize = sizeof(uint64_t) * (dp->len + 1);
	uint64_t *nports = rte_realloc(dp->ports, nsize, 0);

	//  TODO: log no memory
	if (nports == NULL)
		return false;

	n = dp->len;
	nports[n] = ~0UL;
	dp->ports = nports;
	dp->len++;

port_allocation:
	// We should have free port in this bucket.
	offset = __builtin_ffsll(dp->ports[n]) - 1;
	uint32_t ext_port = napt->config.port_min + n * 64 + offset;

	// Port number shall not exceed the upper boundary
	if (ext_port > (uint32_t)napt->config.port_max)
		return false;

	dp->ports[n] &= ~(1UL << offset);
	dp->count++;

	// TODO: offset port base to randomize
	entry->ext_port = htons(ext_port);

	return true;
}

static void
napt_free_port(struct napt *napt, struct napt_dst_ports *dp, uint16_t port) {
	port = ntohs(port);
	port -= napt->config.port_min;
	int n = port / 64;
	int offset = port % 64;

	if (n >= dp->len)
		return;

	dp->ports[n] |= 1UL << offset;

	// If we just freed a port in the last bucket, check if we can free
	// the bucket up to that last bucket.
	if (n == dp->len - 1) {
		int last_bucket = n;

		while (n >= 0 && dp->ports[n] == ~0UL)
			n--;

		// rte_realloc() frees the memory, if the requested size is 0.
		if (n < last_bucket) {
			dp->len = n + 1;
			dp->ports = rte_realloc(dp->ports, sizeof(uint64_t) * dp->len, 0);
		}
	}

	dp->count--;
}

static void
napt_free_entry(struct napt *napt, struct napt_inbound_hash_key *ikey, struct napt_entry *data) {
	struct napt_outbound_hash_key okey = {
	    .src_addr = data->priv_addr,
	    .src_port = data->priv_port,
	    .dst_addr = ikey->src_addr,
	    .dst_port = ikey->src_port,
	    .protocol_id = ikey->protocol_id,
	};
	rte_hash_del_key(napt->outbound_hash, &okey);
	rte_hash_del_key(napt->inbound_hash, ikey);
	rte_mempool_put(napt->pool, data);

	napt_free_port(napt, data->ports, data->ext_port);

	ROUTER_DEBUG("NAPT: Free NAPT Entry: %08x:%d -> %08x:%d, Proto:%d, Ext: %d",
		     ntohl(data->priv_addr), ntohs(data->priv_port),
		     ntohl(ikey->src_addr), ntohs(ikey->src_port),
		     ikey->protocol_id, ntohs(data->ext_port));
}

/**
 * Purge expired entries.
 *
 * This may take a while.
 * Returns a number of entries that are freed.
 */
static int
napt_purge_expired_entries(struct napt *napt) {
	time_t now = time(NULL);
	struct napt_inbound_hash_key *key;
	struct napt_entry *data;
	uint32_t next = 0;
	int count = 0, dst_count = 0;

	while (rte_hash_iterate(napt->inbound_hash, (const void **)&key, (void **)&data, &next) >= 0) {
		if (data->expire < now) {
			napt_free_entry(napt, key, data);
			count++;
		}
	}

	ROUTER_DEBUG("NAPT: Freed %d expired entries", count);

	struct napt_dst_key *dkey;
	struct napt_dst_ports *dp;

	next = 0;
	while (rte_hash_iterate(napt->dst_hash, (const void **)&dkey, (void **)&dp, &next) >= 0) {
		if (dp->len == 0) {
			ROUTER_DEBUG("NAPT: Free Dst Entry: %08x:%d Proto:%d",
				     ntohl(dkey->dst_addr), ntohs(dkey->dst_port), dkey->protocol_id);

			rte_hash_del_key(napt->dst_hash, dkey);
			rte_free(dp);
			dst_count++;
		}
	}

	ROUTER_DEBUG("NAPT: Freed %d unused dst ports", dst_count);

	return count;
}

/**
 * Search outbound NAPT entry.
 *
 * If not found, allocates new one.
 * If the table is full, it returns NULL.
 */
static struct napt_entry *
napt_search_outbound_entry(struct napt *napt, struct napt_outbound_hash_key *key) {
	struct napt_entry *data;
	time_t now = time(NULL);

	int rc = rte_hash_lookup_data(napt->outbound_hash, key, (void **)&data);
	if (rc >= 0) {
		// Found one.  Check if the entry is still valid.
		if (data->expire < now) {
			ROUTER_DEBUG("NAPT: expired %ld < %ld", data->expire, now);

			// Time elapsed. Need to find the new port number.
			uint16_t expired_port = data->ext_port;

			// Allocate a new port first.
			if (!napt_allocate_port(napt, key, data))
				return NULL; // TODO: Log error

			// Free the expired port.
			napt_free_port(napt, data->ports, expired_port);
		}
	} else if (rc == -ENOENT) {
		// Need to allocate one.
		if (rte_mempool_get(napt->pool, (void **)&data) != 0) {
			// TODO
			// Garbage collect if there's no space. Remove
			// entries that are expired. Then retry rte_mepool_get().
			// If we cannot still get the free entry, then
			// there's nothing we can do.
			if (napt_purge_expired_entries(napt) == 0) {
				ROUTER_INFO("NAPT table full for VIF index %u", napt->config.vif);
				goto err1; // TODO: Log error
			}

			if (rte_mempool_get(napt->pool, (void **)&data) != 0) {
				ROUTER_ERROR("Can't allocate NAPT entry after purge (VIF index: %d).",
					     napt->config.vif);
				goto err1; // TODO: Log error
			}
		}

		// napt_allocate_port() should fill data->ext_port.
		data->fin_rst = false;
		data->ports = NULL;
		if (!napt_allocate_port(napt, key, data)) {
			ROUTER_ERROR("NAPT port allocation failed.");
			goto err2; // TODO: Log error
		}

		// Register outbound key
		if (rte_hash_add_key_data(napt->outbound_hash, key, data) != 0) {
			ROUTER_ERROR("NAPT outbound key registration failed.");
			goto err3; // TODO: Log error
		}

		// Register inbound key
		struct napt_inbound_hash_key ikey = {
		    .src_addr = key->dst_addr,
		    .src_port = key->dst_port,
		    .dst_port = data->ext_port,
		    .protocol_id = key->protocol_id,
		};

		if (rte_hash_add_key_data(napt->inbound_hash, &ikey, data) != 0) {
			ROUTER_ERROR("NAPT inbound key registration failed.");
			goto err4; // TODO: Log error
		}

		ROUTER_DEBUG("NAPT INBOUND registered (src: %08x:%d, dst: %d, proto=%d).",
			     ntohl(ikey.src_addr), ntohs(ikey.src_port),
			     ntohs(ikey.dst_port), ikey.protocol_id);

		// Save private source address and port number.
		data->priv_addr = key->src_addr;
		data->priv_port = key->src_port;
	} else {
		// FATAL
		ROUTER_ERROR("NAPT hash in bad condition: rc=%d", rc);
		return NULL;
	}

	// Update the expire time.
	if (!data->fin_rst)
		data->expire = now + napt->config.aging_time;

	return data;

err4:
	rte_hash_del_key(napt->outbound_hash, key);
err3:
	napt_free_port(napt, data->ports, data->ext_port);
err2:
	rte_mempool_put(napt->pool, data);
err1:
	ROUTER_ERROR("NAPT allocation failed (%08x:%d, %08x:%d, %d).",
		     htonl(key->dst_addr), htons(key->dst_port), htonl(key->src_addr), htons(key->src_port), key->protocol_id);
	return NULL;
}

/**
 * Search inbound NAPT entry.
 *
 * If not found or expired, returns NULL.
 */
static struct napt_entry *
napt_search_inbound_entry(struct napt *napt, struct napt_inbound_hash_key *key) {
	struct napt_entry *data;
	time_t now = time(NULL);

	if (rte_hash_lookup_data(napt->inbound_hash, key, (void **)&data) >= 0) {
		// Found one.  Check if the entry is still valid.
		if (data->expire >= now) {
			// Update the expire time.
			if (!data->fin_rst)
				data->expire = now + napt->config.aging_time;
			return data;
		}

		ROUTER_DEBUG("NAPT: expired %ld < %ld", data->expire, now);

		// Free the expired port.
		napt_free_port(napt, data->ports, data->ext_port);
	}

	return NULL;
}

static bool
napt_outbound_icmp(struct napt *napt, struct ipv4_hdr *ip_hdr, struct icmp_hdr *icmp_hdr) {
	// ICMP packet other than echo request shall be dropped.
	if (icmp_hdr->icmp_type != IP_ICMP_ECHO_REQUEST)
		return false;

	struct napt_outbound_hash_key key = {
	    .src_addr = ip_hdr->src_addr,
	    .dst_addr = ip_hdr->dst_addr,
	    .src_port = icmp_hdr->icmp_ident,
	    .dst_port = 0, // Must be zero for ICMP
	    .protocol_id = IPPROTO_ICMP,
	};

	struct napt_entry *data = napt_search_outbound_entry(napt, &key);
	if (data == NULL) {
		ROUTER_INFO("NAPT search outbound entry failed.");
		return false; // TODO: Log error
	}

	// Rewrite packet
	ROUTER_DEBUG("NAPT rewriting to %08x:%d -> %08x:%d",
		     ntohl(ip_hdr->src_addr), ntohs(icmp_hdr->icmp_ident),
		     ntohl(napt->config.wan_addr), ntohs(data->ext_port));

	// Rewrite IP Header Source Address
	uint32_t diff = calc_chksum_diff_4byte(ip_hdr->src_addr, napt->config.wan_addr);
	update_cksum(&ip_hdr->hdr_checksum, diff);
	ip_hdr->src_addr = napt->config.wan_addr;

	// Rewrite ICMP Header Identifier
	diff = calc_chksum_diff_2byte(icmp_hdr->icmp_ident, data->ext_port);
	update_cksum(&icmp_hdr->icmp_cksum, diff);
	icmp_hdr->icmp_ident = data->ext_port;

	return true;
}

static bool
napt_rewrite_icmp_echo_reply(struct napt *napt, struct ipv4_hdr *ip_hdr, struct icmp_hdr *icmp_hdr) {
	struct napt_inbound_hash_key key = {
	    .src_addr = ip_hdr->src_addr,
	    .src_port = 0, // Must be zero for ICMP
	    .dst_port = icmp_hdr->icmp_ident,
	    .protocol_id = IPPROTO_ICMP,
	};

	// Drop packet, if we cannot find the entry.
	struct napt_entry *data = napt_search_inbound_entry(napt, &key);
	if (data == NULL) {
		ROUTER_INFO("NAPT search inbound entry failed.");
		return false; // TODO: Log error
	}

	// Rewrite packet

	// Rewrite IP header destination address
	uint32_t diff = calc_chksum_diff_4byte(ip_hdr->dst_addr, data->priv_addr);
	update_cksum(&ip_hdr->hdr_checksum, diff);
	ip_hdr->dst_addr = data->priv_addr;

	// Rewrite ICMP header identifier
	diff = calc_chksum_diff_2byte(icmp_hdr->icmp_ident, data->priv_port);
	update_cksum(&icmp_hdr->icmp_cksum, diff);
	icmp_hdr->icmp_ident = data->priv_port;

	return true;
};

struct l4_hdr {
	uint16_t src_port;
	uint16_t dst_port;
};

static bool
napt_rewrite_icmp_message(struct napt *napt, struct ipv4_hdr *ip_hdr, struct icmp_hdr *icmp_hdr) {
	struct ipv4_hdr *inner_ip_hdr = (void *)icmp_hdr + sizeof(struct icmp_hdr);

	// Rewrite
	switch (inner_ip_hdr->next_proto_id) {
	case IPPROTO_ICMP: {
		struct icmp_hdr *inner_icmp_hdr = (void *)inner_ip_hdr + sizeof(struct ipv4_hdr);

		struct napt_inbound_hash_key key = {
		    .src_addr = inner_ip_hdr->dst_addr,
		    .src_port = 0,
		    .dst_port = inner_icmp_hdr->icmp_ident,
		    .protocol_id = IPPROTO_ICMP,
		};

		// Drop packet, if we cannot find the entry.
		struct napt_entry *data = napt_search_inbound_entry(napt, &key);
		if (data == NULL) {
			ROUTER_INFO("NAPT INBOUND no entry found (src: %08x:%d, dst: %d, proto=%d).",
				    ntohl(key.src_addr), ntohs(key.src_port), ntohs(key.dst_port), key.protocol_id);
			return false; // TODO: Log error
		}

		// Rewrite inner ICMP identifier
		uint32_t icmp_diff = calc_chksum_diff_2byte(inner_icmp_hdr->icmp_ident, data->priv_port);
		inner_icmp_hdr->icmp_ident = data->priv_port;
		uint32_t cksum_diff = update_cksum(&inner_icmp_hdr->icmp_cksum, icmp_diff);

		// Rewrite inner source IP address
		uint32_t ip_diff = calc_chksum_diff_4byte(inner_ip_hdr->src_addr, data->priv_addr);
		inner_ip_hdr->src_addr = data->priv_addr;
		cksum_diff += update_cksum(&inner_ip_hdr->hdr_checksum, ip_diff);

		// Update outer ICMP checksum
		update_cksum(&icmp_hdr->icmp_cksum, ip_diff + icmp_diff + cksum_diff);

		// Rewrite outer destination IP address
		uint32_t diff = calc_chksum_diff_4byte(ip_hdr->dst_addr, data->priv_addr);
		ip_hdr->dst_addr = data->priv_addr;
		update_cksum(&ip_hdr->hdr_checksum, diff);

		break;
	}

	case IPPROTO_TCP:
	case IPPROTO_UDP: {
		struct l4_hdr *l4_hdr = (void *)inner_ip_hdr + sizeof(struct ipv4_hdr);

		struct napt_inbound_hash_key key = {
		    .src_addr = inner_ip_hdr->dst_addr,
		    .src_port = l4_hdr->dst_port,
		    .dst_port = l4_hdr->src_port,
		    .protocol_id = inner_ip_hdr->next_proto_id,
		};

		// Drop packet, if we cannot find the entry.
		struct napt_entry *data = napt_search_inbound_entry(napt, &key);
		if (data == NULL) {
			ROUTER_INFO("NAPT INBOUND no entry found (src: %08x:%d, dst: %d, proto=%d).",
				    ntohl(key.src_addr), ntohs(key.src_port), ntohs(key.dst_port), key.protocol_id);
			return false; // TODO: Log error
		}

		// Adjust checksum for inner IP header
		uint32_t diff = calc_chksum_diff_4byte(inner_ip_hdr->src_addr, data->priv_addr);

		// Update inner header checksum
		uint32_t cksum_diff = update_cksum(&inner_ip_hdr->hdr_checksum, diff);

		// Adjust checksum for L4 source port
		diff += calc_chksum_diff_2byte(l4_hdr->src_port, data->priv_port);

		// Adjust checksum for UDP
		if (key.protocol_id == IPPROTO_UDP) {
			struct udp_hdr *udp_hdr = (struct udp_hdr *)l4_hdr;

			// Update UDP header checksum
			cksum_diff += update_cksum(&udp_hdr->dgram_cksum, diff);
		}

		// Update ICMP checksum
		update_cksum(&icmp_hdr->icmp_cksum, diff + cksum_diff);

		// Rewrite outer IP header destination address
		diff = calc_chksum_diff_4byte(ip_hdr->dst_addr, data->priv_addr);
		update_cksum(&ip_hdr->hdr_checksum, diff);

		// Rewrite headers
		ip_hdr->dst_addr = data->priv_addr;
		inner_ip_hdr->src_addr = data->priv_addr;
		l4_hdr->src_port = data->priv_port;
		break;
	}

	default:
		ROUTER_INFO("NAPT icmp error: unsupported protocol: %d", inner_ip_hdr->next_proto_id);
		return false;
	}

	return true;
}

static bool
napt_inbound_icmp(struct napt *napt, struct ipv4_hdr *ip_hdr, struct icmp_hdr *icmp_hdr) {
	// check supported ICMP message types.
	switch (icmp_hdr->icmp_type) {
	case IP_ICMP_ECHO_REPLY:
		return napt_rewrite_icmp_echo_reply(napt, ip_hdr, icmp_hdr);
	case IP_ICMP_DESTINATION_UNREACHABLE:
	case IP_ICMP_TIME_EXCEEDED:
		return napt_rewrite_icmp_message(napt, ip_hdr, icmp_hdr);
	default:
		ROUTER_INFO("NAPT icmp unsupported message: %d", icmp_hdr->icmp_type);
		break;
	}
	return false;
}

static bool
napt_outbound_udp(struct napt *napt, struct ipv4_hdr *ip_hdr, struct udp_hdr *udp_hdr) {
	struct napt_outbound_hash_key key = {
	    .src_addr = ip_hdr->src_addr,
	    .dst_addr = ip_hdr->dst_addr,
	    .src_port = udp_hdr->src_port,
	    .dst_port = udp_hdr->dst_port,
	    .protocol_id = IPPROTO_UDP,
	};

	struct napt_entry *data = napt_search_outbound_entry(napt, &key);
	if (data == NULL) {
		ROUTER_INFO("NAPT search outbound entry failed.");
		return false; // TODO: Log error
	}

	// Rewrite packet

	// Rewrite IP Header Source Address
	uint32_t diff = calc_chksum_diff_4byte(ip_hdr->src_addr, napt->config.wan_addr);
	update_cksum(&ip_hdr->hdr_checksum, diff);
	ip_hdr->src_addr = napt->config.wan_addr;

	// Rewrite TCP Header (src port)
	diff += calc_chksum_diff_2byte(udp_hdr->src_port, data->ext_port);
	update_cksum(&udp_hdr->dgram_cksum, diff);
	udp_hdr->src_port = data->ext_port;

	return true;
}

static bool
napt_inbound_udp(struct napt *napt, struct ipv4_hdr *ip_hdr, struct udp_hdr *udp_hdr) {
	struct napt_inbound_hash_key key = {
	    .src_addr = ip_hdr->src_addr,
	    .src_port = udp_hdr->src_port,
	    .dst_port = udp_hdr->dst_port,
	    .protocol_id = IPPROTO_UDP,
	};

	// Drop packet, if we cannot find the entry.
	struct napt_entry *data = napt_search_inbound_entry(napt, &key);
	if (data == NULL) {
		// ROUTER_INFO("NAPT INBOUND UDP no entry found.");
		return false; // TODO: Log error
	}

	// Rewrite packet

	// Rewrite IP Header Destination Address
	uint32_t diff = calc_chksum_diff_4byte(ip_hdr->dst_addr, data->priv_addr);
	update_cksum(&ip_hdr->hdr_checksum, diff);
	ip_hdr->dst_addr = data->priv_addr;

	// Rewrite UDP Header (dst port)
	diff += calc_chksum_diff_2byte(udp_hdr->dst_port, data->priv_port);
	update_cksum(&udp_hdr->dgram_cksum, diff);
	udp_hdr->dst_port = data->priv_port;

	// If the soucre port is of DNS service, then delete the entry immediately.
	if (udp_hdr->src_port == DNS_PORT) {
		ROUTER_DEBUG("NAPT UDP: Deleting NAP entry for DNS query: freeing %d", ntohs(data->ext_port));
		napt_free_entry(napt, &key, data);

#if 0
		// DEBUG
		if (rte_hash_lookup_data(napt->inbound_hash, &key, (void **)&data) != -ENOENT) {
			ROUTER_ERROR("NAPT UDP: couldn't inbound delete entry");
		} else {
			ROUTER_INFO("NAPT UDP: inbound entry clear");
		}

		struct napt_outbound_hash_key okey = {
		    .src_addr = data->priv_addr,
		    .src_port = data->priv_port,
		    .dst_addr = key.src_addr,
		    .dst_port = key.src_port,
		    .protocol_id = key.protocol_id,
		};
		if (rte_hash_lookup_data(napt->outbound_hash, &okey, (void **)&data) != -ENOENT) {
			ROUTER_ERROR("NAPT UDP: couldn't outbound delete entry");
		} else {
			ROUTER_INFO("NAPT UDP: outbound entry clear");
		}
#endif
	}

	return true;
}

static bool
napt_outbound_tcp(struct napt *napt, struct ipv4_hdr *ip_hdr, struct tcp_hdr *tcp_hdr) {
	struct napt_outbound_hash_key key = {
	    .src_addr = ip_hdr->src_addr,
	    .dst_addr = ip_hdr->dst_addr,
	    .src_port = tcp_hdr->src_port,
	    .dst_port = tcp_hdr->dst_port,
	    .protocol_id = IPPROTO_TCP,
	};

	struct napt_entry *data = napt_search_outbound_entry(napt, &key);
	if (data == NULL) {
		ROUTER_INFO("NAPT search outbound entry failed.");
		return false; // TODO: Log error
	}

	// Rewrite packet

	// Rewrite IP Header Source Address
	uint32_t diff = calc_chksum_diff_4byte(ip_hdr->src_addr, napt->config.wan_addr);
	update_cksum(&ip_hdr->hdr_checksum, diff);
	ip_hdr->src_addr = napt->config.wan_addr;

	// Rewrite TCP Header (src port)
	diff += calc_chksum_diff_2byte(tcp_hdr->src_port, data->ext_port);
	update_cksum(&tcp_hdr->cksum, diff);
	tcp_hdr->src_port = data->ext_port;

	/*
	 * Check FIN/RST
	 *
	 * If FIN/RST is set to the packet, we set the expiary time to 2sec from now.
	 * TODO: make timeout to be configurable.
	 */
	if ((!data->fin_rst) && (tcp_hdr->tcp_flags & IP_TCP_FIN_RST)) {
		ROUTER_DEBUG("NAPT: TCP: outbound clean: %02x", tcp_hdr->tcp_flags);
		data->expire = time(NULL) + 2;
		data->fin_rst = true;
	}

	return true;
}

static bool
napt_inbound_tcp(struct napt *napt, struct ipv4_hdr *ip_hdr, struct tcp_hdr *tcp_hdr) {
	struct napt_inbound_hash_key key = {
	    .src_addr = ip_hdr->src_addr,
	    .src_port = tcp_hdr->src_port,
	    .dst_port = tcp_hdr->dst_port,
	    .protocol_id = IPPROTO_TCP,
	};

	// Drop packet, if we cannot find the entry.
	struct napt_entry *data = napt_search_inbound_entry(napt, &key);
	if (data == NULL) {
		// ROUTER_INFO("NAPT INBOUND UDP no entry found.");
		return false; // TODO: Log error
	}

	// Rewrite packet

	// Rewrite IP Header Destination Address
	uint32_t diff = calc_chksum_diff_4byte(ip_hdr->dst_addr, data->priv_addr);
	update_cksum(&ip_hdr->hdr_checksum, diff);
	ip_hdr->dst_addr = data->priv_addr;

	// Rewrite UDP Header (dst port)
	diff += calc_chksum_diff_2byte(tcp_hdr->dst_port, data->priv_port);
	update_cksum(&tcp_hdr->cksum, diff);
	tcp_hdr->dst_port = data->priv_port;

	/*
	 * Check FIN/RST
	 *
	 * If FIN/RST is set to the packet, we set the expiary time to 2sec from now.
	 * TODO: make timeout to be configurable.
	 */
	if ((!data->fin_rst) && (tcp_hdr->tcp_flags & IP_TCP_FIN_RST)) {
		ROUTER_DEBUG("NAPT: TCP: inbound clean: %02x", tcp_hdr->tcp_flags);
		data->expire = time(NULL) + 2;
		data->fin_rst = true;
	}

	return true;
}

static void
napt_outbound_fragment(struct napt *napt, struct ipv4_hdr *ip_hdr) {
	// Rewrite IP Header Source Address
	update_cksum(&ip_hdr->hdr_checksum,
		     calc_chksum_diff_4byte(ip_hdr->src_addr, napt->config.wan_addr));
	ip_hdr->src_addr = napt->config.wan_addr;
}

static int
napt_purge_expired_fragment(struct napt *napt) {
	time_t now = time(NULL);
	struct fragment_key *key;
	struct fragment_info *data;
	uint32_t next = 0;
	int count = 0;

	while (rte_hash_iterate(napt->fragment_hash, (const void **)&key, (void **)&data, &next) >= 0) {
		if (data->expire < now) {
			rte_hash_del_key(napt->fragment_hash, &key);
			rte_mempool_put(napt->fragment_pool, data);
			count++;
		}
	}

	return count;
}

static void
napt_inbound_fragment_first(struct napt *napt, struct ipv4_hdr *ip_hdr) {
	struct fragment_info *fi;

	if (rte_mempool_get(napt->fragment_pool, (void **)&fi) != 0) {
		if (napt_purge_expired_fragment(napt) == 0) {
			ROUTER_INFO("NAPT fragment table full for VIF index %u", napt->config.vif);
			return;
		}

		if (rte_mempool_get(napt->fragment_pool, (void **)&fi) != 0) {
			ROUTER_ERROR("Can't allocate NAPT fragment entry after purge (VIF index: %u).",
				     napt->config.vif);
			return;
		}
	}

	fi->priv_addr = ip_hdr->dst_addr;
	fi->expire = time(NULL) + 15; // TODO: Make timeout configurable

	struct fragment_key key = {
	    .src_addr = ip_hdr->src_addr,
	    .packet_id = ip_hdr->packet_id,
	    .protocol_id = ip_hdr->next_proto_id,
	    .padding = 0,
	};

	if (rte_hash_add_key_data(napt->fragment_hash, &key, fi) != 0) {
		rte_mempool_put(napt->fragment_pool, fi);
		ROUTER_ERROR("Can't register NAPT fragment entry (VIF index: %u)", napt->config.vif);
	}
}

static bool
napt_inbound_fragment_consecutive(struct napt *napt, struct ipv4_hdr *ip_hdr) {
	struct fragment_key key = {
	    .src_addr = ip_hdr->src_addr,
	    .packet_id = ip_hdr->packet_id,
	    .protocol_id = ip_hdr->next_proto_id,
	    .padding = 0,
	};
	struct fragment_info *fi;

	if (rte_hash_lookup_data(napt->fragment_hash, &key, (void **)&fi) < 0)
		return false;

	if (fi->expire < time(NULL)) {
		rte_hash_del_key(napt->fragment_hash, &key);
		rte_mempool_put(napt->fragment_pool, fi);
		return false;
	}
	// TODO: Should we update timer per RFC 791?

	// rewrite header
	update_cksum(&ip_hdr->hdr_checksum,
		     calc_chksum_diff_4byte(ip_hdr->dst_addr, fi->priv_addr));
	ip_hdr->dst_addr = fi->priv_addr;

	// if MF == 0, delete the entry.
	if (!(ip_hdr->fragment_offset & htons(IPV4_HDR_MF_FLAG))) {
		rte_hash_del_key(napt->fragment_hash, &key);
		rte_mempool_put(napt->fragment_pool, fi);
	}

	return true;
}

/**
 * Rewrite mbuf sending to WAN.
 *
 * We assume only valid IPv4 pakcets comes in.
 */
bool
napt_outbound(struct napt *napt, struct rte_mbuf *mbuf) {
	struct ipv4_hdr *hdr = rte_pktmbuf_mtod_offset(mbuf, struct ipv4_hdr *,
						       sizeof(struct ether_hdr));

#if 0
	ROUTER_INFO("NAPT: offset=%d", mbuf->data_off);
	ROUTER_INFO("NAPT: %02x %02x %04x", hdr->version_ihl, hdr->type_of_service, ntohs(hdr->total_length));
	ROUTER_INFO("NAPT: %04x %04x", ntohs(hdr->packet_id), ntohs(hdr->fragment_offset));
	ROUTER_INFO("NAPT: %02x %02x %04x", hdr->time_to_live, hdr->next_proto_id, ntohs(hdr->hdr_checksum));
	ROUTER_INFO("NAPT: %08x %08x", ntohl(hdr->src_addr), ntohl(hdr->dst_addr));
#endif

	// If the packet is locally originated, then no need to
	// perform NAPT.
	if (hdr->src_addr == napt->config.wan_addr)
		return true;

	// Check if the packet is fragmented packet that is not the first
	// fragment. We rewrite only source address for such packets.
	// The first fragmented packet shall be go through the regular
	// NAPT process.
	//
	// TODO: We need to rewrite packet ID to avoid possible conflict.
	uint16_t offset = ntohs(hdr->fragment_offset) & IPV4_HDR_OFFSET_MASK;
	if (offset > 0) {
		ROUTER_DEBUG("NAPT: outgoing fragment packet (offset: %d)", offset);
		napt_outbound_fragment(napt, hdr);
		return true;
	}

	void *l4_hdr = (uint8_t *)hdr + (hdr->version_ihl & IPV4_HDR_IHL_MASK) * IPV4_IHL_MULTIPLIER;

	switch (hdr->next_proto_id) {
	case IPPROTO_ICMP:
		return napt_outbound_icmp(napt, hdr, (struct icmp_hdr *)l4_hdr);
	case IPPROTO_UDP:
		return napt_outbound_udp(napt, hdr, (struct udp_hdr *)l4_hdr);
	case IPPROTO_TCP:
		return napt_outbound_tcp(napt, hdr, (struct tcp_hdr *)l4_hdr);
	default:
		ROUTER_INFO("NAPT OTHERS(%d)", hdr->next_proto_id);
		break;
	}

	return false;
}

/**
 * Rewrite mbuf received from WAN.
 *
 * We assume only valid IPv4 pakcets comes in.
 */
bool
napt_inbound(struct napt *napt, struct rte_mbuf *mbuf) {
	struct ipv4_hdr *hdr = rte_pktmbuf_mtod_offset(mbuf, struct ipv4_hdr *,
						       sizeof(struct ether_hdr));
	void *l4_hdr = (void *)hdr + (hdr->version_ihl & IPV4_HDR_IHL_MASK) * IPV4_IHL_MULTIPLIER;

	// If the packet is not heading to the interface,
	// then drop the packet.
	if (hdr->dst_addr != napt->config.wan_addr)
		return false;

	// Check if the packet is consecutive fragment packet
	uint16_t offset = ntohs(hdr->fragment_offset) & IPV4_HDR_OFFSET_MASK;
	if (offset > 0)
		return napt_inbound_fragment_consecutive(napt, hdr);

	bool rc = false;
	switch (hdr->next_proto_id) {
	case IPPROTO_ICMP:
		rc = napt_inbound_icmp(napt, hdr, (struct icmp_hdr *)l4_hdr);
		break;
	case IPPROTO_UDP:
		rc = napt_inbound_udp(napt, hdr, (struct udp_hdr *)l4_hdr);
		break;
	case IPPROTO_TCP:
		rc = napt_inbound_tcp(napt, hdr, (struct tcp_hdr *)l4_hdr);
		break;
	default:
		break;
	}

	if (rc) {
		// If we successively did NAPT, check for fragment packet.
		// If the packet is the first segment of the fragmented packet,
		// then we must register the packet ID to the hash for further
		// rewrite.
		if ((offset == 0) && (hdr->fragment_offset & htons(IPV4_HDR_MF_FLAG)))
			napt_inbound_fragment_first(napt, hdr);
	} else {
		ROUTER_DEBUG("NAPT: no translation performed");
	}

	return rc;
}
