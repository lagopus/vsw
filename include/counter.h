/*
 * Copyright 2017-2019 Nippon Telegraph and Telephone Corporation.
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

#ifndef VSW_COUNTER_H_
#define VSW_COUNTER_H_

#include <stdint.h>
#include <time.h>

/*
 * Interface counters and statistics.
 *
 * They are adapted from RFC 7223.
 */
struct vsw_counter {
	/**
	 * The total number of octets received on the interface,
	 * including framing characters.
	 */
	uint64_t in_octets;

	/**
	 * The number of packets, delivered by this sub-layer to a
	 * higher (sub-)layer, that were not addressed to a
	 * multicast or broadcast address at this sub-layer.
	 */
	uint64_t in_unicast_pkts;

	/**
	 * The number of packets, delivered by this sub-layer to a
	 * higher (sub-)layer, that were addressed to a broadcast
	 * address at this sub-layer.
	 */
	uint64_t in_broadcast_pkts;

	/**
	 * The number of packets, delivered by this sub-layer to a
	 * higher (sub-)layer, that were addressed to a multicast
	 * address at this sub-layer.  For a MAC-layer protocol,
	 * this includes both Group and Functional addresses.
	 */
	uint64_t in_multicast_pkts;

	/**
	 * The number of inbound packets that were chosen to be
	 * discarded even though no errors had been detected to
	 * prevent their being deliverable to a higher-layer
	 * protocol.  One possible reason for discarding such a
	 * packet could be to free up buffer space.
	 */
	uint64_t in_discards;

	/**
	 * For packet-oriented interfaces, the number of inbound
	 * packets that contained errors preventing them from being
	 * deliverable to a higher-layer protocol.  For character-
	 * oriented or fixed-length interfaces, the number of
	 * inbound transmission units that contained errors
	 * preventing them from being deliverable to a higher-layer
	 * protocol.
	 */
	uint64_t in_errors;

	/**
	 * For packet-oriented interfaces, the number of packets
	 * received via the interface that were discarded because
	 * of an unknown or unsupported protocol.  For
	 * character-oriented or fixed-length interfaces that
	 * support protocol multiplexing, the number of
	 * transmission units received via the interface that were
	 * discarded because of an unknown or unsupported protocol.
	 * For any interface that does not support protocol
	 * multiplexing, this counter is not present.
	 */
	uint32_t in_unknown_protos;

	/**
	 * The total number of octets transmitted out of the
	 * interface, including framing characters.
	 */
	uint64_t out_octets;

	/**
	 * The total number of packets that higher-level protocols
	 * requested be transmitted, and that were not addressed
	 * to a multicast or broadcast address at this sub-layer,
	 * including those that were discarded or not sent.
	 */
	uint64_t out_unicast_pkts;

	/**
	 * The total number of packets that higher-level protocols
	 * requested be transmitted, and that were addressed to a
	 * broadcast address at this sub-layer, including those
	 * that were discarded or not sent.
	 */
	uint64_t out_broadcast_pkts;

	/**
	 * The total number of packets that higher-level protocols
	 * requested be transmitted, and that were addressed to a
	 * multicast address at this sub-layer, including those
	 * that were discarded or not sent.  For a MAC-layer
	 * protocol, this includes both Group and Functional
	 * addresses.
	 */
	uint64_t out_multicast_pkts;

	/**
	 * The number of outbound packets that were chosen to be
	 * discarded even though no errors had been detected to
	 * prevent their being transmitted.  One possible reason
	 * for discarding such a packet could be to free up buffer
	 * space.
	 */
	uint64_t out_discards;

	/**
	 * For packet-oriented interfaces, the number of outbound
	 * packets that could not be transmitted because of errors.
	 * For character-oriented or fixed-length interfaces, the
	 * number of outbound transmission units that could not be
	 * transmitted because of errors.
	 */
	uint64_t out_errors;

	// INTERNAL USE ONLY
	time_t last_clear;
};

#endif /* VSW_COUNTER_H_ */
