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
#include "radix-tree.h"
#include "router_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * A set data type
 */

struct set {
	void **val;
	int len;
	int cap;
};

#define SET_COUNT(s) ((s)->len)
#define SET_VALUE_AT(s, n) ((s)->val[(n)])

struct set *
set_new() {
	return (struct set *)calloc(1, sizeof(struct set));
}

void
set_free(struct set *set) {
	if (set != NULL) {
		if (set->val != NULL)
			free(set->val);
		free(set);
	}
}

static bool
set_expand(struct set *set, size_t size) {
	int cap = set->cap + size;
	void *p = realloc(set->val, sizeof(void *) * cap);
	if (p == NULL)
		return false;
	set->val = p;
	set->cap = cap;

	return true;
}

bool
set_insert(struct set *set, void *value) {
	/*
	 * Check if we already have duplicated entry.
	 * If so, we simply return true.
	 */
	for (int i = 0; i < set->len; i++)
		if (set->val[i] == value)
			return true;

	/*
	 * Check if we have enough space.
	 */
	if (set->len == set->cap) {
		// XXX: Need better strategy to expand the set.
		if (!set_expand(set, 8))
			return false;
	}

	set->val[set->len++] = value;
	return true;
}

void *
set_value_at(struct set *set, unsigned pos) {
	return (set->len > pos) ? set->val[pos] : NULL;
}

void *
set_get_first(struct set *set) {
	return (set->len > 0) ? set->val[0] : NULL;
}

static bool
set_delete(struct set *set, void *value) {
	for (int i = 0; i < set->len; i++) {
		if (set->val[i] == value) {
			set->len--;
			set->val[i] = set->val[set->len];
			return true;
		}
	}
	return false;
}

static void
set_dump(struct set *set, const char *(*stringer)(void *p)) {
	if (set != NULL) {
		putchar('[');
		for (int i = 0; i < set->len; i++) {
			if (i > 0)
				printf(", ");
			printf("%s", stringer(set->val[i]));
		}
		putchar(']');
	}
}

/*
 * Binary Radix Tree
 */

struct node {
	uint32_t key;
	uint32_t len;
	uint32_t guard;
	struct set *values;
	struct node *parent;
	struct node *nodes[2];
};

struct rt {
	struct node root;
	int ptr;
	int len;
	int n;
	struct set *results[32]; // A place holder enough for results
};

static struct node *
new_node(struct node *p) {
	struct node *node = (struct node *)calloc(1, sizeof(struct node));

	if (node != NULL)
		node->parent = p;

	return node;
}

struct rt *
rt_new() {
	return (struct rt *)calloc(1, sizeof(struct rt));
}

static void
delete_node(struct node *node) {
	if (node != NULL) {
		set_free(node->values);
		free(node);
	}
}

static void
set_node(struct node *node, uint32_t key, uint32_t len) {
	node->len = len;
	node->key = key & 0xffffffffUL << (32 - len);
	node->guard = 0x80000000UL >> len;
}

static struct node *
split_node(struct node *node, uint32_t len, int b) {
	struct node *p = new_node(node->parent);
	set_node(p, node->key, len);
	p->parent->nodes[b] = p;

	set_node(node, node->key << len, node->len - len);
	node->parent = p;

	p->nodes[node->key >> 31] = node;

	return p;
}

static struct node *
merge_node(struct node *p, struct node *c) {
	set_node(c, p->key | (c->key >> p->len), p->len + c->len);

	if (p->parent)
		p->parent->nodes[p->key >> 31] = c;

	c->parent = p->parent;
	delete_node(p);
	return c;
}

static struct node *
check_and_merge_if_needed(struct node *p) {
	if (!p)
		return NULL;

	// this is the root node.
	if (p->parent == NULL)
		return p;

	if ((p->values) && (SET_COUNT(p->values) != 0))
		return p;

	if (p->nodes[0] != NULL && p->nodes[1] == NULL) {
		// squash nodes[0] onto this node
		p = merge_node(p, p->nodes[0]);
	} else if (p->nodes[0] == NULL && p->nodes[1] != NULL) {
		// squash nodes[1] onto this node
		p = merge_node(p, p->nodes[1]);
	}

	return p;
}

static inline int
match_key(struct node *p, uint32_t key) {
	// Set a bit at (p->len + 1) as a guard.
	uint32_t match = (p->key ^ key) | p->guard;

	// GCC document says "If x is 0, the result is undefined."
	// This is due to the fact that x86 without ABM support uses
	// BSR to implement __builtin_clz. If the processor supports
	// ABM, the compiler uses LZCNT which returns 32 when 0 is
	// given.
	//
	// ARMv5 or later also supports CLZ which returns 32 for 0,
	// therefore we can safely pass 0.
#if (defined(__x86_64__) || defined(__i386__)) && !defined(__ABM__)
	return (match == 0) ? 32 : __builtin_clz(match);
#else
	return __builtin_clz(match);
#endif
}

void
rt_free(struct rt *rt) {
	if (!rt)
		return;

	struct node *p = &rt->root;
	while (p) {
		if (p->nodes[0]) {
			p = p->nodes[0];
			continue;
		}
		if (p->nodes[1]) {
			p = p->nodes[1];
			continue;
		}
		struct node *t = p;
		p = p->parent;
		delete_node(t);
	}
	free(rt);
}

struct set *
rt_alloc_node(struct rt *rt, uint32_t key, uint32_t len) {
	struct node *p = &rt->root;

	while (len > 0) {
		int b = key >> 31;

		if (p->nodes[b] == NULL) {
			p->nodes[b] = new_node(p);
			p = p->nodes[b];
			set_node(p, key, len);
			break;
		}

		p = p->nodes[b];

		int matched_len = match_key(p, key);

		if (matched_len == len) {
			// we have to insert value in this node.
			break;
		}

		if (matched_len > len) {
			// we have to split the node.
			//
			// create a new node, and put the value in the new node.
			// the current node becomes the child of the new node.
			p = split_node(p, len, b);
			break;
		}

		if (matched_len < p->len) {
			// we have to split the node.
			//
			// craete a new node.
			// the current node becomes the child of the new node.
			//
			// and continue traversal
			p = split_node(p, matched_len, b);
		}

		// we have to traverse the node
		key <<= p->len;
		len -= p->len;
	}

	if (p->values == NULL && (!(p->values = set_new())))
		return NULL;
	return p->values;
}

bool
rt_insert_key(struct rt *rt, uint32_t key, uint32_t len, void *value) {
	struct set *set = rt_alloc_node(rt, key, len);
	if (set == NULL)
		return false;
	return set_insert(set, value);
}

static inline int
append_result(struct rt *rt, struct node *p) {
	if (p->values) {
		rt->results[rt->len] = p->values;
		rt->len++;
		return SET_COUNT(p->values);
	}
	return 0;
}

int
rt_search_key(struct rt *rt, uint32_t key, uint32_t len) {
	struct node *p = &rt->root;
	int count;

	rt->ptr = rt->len = rt->n = 0;
	count = append_result(rt, p);

	while (len > 0) {
		int b = key >> 31;

		if (p->nodes[b] == NULL)
			break;

		p = p->nodes[b];

		int matched_len = match_key(p, key);

		if (matched_len == len) {
			// exact match
			count += append_result(rt, p);
			break;
		}

		if (matched_len < p->len) {
			// no match
			break;
		}

		count += append_result(rt, p);
		key <<= p->len;
		len -= p->len;
	}

	return count;
}

bool
rt_iterate_results(struct rt *rt, void **value) {
	if (value == NULL || rt->ptr == rt->len)
		return false;

	struct set *set = rt->results[rt->ptr];

	if (rt->n == SET_COUNT(set)) {
		rt->ptr++;
		if (rt->ptr == rt->len)
			return false;
		rt->n = 0;
		set = rt->results[rt->ptr];
	}

	*value = SET_VALUE_AT(set, rt->n);
	rt->n++;

	return true;
}

bool
rt_delete_key(struct rt *rt, uint32_t key, uint32_t len, void *value) {
	struct node *p = &rt->root;

	while (len > 0) {
		int b = key >> 31;

		if (p->nodes[b] == NULL) // no match
			return false;

		p = p->nodes[b];

		int matched_len = match_key(p, key);

		if (matched_len == len) // found the exact match
			break;

		if (matched_len < p->len) // no match
			return false;

		key <<= p->len;
		len -= p->len;
	}

	// now we can delete the value.
	if (!set_delete(p->values, value)) // coudn't find the value
		return false;

	// check if we should delete this node.
	if (SET_COUNT(p->values) == 0) {
		if (p->nodes[0] == NULL && p->nodes[1] == NULL) {
			// no children. this node can be deleted safely.
			if (p->parent != NULL)
				p->parent->nodes[p->key >> 31] = NULL;
			delete_node(p);
		} else {
			p = check_and_merge_if_needed(p);
		}

		check_and_merge_if_needed(p->parent);
	}

	return true;
}

/*
 * dump radix tree
 */

static void
print_key(struct node *node) {
	if (node->len > 0) {
		uint32_t key = node->key;
		for (int i = 0; i < node->len; i++) {
			putchar('0' + (key >> 31));
			key <<= 1;
		}
	} else {
		putchar('*');
	}
	printf("/%d", node->len);
}

static const char *
chp2str(void *p) {
	return (char *)p;
}

static void
dump(struct node *node, int n) {
	if (node != NULL) {
		for (int i = 0; i < n; i++)
			putchar(' ');
		print_key(node);
		printf(": ");
		set_dump(node->values, chp2str);
		putchar('\n');

		if (node->nodes[0])
			dump(node->nodes[0], n + 1);

		if (node->nodes[1])
			dump(node->nodes[1], n + 1);
	}
}

void
rt_dump(struct rt *rt) {
	dump(&rt->root, 0);
}

struct key {
	uint32_t key;
	uint32_t len;
};

struct range {
	struct rt *rt;
	uint32_t min;
	uint32_t max;
	void *value;
	bool (*callback)(struct rt *, uint32_t, uint32_t, void *);
};

static void
do_search_range(struct range *r, struct key *k) {
	uint64_t mask = ~0;
	mask <<= 32 - k->len;
	uint32_t min = k->key & mask;
	uint32_t max = k->key | ~mask;

	// Check if the key is inclusive in the range.
	if (r->min <= min && max <= r->max) {
		// adopt. no need to go down further.
		r->callback(r->rt, k->key, k->len, r->value);
		return;
	}

	// we have to narrow down the range and test
	int b = 1 << (31 - k->len);
	uint32_t median = min + (max - min) / 2;

	if (r->min <= median) {
		struct key k0 = {
		    .key = k->key & ~b,
		    .len = k->len + 1,
		};
		do_search_range(r, &k0);
	}

	if (r->max > median) {
		struct key k1 = {
		    .key = k->key | b,
		    .len = k->len + 1,
		};
		do_search_range(r, &k1);
	}
}

static bool
process_range(struct range *r) {
	if (r->min > r->max)
		return false;

	if (r->min == r->max)
		return r->callback(r->rt, r->min, 32, r->value);

	struct key k = {.key = 0, .len = 0};
	do_search_range(r, &k);

	return true;
}

bool
rt_insert_range(struct rt *rt, uint32_t min, uint32_t max, void *value) {
	struct range r = {
	    .rt = rt,
	    .min = min,
	    .max = max,
	    .value = value,
	    .callback = rt_insert_key,
	};
	return process_range(&r);
}

bool
rt_delete_range(struct rt *rt, uint32_t min, uint32_t max, void *value) {
	struct range r = {
	    .rt = rt,
	    .min = min,
	    .max = max,
	    .value = value,
	    .callback = rt_delete_key,
	};
	return process_range(&r);
}
