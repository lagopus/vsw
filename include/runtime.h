/*
 * Copyright 2017 Nippon Telegraph and Telephone Corporation.
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

#ifndef LAGOPUS_RUNTIME_H_
#define LAGOPUS_RUNTIME_H_

#include <stdbool.h>
#include <stdint.h>

#include <rte_ring.h>

struct lagopus_instance {
	uint64_t	id;
	const char	*name;
	bool		enabled;
	struct rte_ring	*input;
	struct rte_ring	*input2;
	struct rte_ring **outputs;
};

struct lagopus_runtime_ops {
	// Initialize the runtime. Called only once at startup time.
	// If the runtime is successively initialized, init shall
	// return non-NULL value. The value is then passed as the first
	// argutment in the subsequent calls.
	void* (*init)(void *param);

	// Dequeue mbufs for each registered instance and process them.
	// Never block. If there's no mbuf to process, just move on.
	// Priv is the value returned by init.
	bool (*process)(void *priv);

	// Terminated the runtime. After this call, the runtime will
	// never be called.
	// Priv is the value returned by init.
	void (*deinit)(void *priv);

	// Register an instance to the runtime.
	// Priv is the value returned by init.
	bool (*register_instance)(void *priv, struct lagopus_instance *instance);

	// Unregister the instance from the runtime.
	// Priv is the value returned by init.
	bool (*unregister_instance)(void *priv, struct lagopus_instance *instance);

	// Update rings for the instance.
	// Rings might have been added or deleted.
	// Priv is the value returned by init.
	bool (*update_rings)(void *priv, struct lagopus_instance *instance);

	// Control the instance. Param is runtime specific.
	// Priv is the value returned by init.
	bool (*control_instance)(void *priv, struct lagopus_instance *instance, void *param);
};

#endif /* LAGOPUS_RUNTIME_H_ */
