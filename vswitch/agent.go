//
// Copyright 2017 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package vswitch

import "fmt"

// Agent defines the interafaces that an agent shall implement.
type Agent interface {
	// Enable the agent.
	// Should return nil on succeess. Error otherwise.
	Enable() error

	// Disable the agent.
	Disable()

	fmt.Stringer
}

var agents = make(map[string]Agent)

// RegisterAgent registers an agent.
// Returns nil on success, error on failure.
func RegisterAgent(agent Agent) error {
	name := agent.String()
	if _, exists := agents[name]; exists {
		return fmt.Errorf("Agent '%s' already exists.\n", name)
	}

	agents[name] = agent
	return nil
}

// GetAgent returns an instance of agent with the given name.
func GetAgent(name string) (Agent, error) {
	agent, ok := agents[name]
	if !ok {
		return nil, fmt.Errorf("Can't find agent '%s'.", name)
	}
	return agent, nil
}

// EnableAgents enables agents listed in names.
// Returns a slice of Agent successively started.
func EnableAgents(names ...string) []Agent {
	var startedAgents []Agent
	for _, name := range names {
		if agent, ok := agents[name]; ok {
			if agent.Enable() == nil {
				startedAgents = append(startedAgents, agent)
			}
		}
	}
	return startedAgents
}
