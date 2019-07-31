//
// Copyright 2017-2019 Nippon Telegraph and Telephone Corporation.
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

import (
	"errors"
	"fmt"
	"sync"
)

//
// TOML Config
//
type agentConfigSection struct {
	Agents agentConfig
}

type agentConfig struct {
	Enable []string
}

// Agent defines the interafaces that an agent shall implement.
type Agent interface {
	// Enable the agent.
	// Should return nil on succeess. Error otherwise.
	Enable() error

	// Disable the agent.
	Disable()

	fmt.Stringer
}

// AgentInitilizer is implemented by any agent that implement Init method.
// The Init method should return error on failure, and nil if succeeded.
// After returning from the Init method successively, it is expected that
// the agent is ready to be enabled with Enable method defined in type Agent.
// If the agent failed to initialize successively, i.e. returned an error,
// the agent will be deregistered.
type AgentInitializer interface {
	Init() error
}

type agentManager struct {
	config      agentConfigSection
	agents      map[string]Agent
	enabled     map[string]Agent
	once        sync.Once
	initialized bool
}

var agntMgr = &agentManager{
	agents:  make(map[string]Agent),
	enabled: make(map[string]Agent),
}

// RegisterAgent registers an agent.
// Returns nil on success, error on failure.
func RegisterAgent(agent Agent) error {
	name := agent.String()
	if _, exists := agntMgr.agents[name]; exists {
		return fmt.Errorf("Agent '%s' already exists.\n", name)
	}

	agntMgr.agents[name] = agent
	return nil
}

// GetAgent returns an instance of agent with the given name.
func GetAgent(name string) (Agent, error) {
	agent, ok := agntMgr.agents[name]
	if !ok {
		return nil, fmt.Errorf("No such agent")
	}
	return agent, nil
}

// EnableAgent enables an agent.
// Returns nil if success. Otherwise, error is returned.
func EnableAgent(name string) error {
	if _, ok := agntMgr.enabled[name]; ok {
		return nil
	}

	agent, err := GetAgent(name)
	if err != nil {
		return err
	}

	if err := agent.Enable(); err != nil {
		return err
	}

	agntMgr.enabled[name] = agent
	return nil
}

// DisableAgent disables an agent.
func DisableAgent(name string) {
	agent, ok := agntMgr.enabled[name]
	if !ok {
		return
	}
	agent.Disable()
	delete(agntMgr.enabled, name)
}

// EnabledAgents returns agents that are up and running.
func EnabledAgents() []Agent {
	var agents []Agent
	for _, agent := range agntMgr.enabled {
		agents = append(agents, agent)
	}
	return agents
}

// RegisteredAgents returns agents that are registered.
func RegisteredAgents() []Agent {
	var agents []Agent
	for _, agent := range agntMgr.agents {
		agents = append(agents, agent)
	}
	return agents
}

func initAgents() {
	agntMgr.once.Do(func() {
		for name, agent := range agntMgr.agents {
			if ai, ok := agent.(AgentInitializer); ok {
				logger.Info("Initializing %s...", name)
				if err := ai.Init(); err != nil {
					logger.Err("Failed to initialize %s. Deregistered. (%v)", name, err)
					delete(agntMgr.agents, name)
				} else {
					logger.Info("%s initialized successively.", name)
				}
			}
		}
		agntMgr.initialized = true
	})
}

func enableAgents() error {
	if !agntMgr.initialized {
		return errors.New("Agents not initialized!")
	}

	if _, err := GetConfig().Decode(&agntMgr.config); err != nil {
		return fmt.Errorf("Can't parse [agents]: %v", err)
	}

	for _, agent := range agntMgr.config.Agents.Enable {
		if err := EnableAgent(agent); err == nil {
			logger.Info("%s agent started", agent)
		} else {
			logger.Err("Can't start agent %s: %v", agent, err)
		}
	}

	return nil
}

func disableAgents() {
	for name := range agntMgr.enabled {
		DisableAgent(name)
	}
}
