//
// Copyright 2018-2019 Nippon Telegraph and Telephone Corporation.
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
	"io/ioutil"
	"sync"

	"github.com/lagopus/toml"
)

// Config is a central holder of vswitch configuration.
type Config struct {
	mutex sync.Mutex
	path  string
	data  string
}

var config = &Config{}

// GetConfig returns an instance of Config.
func GetConfig() *Config {
	return config
}

// setPath shall be called before Decode by modules or agents.
func (c *Config) setPath(path string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.path != "" {
		return errors.New("Can't change config file path once set.")
	}
	c.path = path

	return nil
}

// Decode decodes configuration based on the given interface v.
// Refer to github.com/BurntSushi/toml for details.
func (c *Config) Decode(v interface{}) (*toml.MetaData, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.data == "" {
		if c.path == "" {
			return nil, errors.New("Configuration file path hasn't been set.")
		}
		data, err := ioutil.ReadFile(c.path)
		if err != nil {
			return nil, err
		}
		c.data = string(data)
	}

	md, err := toml.Decode(c.data, v)
	return &md, err
}
