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

import "sync"

type Bridge struct {
	bridgeId   int
	bridgeInfo *BridgeInfo
	vifs       []*Vif
}

type BridgeInfo struct {
	br *Bridge
	*IPAddrs
}

var bridgeMutex sync.Mutex
var bridgeCount = 0

func newBridge() *BridgeInfo {
	bridgeMutex.Lock()
	defer bridgeMutex.Unlock()

	var bridge *Bridge
	if bridgeCount < BridgeMaxID {
		bridgeCount++
		bridge = &Bridge{bridgeId: bridgeCount}
		bridge.bridgeInfo = &BridgeInfo{
			br:      bridge,
			IPAddrs: newIPAddrs(bridge.bridgeInfo),
		}
	}
	return bridge.bridgeInfo
}

func (b *Bridge) addVIF(vif *Vif) {
	b.vifs = append(b.vifs, vif)
}

func (bi *BridgeInfo) BridgeID() int {
	return bi.br.bridgeId
}
