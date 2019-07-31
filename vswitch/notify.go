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
	"github.com/lagopus/vsw/utils/notifier"
)

var noti = notifier.NewNotifier(notificationBuffer)

const notificationBuffer = 100

// GetNotifier returns Notifier for the vswitch status changes.
//
// VRF Related
//
// 1. VRF is created:
//      Type: Notifier.Add
//      Target: *VRF
//      Value: nil
//
// 2. VRF is deleted (XXX: Not supported yet):
//      Type: Notifier.Delete
//      Target: *VRF
//      Value: nil
//
// 3. VIF is added to VRF:
//      Type: Notifier.Add
//      Target: *VRF
//      Value: *VIF
//
// 4. VIF is deleted from VRF:
//      Type: Notifier.Delete
//      Target: *VRF
//      Value: *VIF
//
// 5. Route is added to VRF:
//	Type: Notifier.Add
//	Target: *VRF
//	Value: Route
//
// 6. Route is deleted from VRF:
//	Type: Notifier.Delete
//	Target: *VRF
//	Value: Route
//
// VIF Related
//
// 1. VIF is deleted:
//      Type: Notifier.Delete
//      Target: *VIF
//      Value: nil
//
// 2. MTU has been set:
//      Type: Notifier.Update
//      Target: *VIF
//      Value: MTU
//
// 3. IP Address is added:
//      Type: Notifer.Add
//      Target: *VIF
//      Value: IPAddr
//
// 4. IP Address is deleted:
//      Type: Notifer.Delete
//      Target: *VIF
//      Value: IPAddr
//
// 5. Prefix of IP Address has changed:
//      Type: Notifer.Update
//      Target: *VIF
//      Value: IPAddr
//
// 6. VIF enabled or disabled
// 	Type: Notifier.Update
//	Target: *VIF
//	Value: bool
//
// 7. Neighbour entry added:
//	Type: Notifier.Add
//	Target: *VIF
//	Value: Neighbour
//
// 8. Neighbour entry updated:
//	Type: Notifier.Update
//	Target: *VIF
//	Value: Neighbour
//
// 9. Neighbour entry deleted:
//	Type: Notifier.Delete
//	Target: *VIF
//	Value: Neighbour
//
// 10. MAC Address has changed:
//	Type: Notifier.Update
//	Target: *VIF
//	Value: net.HardwareAddr
//
// 11. PBR Entry added:
//	Type: Notifier.Add
//	Target: *VRF
//	Value: PBREntry
//
// 12. PBR Entry deleted:
//	Type: Notifier.Delete
//	Target: *VRF
//	Value: PBREntry
//
func GetNotifier() *notifier.Notifier {
	return noti
}
