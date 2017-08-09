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

import (
	"github.com/lagopus/vsw/utils/notifier"
)

var noti *notifier.Notifier

const notificationBuffer = 100

// GetNotifier returns Notifier for the vswitch status changes.
//
// VRF Related
//
// 1. VRF is created:
//      Type: Notifier.Add
//      Target: VrfInfo
//      Value: nil
//
// 2. VRF is deleted (XXX: Not supported yet):
//      Type: Notifier.Delete
//      Target: VrfInfo
//      Value: nil
//
// 3. VIF is added to VRF:
//      Type: Notifier.Add
//      Target: VrfInfo
//      Value: VifInfo
//
// 4. Route is added to VRF:
//	Type: Notifier.Add
//	Target: VrfInfo
//	Value: Route
//
// 5. Route is deleted from VRF:
//	Type: Notifier.Delete
//	Target: VrfInfo
//	Value: Route
//
// VIF Related
//
// 1. VIF is deleted:
//      Type: Notifier.Delete
//      Target: VifInfo
//      Value: nil
//
// 2. MAC Address has been set:
//      Type: Notifier.Update
//      Target: VifInfo
//      Value: net.HardwareAddr
//
// 3. MTU has been set:
//      Type: Notifier.Update
//      Target: VifInfo
//      Value: MTU
//
// 4. IP Address is added:
//      Type: Notifer.Add
//      Target: VifInfo
//      Value: IPAddr
//
// 5. IP Address is deleted:
//      Type: Notifer.Delete
//      Target: VifInfo
//      Value: IPAddr
//
// 6. Prefix of IP Address has changed:
//      Type: Notifer.Update
//      Target: VifInfo
//      Value: IPAddr
//
// 7. Link status has changed:
// 	Type: Notifier.Update
//	Target: VifInfo
//	Value: LinkStatus
//
// 8. Neighbour entry added:
//	Type: Notifier.Add
//	Target: VifInfo
//	Value: Neighbour
//
// 9. Neighbour entry updated:
//	Type: Notifier.Update
//	Target: VifInfo
//	Value: Neighbour
//
// 10. Neighbour entry deleted:
//	Type: Notifier.Delete
//	Target: VifInfo
//	Value: Neighbour
//
func GetNotifier() *notifier.Notifier {
	return noti
}

func init() {
	noti = notifier.NewNotifier(notificationBuffer)
}
