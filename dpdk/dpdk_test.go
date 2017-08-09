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

package dpdk

import (
	"flag"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

func searchPmdLibrary(path string) []string {
	files, _ := ioutil.ReadDir(path)
	var pmds []string
	path += "/"
	for _, f := range files {
		if strings.HasPrefix(f.Name(), "librte_pmd_") && strings.HasSuffix(f.Name(), ".so") {
			pmds = append(pmds, "-d", path+f.Name())
		}
	}
	return pmds
}

func TestMain(m *testing.M) {
	args := []string{"test", "-v", "-c", "0xff", "-n", "4"}
	args = append(args, searchPmdLibrary("/usr/local/lib")...)
	EalInit(args)

	flag.Parse()
	os.Exit(m.Run())
}
