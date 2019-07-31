//
// Copyright 2019 Nippon Telegraph and Telephone Corporation.
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
package config

import (
	"encoding/json"
	"fmt"
)

// msg conforms to JSend.
// See https://labs.omniti.com/labs/jsend for more details.
type msg struct {
	Status  Status      `json:"status"`
	Data    interface{} `json:"data,omitempty"`
	Message string      `json:"message,omitempty"`
}

type Status int

const (
	Success Status = iota
	Fail
	Error
)

func (s Status) MarshalJSON() ([]byte, error) {
	var b []byte
	switch s {
	case Success:
		b = []byte(`"success"`)
	case Fail:
		b = []byte(`"fail"`)
	case Error:
		b = []byte(`"error"`)
	}
	return b, nil
}

var internalErrMsg = `{
	"status": "error",
	"message": "Internal Error"
}`

func outputResult(data interface{}) string {
	return outputJSON(&msg{Status: Success, Data: data})
}

func outputErr(f string, args ...interface{}) string {
	return outputJSON(&msg{Status: Error, Message: fmt.Sprintf(f, args...)})
}

func outputJSON(msg *msg) string {
	b, err := json.MarshalIndent(msg, "", "\t")
	if err != nil {
		log.Err("json.MarshalIndent failed: %v", err)
		return internalErrMsg
	}

	return string(b)
}
