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

package hashlist

import (
	"container/list"
)

type HashList struct {
	elements map[interface{}]*list.Element
	list     *list.List
}

// New creates new hashlist.
func New() *HashList {
	h := &HashList{
		elements: make(map[interface{}]*list.Element),
		list:     list.New(),
	}
	return h
}

// If the key already existed, it replace the value of existing
// entry, move the entry to the end of the list, and returns false.
// Otherwise, add to the end of the list, and returns true.
func (h *HashList) Add(key interface{}, v interface{}) bool {
	if e, ok := h.elements[key]; ok {
		e.Value = v
		h.list.MoveToBack(e)
		return false
	}
	e := h.list.PushBack(v)
	h.elements[key] = e
	return true
}

// Remove removes key from the hashlist.
func (h *HashList) Remove(key interface{}) bool {
	if e, ok := h.elements[key]; ok {
		h.list.Remove(e)
		delete(h.elements, key)
		return true
	}
	// no key found
	return false
}

// Find returns list.Lement for the key.
func (h *HashList) Find(key interface{}) *list.Element {
	return h.elements[key]
}

// List returns list.List of the HashList.
func (h *HashList) List() *list.List {
	return h.list
}

// AllElements returns elements in the HashList.
func (h *HashList) AllElements() map[interface{}]*list.Element {
	return h.elements
}

// Reset resets the HashList.
func (h *HashList) Reset() {
	h.elements = make(map[interface{}]*list.Element)
	h.list.Init()
}
