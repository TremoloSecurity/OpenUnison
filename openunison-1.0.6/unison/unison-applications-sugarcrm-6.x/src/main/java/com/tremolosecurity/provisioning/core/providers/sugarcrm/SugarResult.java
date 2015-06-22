/*
Copyright 2015 Tremolo Security, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


package com.tremolosecurity.provisioning.core.providers.sugarcrm;
import java.util.List;


public class SugarResult {
	int result_count;
	int next_offset;
	List<SugarContactEntry> entry_list;
	List<Object> relationship_list;
	public int getResult_count() {
		return result_count;
	}
	public void setResult_count(int result_count) {
		this.result_count = result_count;
	}
	public int getNext_offset() {
		return next_offset;
	}
	public void setNext_offset(int next_offset) {
		this.next_offset = next_offset;
	}
	public List<SugarContactEntry> getEntry_list() {
		return entry_list;
	}
	public void setEntry_list(List<SugarContactEntry> entry_list) {
		this.entry_list = entry_list;
	}
	public List<Object> getRelationship_list() {
		return relationship_list;
	}
	public void setRelationship_list(List<Object> relationship_list) {
		this.relationship_list = relationship_list;
	}
	
	
}
