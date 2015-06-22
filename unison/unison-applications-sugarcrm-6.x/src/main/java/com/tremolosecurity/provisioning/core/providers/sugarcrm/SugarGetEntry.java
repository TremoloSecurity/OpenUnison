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
import java.util.Map;


public class SugarGetEntry {
	String session;
	String module_name;
	String id;
	List<String> select_fields;
	Map<String,List<String>> link_name_to_fields_array;
	
	
	public String getSession() {
		return session;
	}
	public void setSession(String session) {
		this.session = session;
	}
	public String getModule_name() {
		return module_name;
	}
	public void setModule_name(String module_name) {
		this.module_name = module_name;
	}
	public String getId() {
		return id;
	}
	public void setId(String id) {
		this.id = id;
	}
	public List<String> getSelect_fields() {
		return select_fields;
	}
	public void setSelect_fields(List<String> select_fields) {
		this.select_fields = select_fields;
	}
	public Map<String, List<String>> getLink_name_to_fields_array() {
		return link_name_to_fields_array;
	}
	public void setLink_name_to_fields_array(
			Map<String, List<String>> link_name_to_fields_array) {
		this.link_name_to_fields_array = link_name_to_fields_array;
	}
	
	
}
