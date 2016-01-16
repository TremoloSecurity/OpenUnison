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
import java.util.Map;


public class SugarEntry {
	String session;
	String module_name;
	Map<String,String> name_value_list;
	
	public String getSession() {
		return session;
	}
	public void setSession(String session) {
		this.session = session;
	}
	public String getModule() {
		return module_name;
	}
	public void setModule(String module) {
		this.module_name = module;
	}
	public Map<String, String> getName_value_list() {
		return name_value_list;
	}
	public void setName_value_list(Map<String, String> name_value_list) {
		this.name_value_list = name_value_list;
	}
	
	
}
