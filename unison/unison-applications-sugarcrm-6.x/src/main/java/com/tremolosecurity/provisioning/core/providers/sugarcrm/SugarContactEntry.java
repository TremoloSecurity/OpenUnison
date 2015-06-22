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

import com.tremolosecurity.util.NVP;


public class SugarContactEntry {
	String id;
	String session;
	String module_name;
	Map<String,NVP> name_value_list;
	
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
	public Map<String, NVP> getName_value_list() {
		return name_value_list;
	}
	public void setName_value_list(Map<String, NVP> name_value_list) {
		this.name_value_list = name_value_list;
	}
	public String getId() {
		return id;
	}
	public void setId(String id) {
		this.id = id;
	}
	
	
	
}
