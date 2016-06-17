/*******************************************************************************
 * Copyright 2016 Tremolo Security, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.tremolosecurity.unison.openshiftv3.model.users;

import java.util.ArrayList;
import java.util.List;

import com.tremolosecurity.unison.openshiftv3.model.Response;

public class User extends Response {
	List<String> identites;
	
	
	public User() {
		super();
		this.identites = new ArrayList<String>();
	}


	public List<String> getIdentites() {
		return identites;
	}


	public void setIdentites(List<String> identites) {
		this.identites = identites;
	}
	
	public String getName() {
		return this.getMetadata().get("name");
	}
	
	public void setName(String val) {
		this.getMetadata().put("name", val);
	}
	
	public String getFullName() {
		return this.getMetadata().get("fullName");
	}
	
	public void setFullName(String val) {
		this.getMetadata().put("fullName", val);
	}
	
	public String getUid() {
		return this.getMetadata().get("uid");
	}
}
