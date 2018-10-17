/*******************************************************************************
 * Copyright 2018 Tremolo Security, Inc.
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

package com.tremolosecurity.myvd.dataObj;

import java.util.List;

public class K8sUser {
	String sub;
	String firstName;
	String lastName;
	String email;
	String uid;
	
	List<String> groups;
	
	public K8sUser() {
		
	}

	public String getSub() {
		return sub;
	}

	public void setSub(String sub) {
		this.sub = sub;
	}

	public String getFirstName() {
		return firstName;
	}

	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}

	public String getLastName() {
		return lastName;
	}

	public void setLastName(String lastName) {
		this.lastName = lastName;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public List<String> getGroups() {
		return groups;
	}

	public void setGroups(List<String> groups) {
		this.groups = groups;
	}

	public String getUid() {
		return uid;
	}

	public void setUid(String uid) {
		this.uid = uid;
	}
	
	public static String sub2uid(String sub) {
		StringBuilder uid = new StringBuilder();
		for (Character c : sub.toCharArray()) {
			if (c == '.' || c == '-' || (c >= 'a' && c <= 'z')) {
				uid.append(c);
			} else if (c >= 'A' && c <= 'Z') {
 				uid.append(Character.toLowerCase(c));
 			} else {
 				uid.append("x-").append(String.valueOf((int) c.charValue())).append("-x");
 			}
			
			
		}
		
		
		
		return uid.toString();
		
	}
}
