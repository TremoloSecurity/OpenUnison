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
package com.tremolosecurity.unison.openstack.model;

public class Role {
	String name;
	String scope;
	String domain;
	String project;
	
	
	public Role() {
		
	}
	
	public Role(String name,String scope,String domain) {
		this(name,scope,domain,null);
	}
	
	public Role(String name,String scope,String domain,String project) {
		this.name = name;
		this.scope = scope;
		this.domain = domain;
		this.project = project;
	}
	
	public String getName() {
		return name;
	}




	public void setName(String name) {
		this.name = name;
	}




	




	public String getScope() {
		return scope;
	}




	public void setScope(String scope) {
		this.scope = scope;
	}




	public String getDomain() {
		return domain;
	}




	public void setDomain(String domain) {
		this.domain = domain;
	}




	public String getProject() {
		return project;
	}




	public void setProject(String project) {
		this.project = project;
	}




	@Override
	public boolean equals(Object o) {
		Role r = (Role) o;
		return this.name.equalsIgnoreCase(r.getName()) &&
				this.scope.equalsIgnoreCase(r.getScope()) &&
				this.domain.equalsIgnoreCase(r.getDomain()) &&
				((this.project == null && r.getProject() == null) || (this.project.equalsIgnoreCase(r.getProject())));
	}

	@Override
	public int hashCode() {
		StringBuffer b = new StringBuffer();
		b.append(this.name).append(this.scope).append(this.domain);
		if (project != null) {
			b.append(project);
		}
		
		return b.toString().hashCode();
		
	}
	
	
}
