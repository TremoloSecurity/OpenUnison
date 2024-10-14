/*******************************************************************************
 * Copyright (c) 2024 Tremolo Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.tremolosecurity.myvd.dataObj;

import java.util.Comparator;

import org.json.simple.JSONObject;

import com.google.common.collect.ComparisonChain;

public class RoleInfo {
	String name;
	String cluster;
	String namespace;
	
	
	public RoleInfo() {
		
	}
	
	public RoleInfo(String name,String cluster, String namespace) {
		this.name = name;
		this.cluster = cluster;
		this.namespace = namespace;
	}
	
	
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getCluster() {
		return cluster;
	}
	public void setCluster(String cluster) {
		this.cluster = cluster;
	}
	public String getNamespace() {
		return namespace;
	}
	public void setNamespace(String namespace) {
		this.namespace = namespace;
	}
	
	
	
	public JSONObject toJSON() {
		JSONObject obj = new JSONObject();
		obj.put("Cluster", this.cluster);
		obj.put("Namespace",this.namespace);
		obj.put("Name", this.name);
		
		return obj;
	}
	
	@Override
	public int hashCode() {
		return this.toJSON().hashCode();
	}
	
	@Override
	public boolean equals(Object ri) {
		if (! (ri instanceof RoleInfo)) {
			return false;
		}
		
		return this.toJSON().equals(((RoleInfo)ri).toJSON());
	}

	
	
	
}
