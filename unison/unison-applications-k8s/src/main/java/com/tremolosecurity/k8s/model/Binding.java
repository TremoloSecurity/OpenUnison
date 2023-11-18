/*******************************************************************************
 * Copyright (c) 2023 Tremolo Security, Inc.
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
package com.tremolosecurity.k8s.model;

public class Binding {

	boolean namespaced;
	String name;
	String namespace;
	
	String target;
	
	String bindingName;
	
	public Binding() {
		
	}
	
	public Binding(String name,boolean namespaced,String namespace,String target, String bindingName) {
		this.name = name;
		this.namespaced = namespaced;
		this.namespace = namespace;
		this.bindingName = bindingName;
		this.target = target;
	}
	
	public boolean isNamespaced() {
		return namespaced;
	}
	public void setNamespaced(boolean namespaced) {
		this.namespaced = namespaced;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getNamespace() {
		return namespace;
	}
	
	public void setNamespace(String namespace) {
		this.namespace = namespace;
	}

	public String getTarget() {
		return target;
	}

	public void setTarget(String target) {
		this.target = target;
	}

	public String getBindingName() {
		return bindingName;
	}

	public void setBindingName(String bindingName) {
		this.bindingName = bindingName;
	}
	
	
	
	
}
