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
package com.tremolosecurity.unison.openshiftv3.model;

import java.util.ArrayList;
import java.util.HashMap;

public class List<T extends Item> extends Response {
	java.util.List<T> items;
	
	public List() {
		super();
		
		this.items = new ArrayList<T>();
	}

	public java.util.List<T> getItems() {
		return items;
	}

	public void setItems(java.util.List<T> items) {
		this.items = items;
	}

	

	
}
