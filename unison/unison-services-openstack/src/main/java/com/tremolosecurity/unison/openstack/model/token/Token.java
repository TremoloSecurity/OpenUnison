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
package com.tremolosecurity.unison.openstack.model.token;

import java.util.ArrayList;
import java.util.List;

import com.tremolosecurity.unison.openstack.model.KSUser;

public class Token {
	String issued_at;
	List<String> audit_ids;
	List<String> methods;
	String expires_at;
	KSUser user;
	
	public Token() {
		this.methods = new ArrayList<String>();
		this.audit_ids = new ArrayList<String>();
	}
}
