/*******************************************************************************
 * Copyright 2020 Tremolo Security, Inc.
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

package com.tremolosecurity.mapping;

import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.mapping.CustomMapping;
import com.tremolosecurity.saml.Attribute;

public class DefaultEmail implements CustomMapping {

	@Override
	public Attribute doMapping(User user, String name) {
		Attribute mail = new Attribute(name);
		if (user.getAttribs().get("mail") != null) {
			mail.getValues().add(user.getAttribs().get("mail").getValues().get(0));
		} else {
			mail.getValues().add("none@none.com");
		}
		
		return mail;
	}

	@Override
	public void setParams(String... params) {
		// TODO Auto-generated method stub
		
	}

}
