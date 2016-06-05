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
package com.tremolosecurity.unison.freeipa.mapping;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.mapping.CustomMapping;
import com.tremolosecurity.saml.Attribute;

public class Upn2Uid implements CustomMapping {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(Upn2Uid.class.getName());
	@Override
	public Attribute doMapping(User user, String name) {
		Attribute upn = user.getAttribs().get("userPrincipalName");
		
		if (upn == null) {
			logger.error("No userPrincipalName for " + user.getUserID());
			return null;
		}
		
		Attribute uid = new Attribute(name,upn.getValues().get(0).replace('@', '.'));
		return uid;
	}

}
