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
package com.tremolosecurity.scalejs.password.validators;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.saml.Attribute;

public class ActiveDirectoryValidator extends BasicValidator {
	Map<String,String> attrsToCheck;
	
	@Override
	public void init(HashMap<String, Attribute> initParams) throws Exception {
		super.init(initParams);
		this.attrsToCheck = new HashMap<String,String>();
		Attribute attr = initParams.get("attributesToCheck");
		if (attr != null) {
			for (String v : attr.getValues()) {
				String label = v.substring(0,v.indexOf('='));
				String name = v.substring(v.indexOf('=') + 1);
				this.attrsToCheck.put(name, label);
			}
		}
	}

	@Override
	public List<String> validate(String password, AuthInfo user) throws ProvisioningException {
		List<String> errors =  super.validate(password, user);
		for (String attrName : this.attrsToCheck.keySet()) {
			String attrLabel = this.attrsToCheck.get(attrName);
			Attribute attr = user.getAttribs().get(attrName);
			if (attr != null) {
				if (this.hasWord(attr.getValues().get(0), password)) {
					errors.add("Your new password must not contain more then 3 consecutive characters from your " + attrLabel);
				}
			}
			
			
		}
		
		return errors;
	}
	
	private boolean hasWord(String val,String password) {
		val = val.toLowerCase();
		password = password.toLowerCase();
		
		
		for (int i=0;(i<val.length()-3);i++) {
			if (password.contains(val.subSequence(i, i + 3))) {
				
				return true;
			}
		}
		
		return false;
	}

}

