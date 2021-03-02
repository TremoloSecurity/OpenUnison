/*******************************************************************************
 * Copyright 2020 Tremolo Security, Inc.
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
package com.tremolosecurity.provisioning.tasks;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;

public class CleanLabels implements CustomTask {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(CleanLabels.class.getName());

	String replacementCharacter;
	String newAttributeSuffix;
	List<String> attributes;
	
	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		this.replacementCharacter = params.get("replacementCharacter").getValues().get(0);
		this.newAttributeSuffix = params.get("newAttributeSuffix").getValues().get(0);
		
		this.attributes = new ArrayList<String>();
		this.attributes.addAll(params.get("attributes").getValues());

	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		

	}

	@Override
	public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
		StringBuilder newAttributeName = new StringBuilder();
		for (String attributeName : this.attributes) {
			if (logger.isDebugEnabled()) {
				logger.debug("Attribute name : '" + attributeName + "'");
			}
			String attributeFromRequest = (String) request.get(attributeName);
			if (logger.isDebugEnabled()) {
				logger.debug("From request : '" + attributeFromRequest + "'");
			}
			if (attributeFromRequest != null) {
				String newAttributeValue = this.cleanLabel(attributeFromRequest);
				if (logger.isDebugEnabled()) {
					logger.debug("New Value : '" + newAttributeValue + "'");
				}
				newAttributeName.setLength(0);
				newAttributeName.append(attributeName).append(this.newAttributeSuffix);
				if (logger.isDebugEnabled()) {
					logger.debug("new name : '" + newAttributeName + "'");
				}
				request.put(newAttributeName.toString(),newAttributeValue);
			}
			
		}
		return true;
	}
	
	private  String cleanLabel(String label) {
		StringBuilder newLabel = new StringBuilder();
		for (Character c : label.toCharArray()) {
			if (c == '.' || c == '-' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
				newLabel.append(c);
			} else {
 				newLabel.append(this.replacementCharacter);
 			}
			
			
		}
		
		char firstChar = newLabel.charAt(0);
		if (! Character.isAlphabetic(firstChar) && ! Character.isDigit(firstChar)) {
			newLabel.insert(0, 'x');
		}
		
		char lastChar = newLabel.charAt(newLabel.length() - 1);
		if (! Character.isAlphabetic(lastChar) && ! Character.isDigit(firstChar)) {
			newLabel.append('x');
		}
		
		return newLabel.toString();
		
	}

}
