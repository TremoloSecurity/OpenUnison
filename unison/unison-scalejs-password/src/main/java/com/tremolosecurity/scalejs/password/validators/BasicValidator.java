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

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.scalejs.password.sdk.PasswordValidator;


public class BasicValidator implements PasswordValidator {
	int minChars;
	int maxChars;
	int minReqs;

	boolean requireUpper;
	boolean requireLower;
	boolean requireNumber;
	boolean requireSpecial;

	@Override
	public void init(HashMap<String, Attribute> initParams) throws Exception {
		Attribute attr = initParams.get("minChars");
		if (attr == null) {
			this.minChars = 0;
		} else {
			this.minChars = Integer.parseInt(attr.getValues().get(0));
		}

		attr = initParams.get("maxChars");
		if (attr == null) {
			this.maxChars = -1;
		} else {
			this.maxChars = Integer.parseInt(attr.getValues().get(0));
		}

		attr = initParams.get("requireLower");
		if (attr == null) {
			this.requireLower = true;
		} else {
			this.requireLower = attr.getValues().get(0).equalsIgnoreCase("true");
		}

		attr = initParams.get("requireUpper");
		if (attr == null) {
			this.requireUpper = true;
		} else {
			this.requireUpper = attr.getValues().get(0).equalsIgnoreCase("true");
		}
		
		attr = initParams.get("requireNumber");
		if (attr == null) {
			this.requireNumber = true;
		} else {
			this.requireNumber = attr.getValues().get(0).equalsIgnoreCase("true");
		}

		attr = initParams.get("requireSpecial");
		if (attr == null) {
			this.requireSpecial = true;
		} else {
			this.requireSpecial = attr.getValues().get(0).equalsIgnoreCase("true");
		}

		attr = initParams.get("minRequirements");
		if (attr == null) {
			this.minReqs = -1;
		} else {
			this.minReqs = Integer.parseInt(attr.getValues().get(0));
		}

	}

	@Override
	public List<String> validate(String password, AuthInfo user) throws ProvisioningException {
		ArrayList<String> errors = new ArrayList<String>();

		if (password.length() < this.minChars) {
			errors.add("Password must be at least " + this.minChars
					+ " characters long");
			return errors;
		}

		if (this.maxChars > -1 && password.length() > this.maxChars) {
			errors.add("Password can not be more then " + this.maxChars
					+ " characters long");
			return errors;
		}

		boolean hasLower = false;
		boolean hasUpper = false;
		boolean hasSpecial = false;
		boolean hasNumber = false;

		int numReqs = 0;

		for (char c : password.toCharArray()) {
			if (Character.isLowerCase(c)) {
				if (! hasLower) {
					hasLower = true;
					numReqs++;
				}
			} else if (Character.isUpperCase(c)) {
				if (! hasUpper) {
					hasUpper = true;
					numReqs++;
				}
			} else if (Character.isDigit(c)) {
				if (! hasNumber) {
					hasNumber = true;
					numReqs++;
				}
			} else {
				if (! hasSpecial) {
					hasSpecial = true;
					numReqs++;
				}
			}
		}

		if (this.minReqs == 0) {
			checkForErrors(errors, hasLower, hasUpper, hasSpecial, hasNumber);
		} else {
			if (numReqs < this.minReqs) {
				StringBuffer b = new StringBuffer();
				b.append("At least " + this.minReqs + " of ");
				if (this.requireLower) {
					b.append("lower case character,");
				}

				if (this.requireUpper) {
					b.append("upper case character,");
				}

				if (this.requireNumber) {
					b.append("numeric character,");
				}

				if (this.requireSpecial) {
					b.append("special character,");
				}
				errors.add(b.toString().substring(0, b.toString().length() - 1));
				checkForErrors(errors, hasLower, hasUpper, hasSpecial,
						hasNumber);
			}
		}

		return errors;

	}

	private void checkForErrors(ArrayList<String> errors, boolean hasLower,
			boolean hasUpper, boolean hasSpecial, boolean hasNumber) {
		if (this.requireLower && !hasLower) {
			errors.add("At least one lowercase letter is required");
		}

		if (this.requireUpper && !hasUpper) {
			errors.add("At least one uppercase letter is required");
		}

		if (this.requireNumber && !hasNumber) {
			errors.add("At least one number is required");
		}

		if (this.requireSpecial && !hasSpecial) {
			errors.add("At least one non-alphanumeric character is required");
		}
	}

}

