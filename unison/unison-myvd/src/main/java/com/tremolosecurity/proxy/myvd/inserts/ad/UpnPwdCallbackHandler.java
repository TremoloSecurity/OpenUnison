/*
Copyright 2015 Tremolo Security, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


package com.tremolosecurity.proxy.myvd.inserts.ad;
import java.io.IOException;


import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextOutputCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.logging.log4j.Logger;


public class UpnPwdCallbackHandler implements CallbackHandler {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(UpnPwdCallbackHandler.class.getName());
	
	String upn;
	String password;
	
	public UpnPwdCallbackHandler(String upn,byte[] password) {
		this.upn = upn;
		this.password = new String(password);
	}
	
	@Override
	public void handle(Callback[] callbacks) throws IOException,
			UnsupportedCallbackException {
		
		for (Callback callback : callbacks) {
			if (callback instanceof TextOutputCallback) {
				 TextOutputCallback tc = (TextOutputCallback) callback;
				 switch (tc.getMessageType()) {
				 	case TextOutputCallback.INFORMATION: logger.info(tc.getMessage()); break;
				 	case TextOutputCallback.ERROR: logger.error(tc.getMessage()); break;
				 	case TextOutputCallback.WARNING: logger.warn(tc.getMessage()); break;
				 }
			} else if (callback instanceof NameCallback) {
				NameCallback nc = (NameCallback) callback;
				nc.setName(upn);
			} else if (callback instanceof PasswordCallback) {
				PasswordCallback pc = (PasswordCallback) callback;
				pc.setPassword(this.password.toCharArray());
			}
		}

	}

}
