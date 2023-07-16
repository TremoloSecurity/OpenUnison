/*******************************************************************************
 * Copyright 2016 Tremolo Security, Inc.
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
package com.tremolosecurity.scalejs.token.password;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.provisioning.service.util.TremoloUser;
import com.tremolosecurity.provisioning.service.util.WFCall;
import com.tremolosecurity.proxy.logout.LogoutHandler;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

public class ResetUserPasswordOnLogout implements LogoutHandler {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(ResetUserPasswordOnLogout.class.getName());
	
	String workflow;
	String userID;
	String uidAttributeName;
	
	public ResetUserPasswordOnLogout(String workflow,String uidAttributeName,String userID) {
		this.workflow = workflow;
		this.userID = userID;
		this.uidAttributeName = uidAttributeName;
	}
	
	@Override
	public void handleLogout(HttpServletRequest request, HttpServletResponse response) throws ServletException {
		WFCall wfCall = new WFCall();
		wfCall.setName(this.workflow);
		wfCall.setReason("Logout");
		wfCall.setUidAttributeName(this.uidAttributeName);
		
		TremoloUser tu = new TremoloUser();
		tu.setUid(this.userID);
		tu.getAttributes().add(new Attribute(this.uidAttributeName,this.userID));
		
		wfCall.setUser(tu);
		
		try {
			com.tremolosecurity.provisioning.workflow.ExecuteWorkflow exec = new com.tremolosecurity.provisioning.workflow.ExecuteWorkflow();
			exec.execute(wfCall, GlobalEntries.getGlobalEntries().getConfigManager());
			
		} catch (Exception e) {
			logger.error("Could not update user",e);
			
		}

	}

}
