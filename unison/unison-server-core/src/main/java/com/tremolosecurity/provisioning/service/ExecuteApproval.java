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


package com.tremolosecurity.provisioning.service;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

import com.google.gson.Gson;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.service.util.ProvisioningError;
import com.tremolosecurity.provisioning.service.util.ProvisioningResult;
import com.tremolosecurity.server.GlobalEntries;


public class ExecuteApproval extends HttpServlet {

	static Logger logger = Logger.getLogger(ExecuteApproval.class.getName());
	
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		int approvalID = Integer.parseInt(req.getParameter("approvalID"));
		String approver = req.getParameter("approver");
		boolean approved = Boolean.parseBoolean(req.getParameter("approved"));
		String reason = req.getParameter("reason");
		Gson gson = new Gson();
		
		try {
			GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().doApproval(approvalID, approver, approved,reason);
			
			ProvisioningResult res = new ProvisioningResult();
			res.setSuccess(true);
			resp.getOutputStream().print(gson.toJson(res));
		} catch (ProvisioningException e) {
			logger.error("Could not execute approval",e);
			resp.setStatus(500);
			ProvisioningError pe = new ProvisioningError();
			pe.setError("Could not execute approval;" + e.getMessage());
			ProvisioningResult resObj = new ProvisioningResult();
			resObj.setSuccess(false);
			resObj.setError(pe);
			gson = new Gson();
			resp.getOutputStream().print(gson.toJson(resObj));
		}
	}

}
