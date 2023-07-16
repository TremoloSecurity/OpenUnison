/*
Copyright 2015, 2016 Tremolo Security, Inc.

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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.logging.log4j.Logger;

import com.google.gson.Gson;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.service.util.ProvisioningError;
import com.tremolosecurity.provisioning.service.util.ProvisioningResult;
import com.tremolosecurity.provisioning.service.util.WFCall;
import com.tremolosecurity.provisioning.workflow.ApprovalData;
import com.tremolosecurity.provisioning.workflow.Approvals;
import com.tremolosecurity.server.GlobalEntries;


public class ExecuteWorkflow extends HttpServlet {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(ExecuteWorkflow.class.getName());
	
	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		Gson gson = new Gson();
		String wfcall = req.getParameter("wfcall");
		if (wfcall == null) {
			logger.error("Could not get workflow call");
			resp.setStatus(500);
			ProvisioningError pe = new ProvisioningError();
			ProvisioningResult pres = new ProvisioningResult();
			pres.setSuccess(false);
			pres.setError(pe);
			pe.setError("Could not get workflow call");
			gson = new Gson();
			resp.getOutputStream().print(gson.toJson(pres));
			return;
		}
		
		String line;
		StringBuffer json = new StringBuffer();
		BufferedReader in = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(wfcall.getBytes("UTF-8"))));
		while ((line = in.readLine()) != null) {
			json.append(line).append('\n');
		}
		
		
		
		
		
		WFCall wfCall = gson.fromJson(json.toString(), WFCall.class);
		
		if (wfCall == null) {
			logger.error("Could not get workflow call");
			resp.setStatus(500);
			ProvisioningError pe = new ProvisioningError();
			pe.setError("Could not get workflow call");
			ProvisioningResult pres = new ProvisioningResult();
			pres.setSuccess(false);
			pres.setError(pe);
			gson = new Gson();
			resp.getOutputStream().print(gson.toJson(pres));
			return;
		}
		
		List<ApprovalData> autoApprovals = null;
		
		
		
		try {
			
			//TremoloContext.getContext().getConfigManager("proxy").getProvisioningEngine().getWorkFlow(wfCall.getName()).executeWorkflow(wfCall);
			com.tremolosecurity.provisioning.workflow.ExecuteWorkflow exec = new com.tremolosecurity.provisioning.workflow.ExecuteWorkflow();
			exec.execute(wfCall, GlobalEntries.getGlobalEntries().getConfigManager());
			ProvisioningResult res = new ProvisioningResult();
			res.setSuccess(true);
			resp.getOutputStream().print(gson.toJson(res));
		} catch (Throwable t) {
			logger.error("Error executing workflow",t);
			resp.setStatus(500);
			ProvisioningError pe = new ProvisioningError();
			pe.setError("Error executing workflow");
			ProvisioningResult pres = new ProvisioningResult();
			pres.setSuccess(false);
			pres.setError(pe);
			gson = new Gson();
			resp.getOutputStream().print(gson.toJson(pres));
		}
		
		
	}

}
