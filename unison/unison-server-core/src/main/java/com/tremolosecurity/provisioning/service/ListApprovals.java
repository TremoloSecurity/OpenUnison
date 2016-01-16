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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;

import com.cedarsoftware.util.io.JsonReader;
import com.google.gson.Gson;
import com.tremolosecurity.config.xml.WorkflowType;
import com.tremolosecurity.json.Token;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.service.util.ApprovalDetails;
import com.tremolosecurity.provisioning.service.util.ApprovalSummaries;
import com.tremolosecurity.provisioning.service.util.ApprovalSummary;
import com.tremolosecurity.provisioning.service.util.ProvisioningError;
import com.tremolosecurity.provisioning.service.util.ProvisioningResult;
import com.tremolosecurity.provisioning.service.util.ServiceActions;
import com.tremolosecurity.server.GlobalEntries;


public class ListApprovals extends HttpServlet {

	static Logger logger = Logger.getLogger(ListApprovals.class.getName());
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		
		String approver = req.getParameter("approver");
		int approvalID = Integer.parseInt(req.getParameter("approvalID"));
		Connection con = null;
		
		Gson gson = new Gson();
		
		if (approvalID == 0) {
			//list all approvals
			try {
				
				ProvisioningResult pres = new ProvisioningResult();
				pres.setSuccess(true);
				pres.setSummaries(ServiceActions.listOpenApprovals(approver));
				resp.getOutputStream().print(gson.toJson(pres));
				
				
				
			} catch (ProvisioningException e) {
				ProvisioningError pe = new ProvisioningError();
				pe.setError("Could not load executed workflows : " + e.getMessage());
				ProvisioningResult res = new ProvisioningResult();
				res.setSuccess(false);
				res.setError(pe);
				
				
				resp.getWriter().write(gson.toJson(res));
			} finally {
				if (con != null) {
					try {
						con.close();
					} catch (SQLException e) {
				
					}
				}
			}
			
		} else {
			try {
				
				
				ProvisioningResult pres = new ProvisioningResult();
				pres.setSuccess(true);
				pres.setApprovalDetail(ServiceActions.loadApprovalDetails(approver, approvalID));
				
				
				
				resp.getOutputStream().print(gson.toJson(pres));
				
			} catch (Throwable e) {
				logger.error("Could not load approval",e);
				ProvisioningError pe = new ProvisioningError();
				pe.setError("Could not load executed approval : " + e.getMessage());
				ProvisioningResult res = new ProvisioningResult();
				res.setSuccess(false);
				res.setError(pe);
				
				
				
				resp.getWriter().write(gson.toJson(res));
			} finally {
				if (con != null) {
					try {
						con.close();
					} catch (SQLException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			}
		}
		
	}

}
