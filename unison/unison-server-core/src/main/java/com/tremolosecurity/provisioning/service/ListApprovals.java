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
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.service.util.ApprovalDetails;
import com.tremolosecurity.provisioning.service.util.ApprovalSummaries;
import com.tremolosecurity.provisioning.service.util.ApprovalSummary;
import com.tremolosecurity.provisioning.service.util.ProvisioningError;
import com.tremolosecurity.provisioning.service.util.ProvisioningResult;
import com.tremolosecurity.server.GlobalEntries;


public class ListApprovals extends HttpServlet {

	static Logger logger = Logger.getLogger(ListApprovals.class.getName());
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		
		String approver = req.getParameter("approver");
		int approvalID = Integer.parseInt(req.getParameter("approvalID"));
		Connection con = null;
		
		if (approvalID == 0) {
			//list all approvals
			try {
				con = GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getApprovalDBConn();
				PreparedStatement ps = con.prepareStatement("SELECT workflows.requestReason AS wfreason, workflows.name AS wfName,workflows.id AS workflow, workflows.startTS AS wfStart, approvals.id AS approval,approvals.label AS label,approvals.createTS AS approvalTS, users.userKey AS userid   FROM approvals INNER JOIN workflows ON approvals.workflow=workflows.id INNER JOIN allowedApprovers ON allowedApprovers.approval=approvals.id INNER JOIN approvers ON approvers.id=allowedApprovers.approver INNER JOIN users ON users.id=workflows.userid WHERE approvers.userKey=? AND approvals.approved IS NULL");
				ps.setString(1, approver);
				ResultSet rs = ps.executeQuery();
				ArrayList<ApprovalSummary> summaries = new ArrayList<ApprovalSummary>();
				
				while (rs.next()) {
					ApprovalSummary sum = new ApprovalSummary();
					sum.setApproval(rs.getInt("approval"));
					sum.setWorkflow(rs.getInt("workflow"));
					sum.setLabel(rs.getString("label"));
					sum.setUser(rs.getString("userid"));
					sum.setWfStart(rs.getTimestamp("wfStart").getTime());
					sum.setApprovalStart(rs.getTimestamp("approvalTS").getTime());
					sum.setReason(rs.getString("wfreason"));
					
					String wfName = rs.getString("wfName");
					sum.setWfName(wfName);
					
					for (WorkflowType wf : GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getWorkflows().getWorkflow()) {
						if (wf.getName().equalsIgnoreCase(sum.getWfName())) {
							sum.setWfLabel(wf.getLabel());
							sum.setWfDescription(wf.getDescription());
						}
					}
					
					summaries.add(sum);
				}
				
				
				Gson gson = new Gson();
				ApprovalSummaries sums = new ApprovalSummaries();
				
				sums.setApprovals(summaries);
				ProvisioningResult pres = new ProvisioningResult();
				pres.setSuccess(true);
				pres.setSummaries(sums);
				resp.getOutputStream().print(gson.toJson(pres));
				
				
				
			} catch (SQLException e) {
				ProvisioningError pe = new ProvisioningError();
				pe.setError("Could not load executed workflows : " + e.getMessage());
				ProvisioningResult res = new ProvisioningResult();
				res.setSuccess(false);
				res.setError(pe);
				Gson gson = new Gson();
				
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
				con = GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getApprovalDBConn();
				PreparedStatement ps = con.prepareStatement("SELECT workflows.requestReason as wfreason,approvals.workflowObj,workflows.name AS wfName, workflows.id AS workflow, workflows.startTS AS wfStart, approvals.id AS approval,approvals.label AS label,approvals.createTS AS approvalTS, users.userKey AS userid   FROM approvals INNER JOIN workflows ON approvals.workflow=workflows.id INNER JOIN allowedApprovers ON allowedApprovers.approval=approvals.id INNER JOIN approvers ON approvers.id=allowedApprovers.approver INNER JOIN users ON users.id=workflows.userid WHERE approvers.userKey=? AND approvals.id=? AND approvals.approved IS NULL");
				ps.setString(1, approver);
				ps.setInt(2, approvalID);
				ResultSet rs = ps.executeQuery();
				
				if (! rs.next()) {
					throw new ServletException("no approval found");
				}
				
				
				ApprovalDetails sum = new ApprovalDetails();
				sum.setApproval(rs.getInt("approval"));
				sum.setWorkflow(rs.getInt("workflow"));
				sum.setLabel(rs.getString("label"));
				sum.setUser(rs.getString("userid"));
				sum.setWfStart(rs.getTimestamp("wfStart").getTime());
				sum.setApprovalStart(rs.getTimestamp("approvalTS").getTime());
				sum.setReason(rs.getString("wfreason"));
				
				
				Gson gson = new Gson();
				String json = rs.getString("workflowObj");
				Token token = gson.fromJson(json, Token.class);
				
				byte[] iv = org.bouncycastle.util.encoders.Base64.decode(token.getIv());
				
				
			    IvParameterSpec spec =  new IvParameterSpec(iv);
			    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				cipher.init(Cipher.DECRYPT_MODE,  GlobalEntries.getGlobalEntries().getConfigManager().getSecretKey( GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getApprovalDB().getEncryptionKey()),spec);
			    
				byte[] encBytes = org.bouncycastle.util.encoders.Base64.decode(token.getEncryptedRequest());
				
				json = new String(cipher.doFinal(encBytes));
				
				
				
				Workflow wf = (Workflow) JsonReader.jsonToJava(json);
				
				sum.setUserObj(wf.getUser());
				
				String wfName = rs.getString("wfName");
				sum.setWfName(wfName);
				
				for (WorkflowType wft : GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getWorkflows().getWorkflow()) {
					if (wft.getName().equalsIgnoreCase(sum.getWfName())) {
						sum.setWfLabel(wft.getLabel());
						sum.setWfDescription(wft.getDescription());
					}
				}
				
				ProvisioningResult pres = new ProvisioningResult();
				pres.setSuccess(true);
				pres.setApprovalDetail(sum);
				
				
				
				resp.getOutputStream().print(gson.toJson(pres));
				
			} catch (Throwable e) {
				logger.error("Could not load approval",e);
				ProvisioningError pe = new ProvisioningError();
				pe.setError("Could not load executed approval : " + e.getMessage());
				ProvisioningResult res = new ProvisioningResult();
				res.setSuccess(false);
				res.setError(pe);
				
				Gson gson = new Gson();
				
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
