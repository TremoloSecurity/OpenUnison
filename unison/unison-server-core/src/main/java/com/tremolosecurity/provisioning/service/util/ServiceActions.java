/*******************************************************************************
 * Copyright 2015, 2017 Tremolo Security, Inc.
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
package com.tremolosecurity.provisioning.service.util;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.servlet.ServletException;

import org.apache.logging.log4j.Logger;
import org.hibernate.Query;
import org.hibernate.Session;

import com.cedarsoftware.util.io.JsonReader;
import com.google.gson.Gson;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.WorkflowType;
import com.tremolosecurity.json.Token;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.objects.Approvals;
import com.tremolosecurity.provisioning.objects.UserAttributes;
import com.tremolosecurity.provisioning.objects.Workflows;
import com.tremolosecurity.server.GlobalEntries;

public class ServiceActions {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(ServiceActions.class.getName());

	public static ApprovalSummaries listOpenApprovals(String approver,String displayNameAttribute,ConfigManager cfgMgr) throws ProvisioningException {
		Session session = null;
		
		
		
		try {
			
			//PreparedStatement ps = con.prepareStatement("SELECT workflows.requestReason AS wfreason, workflows.name AS wfName,workflows.id AS workflow, workflows.startTS AS wfStart, approvals.id AS approval,approvals.label AS label,approvals.createTS AS approvalTS, users.userKey AS userid   FROM approvals INNER JOIN workflows ON approvals.workflow=workflows.id INNER JOIN allowedApprovers ON allowedApprovers.approval=approvals.id INNER JOIN approvers ON approvers.id=allowedApprovers.approver INNER JOIN users ON users.id=workflows.userid WHERE approvers.userKey=? AND approvals.approved IS NULL");
			
			
			session = GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getHibernateSessionFactory().openSession();
			
			
			Query query = session.createQuery("SELECT aprv FROM Approvals aprv JOIN aprv.allowedApproverses allowed JOIN allowed.approvers apprv  WHERE aprv.approved IS  NULL AND apprv.userKey = :user_key");
			
			query.setParameter("user_key", approver);
			List<com.tremolosecurity.provisioning.objects.Approvals> approvals = query.list();
			
			
			
			
			
			ArrayList<ApprovalSummary> summaries = new ArrayList<ApprovalSummary>();
			
			
			
			
			for (Approvals appr : approvals) {
				
				ApprovalSummary sum = new ApprovalSummary();
				
				
				
				
				
				sum.setApproval(appr.getId());
				sum.setWorkflow(appr.getWorkflow().getId());
				sum.setLabel(appr.getLabel());
				sum.setUser(appr.getWorkflow().getUsers().getUserKey());
				
				String filter = equal(cfgMgr.getCfg().getProvisioning().getApprovalDB().getUserIdAttribute(),appr.getWorkflow().getUsers().getUserKey()).toString();
				ArrayList<String> attributes = new ArrayList<String>();
				attributes.add(displayNameAttribute);
				
				LDAPSearchResults res = cfgMgr.getMyVD().search(cfgMgr.getCfg().getLdapRoot(), 2, filter, attributes);
				if (res.hasMore()) {
					LDAPEntry entry = res.next();
					while (res.hasMore()) res.next();
					LDAPAttribute attr = entry.getAttribute(displayNameAttribute);
					if (attr != null) {
						sum.setDisplayName(attr.getStringValue());
					} else {
						sum.setDisplayName(approver);
					}
					while (res.hasMore()) res.next();
				} else {
					
					//TODO decrypt object
					if (displayNameAttribute.equalsIgnoreCase(cfgMgr.getCfg().getProvisioning().getApprovalDB().getUserIdAttribute())) {
						sum.setDisplayName(appr.getWorkflow().getUsers().getUserKey());
					} else {
						boolean found = false;
						Set<UserAttributes> fromReportData = appr.getWorkflow().getUsers().getUserAttributeses();
						for (UserAttributes attr : fromReportData) {
							if (attr.getName().equalsIgnoreCase(displayNameAttribute)) {
								sum.setDisplayName(attr.getValue());
								found = true;
								break;
							}
						}
						
						if (! found) {
							sum.setDisplayName(appr.getWorkflow().getUsers().getUserKey());
						}
					} 
					
					
					
				}
				
				
				
				sum.setWfStart(appr.getWorkflow().getStartTs().getTime());
				sum.setApprovalStart(appr.getCreateTs().getTime());
				sum.setReason(appr.getWorkflow().getRequestReason());
				
				String wfName = appr.getWorkflow().getName();
				sum.setWfName(wfName);
				sum.setWfLabel(appr.getWorkflow().getLabel());
				sum.setWfDescription(appr.getWorkflow().getDescription());
				
				
				
				summaries.add(sum);
				
				
			}
			
			
			Gson gson = new Gson();
			ApprovalSummaries sums = new ApprovalSummaries();
			
			
			
			sums.setApprovals(summaries);
			
			
			
			return sums;
		} catch (Throwable t) {
			throw new ProvisioningException("Could not load approvals",t);
		} finally {
			if (session != null) {
				session.close();
			}
		}
	}
	
	public static ApprovalDetails loadApprovalDetails(String approver,int approvalID) throws ProvisioningException {
		return loadApprovalDetails(approver,approvalID,new ArrayList<String>());
	}
	
	public static ApprovalDetails loadApprovalDetails(String approver,int approvalID,Collection<String> requestAttributes) throws ProvisioningException {
		Session session = null;
		Gson gson = new Gson();
		try {
			session = GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getHibernateSessionFactory().openSession();
			
			Query query = session.createQuery("SELECT apprv FROM Approvals apprv JOIN apprv.allowedApproverses allowed JOIN allowed.approvers approver WHERE apprv.id = :approval_id AND approver.userKey = :approver_id");
			query.setParameter("approval_id", approvalID);
			query.setParameter("approver_id", approver);
			List<com.tremolosecurity.provisioning.objects.Approvals> approvals = query.list();
			
			
			
			
			if (approvals.isEmpty()) {
				throw new ServletException("no approval found");
			}
			
			Approvals approval = approvals.get(0);
			
			ApprovalDetails sum = new ApprovalDetails();
			sum.setApproval(approval.getId());
			sum.setWorkflow(approval.getWorkflow().getId());
			sum.setLabel(approval.getLabel());
			sum.setUser(approval.getWorkflow().getUsers().getUserKey());
			sum.setWfStart(approval.getWorkflow().getStartTs().getTime());
			sum.setApprovalStart(approval.getCreateTs().getTime());
			sum.setReason(approval.getWorkflow().getRequestReason());
			
			
			
			String json = approval.getWorkflowObj();
			Token token = gson.fromJson(json, Token.class);
			
			byte[] iv = org.bouncycastle.util.encoders.Base64.decode(token.getIv());
			
			
		    IvParameterSpec spec =  new IvParameterSpec(iv);
		    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE,  GlobalEntries.getGlobalEntries().getConfigManager().getSecretKey( GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getApprovalDB().getEncryptionKey()),spec);
		    
			byte[] encBytes = org.bouncycastle.util.encoders.Base64.decode(token.getEncryptedRequest());
			
			json = new String(cipher.doFinal(encBytes));
			
			
			
			Workflow wf = (Workflow) JsonReader.jsonToJava(json);
			
			sum.setUserObj(wf.getUser());
			sum.setRequestAttributes(new HashMap<String,String>());
			
			for (String requestAttribute : requestAttributes) {
				Object o = wf.getRequest().get(requestAttribute);
				String val = "";
				if (o != null) {
					val = o.toString();
				}
				
				if (! val.isBlank()) {
					sum.getRequestAttributes().put(requestAttribute, val);
				}
			}
			
			
			
			String wfName = approval.getWorkflow().getName();
			sum.setWfName(wfName);
			sum.setWfLabel(approval.getWorkflow().getLabel());
			sum.setWfDescription(approval.getWorkflow().getDescription());
			
			
			
			return sum;
		} catch (Throwable t) {
			throw new ProvisioningException("Could not load approval",t);
		} finally {
			if (session != null) {
				session.close();
			}
		}
	}
}
