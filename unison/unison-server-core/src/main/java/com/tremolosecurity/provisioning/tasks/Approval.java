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


package com.tremolosecurity.provisioning.tasks;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;

import com.cedarsoftware.util.io.JsonWriter;
import com.google.gson.Gson;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPReferralException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.ApprovalType;
import com.tremolosecurity.config.xml.AzRuleType;
import com.tremolosecurity.config.xml.WorkflowTaskType;
import com.tremolosecurity.json.Token;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.WorkflowTaskImpl;
import com.tremolosecurity.provisioning.tasks.Approval.ApproverType;
import com.tremolosecurity.provisioning.util.AzUtils;
import com.tremolosecurity.proxy.az.AzRule;

public class Approval extends WorkflowTaskImpl implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = -4449491970307931192L;
	public static final String SEND_NOTIFICATION = "APPROVAL_SEND_NOTIFICATION";
	static Logger logger = Logger.getLogger(Approval.class.getName());
	
	

	public enum ApproverType {
		StaticGroup,
		DynamicGroup,
		Filter,
		DN
	};
	
	String emailTemplate;
	String label;
	ArrayList<Approver> approvers;
	ArrayList<AzRule> azRules;
	
	String mailAttr;
	String failureEmailSubject;
	String failureEmailMsg;
	
	



	int id;
	
	transient ConfigManager cfg; 
	
	public Approval() {
		
	}
	
	public Approval(WorkflowTaskType taskConfig, ConfigManager cfg,Workflow wf)
			throws ProvisioningException {
		super(taskConfig, cfg,wf);
		
		this.approvers = new ArrayList<Approver>();
		this.azRules = new ArrayList<AzRule>();
		
		ApprovalType att = (ApprovalType) taskConfig;
		for (AzRuleType azr : att.getApprovers().getRule()) {
			Approver approver = new Approver();
			
			if (azr.getScope().equalsIgnoreCase("filter")) {
				approver.type = ApproverType.Filter;
			} else if (azr.getScope().equalsIgnoreCase("group")) {
				approver.type = ApproverType.StaticGroup;
			} else if (azr.getScope().equalsIgnoreCase("dn")) {
				approver.type = ApproverType.DN;
			} else if (azr.getScope().equalsIgnoreCase("dynamicGroup")) {
				approver.type = ApproverType.DynamicGroup;
			} 
			
			approver.constraint = azr.getConstraint();
			
			this.approvers.add(approver);
			this.azRules.add(new AzRule(azr.getScope(),azr.getConstraint(),azr.getClassName()));
			
			
		}
		
		this.label = att.getLabel();
		this.emailTemplate = att.getEmailTemplate();
		this.mailAttr = att.getMailAttr();
		this.failureEmailSubject = att.getFailureEmailSubject();
		this.failureEmailMsg = att.getFailureEmailMsg();
		
		
		
	}

	@Override
	public void init(WorkflowTaskType taskConfig) throws ProvisioningException {
		
	}

	
	
	@Override
	public void reInit() throws ProvisioningException {
		
	}

	@Override
	public boolean doTask(User user,Map<String,Object> request) throws ProvisioningException {
		if (this.isOnHold()) {
			this.setOnHold(false);
			HashMap<String,Object> nrequest = new HashMap<String,Object>();
			nrequest.putAll(request);
			
			nrequest.put("APPROVAL_ID", this.id);
			
			return this.runChildren(user,nrequest);
		} else {
			Connection con = null;
			try {
				con = this.getConfigManager().getProvisioningEngine().getApprovalDBConn();
				con.setAutoCommit(false);
				PreparedStatement ps = con.prepareStatement("INSERT INTO approvals (label,workflow,createTS) VALUES (?,?,?)",Statement.RETURN_GENERATED_KEYS);
				ps.setString(1, this.label);
				ps.setLong(2, this.getWorkflow().getId());
				DateTime now = new DateTime();
				ps.setTimestamp(3, new Timestamp(now.getMillis()));
				ps.executeUpdate();
				ResultSet keys = ps.getGeneratedKeys();
				keys.next();
				this.id = keys.getInt(1);
				
				//request.put("APPROVAL_ID", Integer.toString(this.id));
				request.put("APPROVAL_ID", this.id);
				
				keys.close();
				ps.close();
				
				this.setOnHold(true);
				
				
				
				Gson gson = new Gson();
				
				String json = JsonWriter.objectToJson(this.getWorkflow());
				
				
				Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				cipher.init(Cipher.ENCRYPT_MODE, this.getConfigManager().getSecretKey(this.getConfigManager().getCfg().getProvisioning().getApprovalDB().getEncryptionKey()));
				
				
				byte[] encJson = cipher.doFinal(json.getBytes("UTF-8"));
				String base64d = new String(org.bouncycastle.util.encoders.Base64.encode(encJson));
				
				Token token = new Token();
				token.setEncryptedRequest(base64d);
				token.setIv(new String(org.bouncycastle.util.encoders.Base64.encode(cipher.getIV())));
				
				//String base64 = new String(org.bouncycastle.util.encoders.Base64.encode(baos.toByteArray()));
				
				ps = con.prepareStatement("UPDATE approvals SET workflowObj=? WHERE id=?");
				ps.setString(1, gson.toJson(token));
				ps.setInt(2, this.id);
				ps.executeUpdate();
				
				boolean sendNotification = true;
				if (request.containsKey(Approval.SEND_NOTIFICATION) && request.get(Approval.SEND_NOTIFICATION).equals("false")) {
					sendNotification = false;
				}
				
				for (Approver approver : this.approvers) {
					switch (approver.type) {
						case StaticGroup : AzUtils.loadStaticGroupApprovers(this.id,this.emailTemplate,this.getConfigManager(),con,id,approver.constraint,sendNotification); break;
						case Filter : AzUtils.loadFilterApprovers(this.id,this.emailTemplate,this.getConfigManager(),con,id,approver.constraint,sendNotification); break;
						case DN : AzUtils.loadDNApprovers(this.id,this.emailTemplate,this.getConfigManager(),con,id,approver.constraint,sendNotification);break;
					}
				}
				
				con.commit();
				
				return false;
				
			} catch (SQLException e) {
				throw new ProvisioningException("Could not create approval",e);
			} catch (IOException e) {
				throw new ProvisioningException("Could not store approval",e);
			} catch (NoSuchAlgorithmException e) {
				throw new ProvisioningException("Could not encrypt workflow object",e);
			} catch (NoSuchPaddingException e) {
				throw new ProvisioningException("Could not encrypt workflow object",e);
			} catch (InvalidKeyException e) {
				throw new ProvisioningException("Could not encrypt workflow object",e);
			} catch (IllegalBlockSizeException e) {
				throw new ProvisioningException("Could not encrypt workflow object",e);
			} catch (BadPaddingException e) {
				throw new ProvisioningException("Could not encrypt workflow object",e);
			} finally {
				if (con != null) {
					
					try {
						con.rollback();
					} catch (SQLException e1) {
						
					}
					
					try {
						con.close();
					} catch (SQLException e) {
						
					}
				}
			}
		}
	}

	

	@Override
	public boolean restartChildren() throws ProvisioningException {
		return super.restartChildren(this.getWorkflow().getUser(),this.getWorkflow().getRequest());
	}
	
	public List<AzRule> getAzRules() {
		
		
		return this.azRules;
	}
	
	public String getMailAttr() {
		return mailAttr;
	}

	public String getFailureEmailSubject() {
		return failureEmailSubject;
	}

	public String getFailureEmailMsg() {
		return failureEmailMsg;
	}
	
	public String toString() {
		StringBuffer b = new StringBuffer();
		b.append("Approval - ").append(this.label).append(" - ").append(this.isOnHold());
		return b.toString();
	}

	@Override
	public String getLabel() {
		StringBuffer b = new StringBuffer();
		b.append("Approval ").append(this.label);
		return b.toString();
	}
	
	public void updateAllowedApprovals(Connection con,ConfigManager cfg) throws ProvisioningException, SQLException {
		for (Approver approver : this.approvers) {
			switch (approver.type) {
				case StaticGroup : AzUtils.loadStaticGroupApprovers(this.id,this.emailTemplate,cfg,con,id,approver.constraint,false); break;
				case Filter : AzUtils.loadFilterApprovers(this.id,this.emailTemplate,cfg,con,id,approver.constraint,false); break;
				case DN : AzUtils.loadDNApprovers(this.id,this.emailTemplate,cfg,con,id,approver.constraint,false);break;
			}
		}
	}

	public String getEmailTemplate() {
		return emailTemplate;
	}

	public void setEmailTemplate(String emailTemplate) {
		this.emailTemplate = emailTemplate;
	}

	public ArrayList<Approver> getApprovers() {
		return approvers;
	}

	public void setApprovers(ArrayList<Approver> approvers) {
		this.approvers = approvers;
	}

	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}

	public void setLabel(String label) {
		this.label = label;
	}

	public void setAzRules(ArrayList<AzRule> azRules) {
		this.azRules = azRules;
	}

	public void setMailAttr(String mailAttr) {
		this.mailAttr = mailAttr;
	}

	public void setFailureEmailSubject(String failureEmailSubject) {
		this.failureEmailSubject = failureEmailSubject;
	}

	public void setFailureEmailMsg(String failureEmailMsg) {
		this.failureEmailMsg = failureEmailMsg;
	}
	
	
}

class Approver implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = -4721972479742465278L;
	ApproverType type;
	String constraint;
}