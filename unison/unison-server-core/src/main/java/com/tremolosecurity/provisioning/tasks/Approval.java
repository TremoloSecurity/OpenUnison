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
import com.tremolosecurity.config.xml.EscalationType;
import com.tremolosecurity.config.xml.WorkflowTaskType;
import com.tremolosecurity.json.Token;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.WorkflowTaskImpl;
import com.tremolosecurity.provisioning.tasks.Approval.ApproverType;
import com.tremolosecurity.provisioning.tasks.escalation.EsclationRuleImpl;
import com.tremolosecurity.provisioning.util.AzUtils;
import com.tremolosecurity.provisioning.util.EscalationRule;
import com.tremolosecurity.provisioning.util.EscalationRule.RunOptions;
import com.tremolosecurity.proxy.az.AzRule;
import com.tremolosecurity.proxy.az.CustomAuthorization;
import com.tremolosecurity.proxy.az.VerifyEscalation;
import com.tremolosecurity.proxy.az.AzRule.ScopeType;

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
		DN,
		Custom
	};
	
	String emailTemplate;
	String label;
	ArrayList<Approver> approvers;
	List<AzRule> azRules;
	List<EscalationRule> escalationRules;
	
	
	String mailAttr;
	String failureEmailSubject;
	String failureEmailMsg;
	
	
	boolean failOnNoAZ;


	int id;
	
	transient ConfigManager cfg;
	private ArrayList<AzRule> failureAzRules; 
	boolean failed;
	
	public Approval() {
		
	}
	
	public Approval(WorkflowTaskType taskConfig, ConfigManager cfg,Workflow wf)
			throws ProvisioningException {
		super(taskConfig, cfg,wf);
		
		this.approvers = new ArrayList<Approver>();
		this.azRules = new ArrayList<AzRule>();
		
		this.failed = false;
		
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
			} else if (azr.getScope().equalsIgnoreCase("custom")) {
				approver.type = ApproverType.Custom;
			}
			
			approver.constraint = azr.getConstraint();
			
			this.approvers.add(approver);
			
			AzRule rule = new AzRule(azr.getScope(),azr.getConstraint(),azr.getClassName(),cfg,wf);
			
			this.azRules.add(rule);
			approver.customAz = rule.getCustomAuthorization();
			
			
			
			
		}
		
		this.label = att.getLabel();
		this.emailTemplate = att.getEmailTemplate();
		this.mailAttr = att.getMailAttr();
		this.failureEmailSubject = att.getFailureEmailSubject();
		this.failureEmailMsg = att.getFailureEmailMsg();
		
		this.escalationRules = new ArrayList<EscalationRule>();
		
		if (att.getEscalationPolicy() != null) {
			DateTime now = new DateTime();
			for (EscalationType ert : att.getEscalationPolicy().getEscalation()) {
				EscalationRule erule = new EsclationRuleImpl();
				
				DateTime when;
				
				if (ert.getExecuteAfterUnits().equalsIgnoreCase("sec")) {
					when = now.plusSeconds(ert.getExecuteAfterTime());
				} else if (ert.getExecuteAfterUnits().equals("min")) {
					when = now.plusMinutes(ert.getExecuteAfterTime());
				} else if (ert.getExecuteAfterUnits().equals("hr")) {
					when = now.plusHours(ert.getExecuteAfterTime());
				} else if (ert.getExecuteAfterUnits().equals("day")) {
					when = now.plusDays(ert.getExecuteAfterTime());
				} else if (ert.getExecuteAfterUnits().equals("wk")) {
					when = now.plusWeeks(ert.getExecuteAfterTime());
				} else {
					throw new ProvisioningException("Unknown time unit : " + ert.getExecuteAfterUnits());
				}
				
				erule.setCompleted(false);
				erule.setExecuteTS(when.getMillis());
				
				
				
				if (ert.getValidateEscalationClass() != null && ! ert.getValidateEscalationClass().isEmpty() ) {
					try {
						erule.setVerify((VerifyEscalation) Class.forName(ert.getValidateEscalationClass()).newInstance());
					} catch (InstantiationException | IllegalAccessException
							| ClassNotFoundException e) {
						throw new ProvisioningException("Could not initialize escalation rule",e);
					}
				} else {
					erule.setVerify(null);
				}
				
				erule.setAzRules(new ArrayList<AzRule>());
				for (AzRuleType azr : ert.getAzRules().getRule()) {
					Approver approver = new Approver();
					
					if (azr.getScope().equalsIgnoreCase("filter")) {
						approver.type = ApproverType.Filter;
					} else if (azr.getScope().equalsIgnoreCase("group")) {
						approver.type = ApproverType.StaticGroup;
					} else if (azr.getScope().equalsIgnoreCase("dn")) {
						approver.type = ApproverType.DN;
					} else if (azr.getScope().equalsIgnoreCase("dynamicGroup")) {
						approver.type = ApproverType.DynamicGroup;
					} else if (azr.getScope().equalsIgnoreCase("custom")) {
						approver.type = ApproverType.Custom;
					} 
					
					
					
					
					approver.constraint = azr.getConstraint();
					
					//this.approvers.add(approver);
					
					AzRule rule = new AzRule(azr.getScope(),azr.getConstraint(),azr.getClassName(),cfg,wf);
					
					erule.getAzRules().add(rule);
					approver.customAz = rule.getCustomAuthorization();
					
					
				}
				
				this.escalationRules.add(erule);
				now = when;
			}
			
			
			switch (att.getEscalationPolicy().getEscalationFailure().getAction()) {
				case "leave" :
					this.failureAzRules = null;
					this.failOnNoAZ = false;
					break;
				case "assign" : 
					this.failOnNoAZ = true;
					this.failureAzRules = new ArrayList<AzRule>();
					for (AzRuleType azr : att.getEscalationPolicy().getEscalationFailure().getAzRules().getRule()) {
						Approver approver = new Approver();
						
						if (azr.getScope().equalsIgnoreCase("filter")) {
							approver.type = ApproverType.Filter;
						} else if (azr.getScope().equalsIgnoreCase("group")) {
							approver.type = ApproverType.StaticGroup;
						} else if (azr.getScope().equalsIgnoreCase("dn")) {
							approver.type = ApproverType.DN;
						} else if (azr.getScope().equalsIgnoreCase("dynamicGroup")) {
							approver.type = ApproverType.DynamicGroup;
						} else if (azr.getScope().equalsIgnoreCase("custom")) {
							approver.type = ApproverType.Custom;
						} 
						
						
						approver.constraint = azr.getConstraint();
						
						//this.approvers.add(approver);
						
						AzRule rule = new AzRule(azr.getScope(),azr.getConstraint(),azr.getClassName(),cfg,wf);
						
						this.failureAzRules.add(rule);
						approver.customAz = rule.getCustomAuthorization();
						
					}
					break;
					
				default : throw new ProvisioningException("Unknown escalation failure action : " + att.getEscalationPolicy().getEscalationFailure().getAction());
			}
			
			
			
		}
		
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
				String json = "";
				synchronized (this.getWorkflow()) {
					json = JsonWriter.objectToJson(this.getWorkflow());
				}
				
				
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
						case Custom : AzUtils.loadCustomApprovers(this.id,this.emailTemplate,this.getConfigManager(),con,id,approver.constraint,sendNotification,approver.customAz);break;
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
	
	public boolean updateAllowedApprovals(Connection con,ConfigManager cfg) throws ProvisioningException, SQLException {
		boolean updateObj = false;
		boolean localFail = false;
		
		
		if (! this.failed && this.escalationRules != null && ! this.escalationRules.isEmpty()) {
			boolean continueLooking = true;
			for (EscalationRule rule : this.escalationRules) {
				if (! rule.isCompleted() && continueLooking) {
					
					RunOptions res = rule.shouldExecute(this.getWorkflow().getUser()); 
					switch (res) {
						case notReadyYet : 
							continueLooking = false;
							break;
						case run :
							continueLooking = false;
							this.azRules.clear();
							this.azRules.addAll(rule.getAzRules());
							
							this.approvers = new ArrayList<Approver>();
							
							for (AzRule azr : this.azRules) {
								Approver approver = new Approver();
								
								if (azr.getScope() == ScopeType.Filter) {
									approver.type = ApproverType.Filter;
								} else if (azr.getScope() == ScopeType.Group) {
									approver.type = ApproverType.StaticGroup;
								} else if (azr.getScope() == ScopeType.DN) {
									approver.type = ApproverType.DN;
								} else if (azr.getScope() == ScopeType.DynamicGroup) {
									approver.type = ApproverType.DynamicGroup;
								} else if (azr.getScope() == ScopeType.Custom) {
									approver.type = ApproverType.Custom;
									approver.customAz = azr.getCustomAuthorization();
								} 
								
								approver.constraint = azr.getConstraint();
								this.approvers.add(approver);
							}
							
							if (this.approvers.size() == 0 && this.failOnNoAZ) {
								this.azRules = this.failureAzRules;
								this.approvers = new ArrayList<Approver>();
								
								for (AzRule azr : this.azRules) {
									Approver approver = new Approver();
									
									if (azr.getScope() == ScopeType.Filter) {
										approver.type = ApproverType.Filter;
									} else if (azr.getScope() == ScopeType.Group) {
										approver.type = ApproverType.StaticGroup;
									} else if (azr.getScope() == ScopeType.DN) {
										approver.type = ApproverType.DN;
									} else if (azr.getScope() == ScopeType.DynamicGroup) {
										approver.type = ApproverType.DynamicGroup;
									} else if (azr.getScope() == ScopeType.Custom) {
										approver.type = ApproverType.Custom;
										approver.customAz = azr.getCustomAuthorization();
									} 
									
									approver.constraint = azr.getConstraint();
									this.approvers.add(approver);
								}
								
								
							}
							
							updateObj = true;
							
							rule.setCompleted(true);
							
							PreparedStatement psAddEscalation = con.prepareStatement("INSERT INTO escalation (approval,whenTS) VALUES (?,?)");
							psAddEscalation.setInt(1, this.id);
							psAddEscalation.setTimestamp(2, new Timestamp(new DateTime().getMillis()));
							psAddEscalation.executeUpdate();
							psAddEscalation.close();
							
							break;
						case stopEscalating : 
							continueLooking = false;
							localFail = true;
							
							
							
							updateObj = true;
							
							break;
					}
					
					
				}
			}
			

		}
		
		boolean foundApprovers = false;
		
		for (Approver approver : this.approvers) {
			switch (approver.type) {
				case StaticGroup : foundApprovers |= AzUtils.loadStaticGroupApprovers(this.id,this.emailTemplate,cfg,con,id,approver.constraint,false); break;
				case Filter : foundApprovers |= AzUtils.loadFilterApprovers(this.id,this.emailTemplate,cfg,con,id,approver.constraint,false); break;
				case DN : foundApprovers |= AzUtils.loadDNApprovers(this.id,this.emailTemplate,cfg,con,id,approver.constraint,false);break;
				case Custom : foundApprovers |= AzUtils.loadCustomApprovers(this.id,this.emailTemplate,cfg,con,id,approver.constraint,false,approver.customAz);break;
			}
		}
		
		if (! this.failed && (! foundApprovers || localFail)) {
			if (this.failOnNoAZ) {
				this.azRules = this.failureAzRules;
				this.approvers = new ArrayList<Approver>();
				
				for (AzRule azr : this.azRules) {
					Approver approver = new Approver();
					
					if (azr.getScope() == ScopeType.Filter) {
						approver.type = ApproverType.Filter;
					} else if (azr.getScope() == ScopeType.Group) {
						approver.type = ApproverType.StaticGroup;
					} else if (azr.getScope() == ScopeType.DN) {
						approver.type = ApproverType.DN;
					} else if (azr.getScope() == ScopeType.DynamicGroup) {
						approver.type = ApproverType.DynamicGroup;
					} else if (azr.getScope() == ScopeType.Custom) {
						approver.type = ApproverType.Custom;
						approver.customAz = azr.getCustomAuthorization();
					} 
					
					approver.constraint = azr.getConstraint();
					this.approvers.add(approver);
				}
			}
			
			for (Approver approver : this.approvers) {
				switch (approver.type) {
					case StaticGroup : AzUtils.loadStaticGroupApprovers(this.id,this.emailTemplate,cfg,con,id,approver.constraint,false); break;
					case Filter : AzUtils.loadFilterApprovers(this.id,this.emailTemplate,cfg,con,id,approver.constraint,false); break;
					case DN : AzUtils.loadDNApprovers(this.id,this.emailTemplate,cfg,con,id,approver.constraint,false);break;
					case Custom : AzUtils.loadCustomApprovers(this.id,this.emailTemplate,cfg,con,id,approver.constraint,false,approver.customAz);break;
				}
			}
			
			this.failed = true;
		}
		
		return updateObj;
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

	
	public List<EscalationRule> getEscalationRules() {
		return escalationRules;
	}
	
	
	public void setEscalationRules(List<EscalationRule> escalationRules) {
		this.escalationRules = escalationRules;
	}

	
	public List<AzRule> getFailureAzRules() {
		return failureAzRules;
	}

	
	public void setFailureAzRules(ArrayList<AzRule> failureAzRules) {
		this.failureAzRules = failureAzRules;
	}

	public boolean isFailed() {
		return failed;
	}

	public void setFailed(boolean failed) {
		this.failed = failed;
	}
	
	
	
	
}

class Approver  {

	ApproverType type;
	String constraint;
	CustomAuthorization customAz;
}