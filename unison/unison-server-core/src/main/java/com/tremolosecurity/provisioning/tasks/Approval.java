/*
Copyright 2015, 2018 Tremolo Security, Inc.

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

import org.apache.logging.log4j.Logger;
import org.hibernate.Session;
import org.hibernate.resource.transaction.spi.TransactionStatus;
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
import com.tremolosecurity.provisioning.objects.Approvals;
import com.tremolosecurity.provisioning.objects.Escalation;
import com.tremolosecurity.provisioning.objects.Workflows;
import com.tremolosecurity.provisioning.tasks.Approval.ApproverType;
import com.tremolosecurity.provisioning.tasks.escalation.EsclationRuleImpl;
import com.tremolosecurity.provisioning.util.AzUtils;
import com.tremolosecurity.provisioning.util.EscalationRule;
import com.tremolosecurity.provisioning.util.EscalationRule.RunOptions;
import com.tremolosecurity.proxy.az.AzRule;
import com.tremolosecurity.proxy.az.CustomAuthorization;
import com.tremolosecurity.proxy.az.VerifyEscalation;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.proxy.az.AzRule.ScopeType;

public class Approval extends WorkflowTaskImpl implements Serializable {

	/**
	 * 
	 */
	
	public static final String SEND_NOTIFICATION = "APPROVAL_SEND_NOTIFICATION";
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(Approval.class.getName());
	
	public static final String APPROVAL_RESULT = "APPROVAL_RESULT";
	public static final String REASON = "APPROVAL_REASON";
	public static final String IMMEDIATE_ACTION = "APPROVAL_IMMEDIATE_ACTION";

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
			
			setupCustomParameters(approver);

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
					setupCustomParameters(approver);
					//this.approvers.add(approver);
					
					AzRule rule = new AzRule(azr.getScope(),azr.getConstraint(),azr.getClassName(),cfg,wf);
					
					erule.getAzRules().add(rule);
					approver.customAz = rule.getCustomAuthorization();
					
					
				}
				
				this.escalationRules.add(erule);
				now = when;
			}
			
			if (att.getEscalationPolicy().getEscalationFailure().getAction() != null) {
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
							setupCustomParameters(approver);
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
		
	}

	private void setupCustomParameters(Approver approver) {
		if (approver.type == ApproverType.Custom) {
				if (approver.constraint.contains("!")) {
					String[] vals = approver.constraint.split("[!]");
					approver.params = new String[vals.length - 1];
					approver.constraint = vals[0];

					for (int i=0;i<approver.params.length;i++) {
						approver.params[i] = vals[i+1];
					}
				} else {
					approver.params = new String[0];
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
			return runChildTasks(user, request);
			
			
		} else {
			Session session = this.getConfigManager().getProvisioningEngine().getHibernateSessionFactory().openSession();
			try {
				
				DateTime now = new DateTime();
				
				Approvals approval = new Approvals();
				approval.setLabel(this.renderTemplate(this.label, request));
				approval.setWorkflow(this.getWorkflow().getFromDB(session));
				approval.setCreateTs(new Timestamp(now.getMillis()));
				
				
				
				if (request.get(Approval.APPROVAL_RESULT) != null) {
					request.remove(Approval.APPROVAL_RESULT);
				}
				
				this.setOnHold(true);
				
				
				
				
				
				
				
				
				
				
				boolean sendNotification = true;
				if (request.containsKey(Approval.SEND_NOTIFICATION) && request.get(Approval.SEND_NOTIFICATION).equals("false")) {
					sendNotification = false;
				}
				
				String localTemplate = this.renderTemplate(this.emailTemplate, request);
				
				List<Object> objToSave = new ArrayList<Object>();
				
				
				for (Approver approver : this.approvers) {
					String[] localParams = null;
					localParams = renderCustomParameters(request, approver, localParams);

					String constraintRendered = this.renderTemplate(approver.constraint, request);
					switch (approver.type) {
						case StaticGroup : AzUtils.loadStaticGroupApprovers(approval,localTemplate,this.getConfigManager(),session,constraintRendered,sendNotification,objToSave); break;
						case Filter : AzUtils.loadFilterApprovers(approval,localTemplate,this.getConfigManager(),session,constraintRendered,sendNotification,objToSave); break;
						case DN : AzUtils.loadDNApprovers(approval,localTemplate,this.getConfigManager(),session,constraintRendered,sendNotification,objToSave);break;
						case Custom : AzUtils.loadCustomApprovers(approval,localTemplate,this.getConfigManager(),session,constraintRendered,sendNotification,approver.customAz,localParams,objToSave);break;
					}
				}
				
				session.beginTransaction();
				approval.setWorkflowObj(null);
				session.save(approval);
				
				for (Object o : objToSave) {
					session.save(o);
				}
				
				
				
				this.id = approval.getId();
				
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
				
				approval.setWorkflowObj(gson.toJson(token));
				session.save(approval);
				
				//request.put("APPROVAL_ID", Integer.toString(this.id));
				request.put("APPROVAL_ID", this.id);
				
				session.getTransaction().commit();
				
				if (request.get(Approval.IMMEDIATE_ACTION) != null && request.get(Approval.REASON) != null) {
					String reason = (String) request.get(Approval.REASON);
					boolean action = false;
					Object tmp = request.get(Approval.IMMEDIATE_ACTION);
					if (tmp instanceof String) {
						action = tmp.equals("true");
					} else {
						action = (boolean) tmp;
					}
					
					 try {
						 GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().doApproval(this.id, this.getWorkflow().getRequester().getUserID(), action, reason);
					 } catch (ProvisioningException pe) {
						 logger.warn("Could not execute pre-approval",pe);
					 }
				}
				
				
				return false;
				
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
				if (session != null) {
					if (session.getTransaction() != null && session.getTransaction().getStatus() == TransactionStatus.ACTIVE) {
						session.getTransaction().rollback();
					}
					
					session.close();
				}
			}
		}
	}

	private boolean runChildTasks(User user, Map<String, Object> request) throws ProvisioningException {
		this.setOnHold(false);
		HashMap<String,Object> nrequest = new HashMap<String,Object>();
		nrequest.putAll(request);
		
		nrequest.put("APPROVAL_ID", this.id);
		
		Boolean result = (Boolean) request.get(Approval.APPROVAL_RESULT);
		
		if (result != null && result.booleanValue()) {
			return super.runSubTasks(super.getOnSuccess(),user,request);
		} else {
			return super.runSubTasks(super.getOnFailure(),user,request);
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
	
	public boolean updateAllowedApprovals(Session session,ConfigManager cfg, Map<String, Object> request,List<Object> objToSave) throws ProvisioningException, SQLException {
		boolean updateObj = false;
		boolean localFail = false;
		
		Approvals approvalObj = session.load(Approvals.class, this.id);
		
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
								setupCustomParameters(approver);
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
										approver.params = azr.getCustomParameters();
									} 
									
									approver.constraint = azr.getConstraint();
									this.approvers.add(approver);
								}
								
								
							}
							
							updateObj = true;
							
							rule.setCompleted(true);
							
							Escalation escalation = new Escalation();
							escalation.setApprovals(approvalObj);
							escalation.setWhenTs(new Timestamp(new DateTime().getMillis()));
							//if (! session.isJoinedToTransaction()) {
							//	session.beginTransaction();
							//}
							//session.save(escalation);
							objToSave.add(escalation);
							
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
		
		Approvals approval = session.load(Approvals.class, this.id);
		
		for (Approver approver : this.approvers) {
			String constraintRendered = this.renderTemplate(approver.constraint, request);
			
			String[] localParams = null;
			localParams = renderCustomParameters(request, approver, localParams);
			
			switch (approver.type) {
				case StaticGroup : foundApprovers |= AzUtils.loadStaticGroupApprovers(approval,this.emailTemplate,cfg,session,constraintRendered,false,objToSave); break;
				case Filter : foundApprovers |= AzUtils.loadFilterApprovers(approval,this.emailTemplate,cfg,session,constraintRendered,false,objToSave); break;
				case DN : foundApprovers |= AzUtils.loadDNApprovers(approval,this.emailTemplate,cfg,session,constraintRendered,false,objToSave);break;
				case Custom : foundApprovers |= AzUtils.loadCustomApprovers(approval,this.emailTemplate,cfg,session,constraintRendered,false,approver.customAz,localParams,objToSave);break;
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
						approver.params = azr.getCustomParameters();
					} 
					
					approver.constraint = azr.getConstraint();
					this.approvers.add(approver);
				}
			}
			
			for (Approver approver : this.approvers) {
				String constraintRendered = this.renderTemplate(approver.constraint, request);

				String[] localParams = null;
				localParams = renderCustomParameters(request, approver, localParams);

				switch (approver.type) {
					case StaticGroup : AzUtils.loadStaticGroupApprovers(approval,this.emailTemplate,cfg,session,constraintRendered,false,objToSave); break;
					case Filter : AzUtils.loadFilterApprovers(approval,this.emailTemplate,cfg,session,constraintRendered,false,objToSave); break;
					case DN : AzUtils.loadDNApprovers(approval,this.emailTemplate,cfg,session,constraintRendered,false,objToSave);break;
					case Custom : AzUtils.loadCustomApprovers(approval,this.emailTemplate,cfg,session,constraintRendered,false,approver.customAz,localParams,objToSave);break;
				}
			}
			
			this.failed = true;
		}
		
		return updateObj;
	}

	private String[] renderCustomParameters(Map<String, Object> request, Approver approver, String[] localParams) {
		if (approver.type == ApproverType.Custom) {
					localParams = new String[approver.params.length];
					for (int i = 0;i<approver.params.length;i++) {
						localParams[i] = this.renderTemplate(approver.params[i], request);
					}
				}
		return localParams;
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
	
	@Override
	public boolean canHaveChildren() {
		return true;
	}
	
	
}

class Approver  {

	public Approver() {

	}

	ApproverType type;
	String constraint;
	CustomAuthorization customAz;
	String[] params;
}