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


package com.tremolosecurity.provisioning.util;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.Logger;
import org.hibernate.Query;
import org.hibernate.Session;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPReferralException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.objects.AllowedApprovers;
import com.tremolosecurity.provisioning.objects.Approvals;
import com.tremolosecurity.provisioning.objects.ApproverAttributes;
import com.tremolosecurity.provisioning.objects.Approvers;
import com.tremolosecurity.proxy.az.CustomAuthorization;


public class AzUtils {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(AzUtils.class);
	
	
	
	
	
	
	
	

	

	public static boolean loadDNApprovers(Approvals approval,String emailTemplate,ConfigManager cfg,Session session, int id2, String constraint,boolean sendNotification) throws ProvisioningException {
		ArrayList<String> attrs = new ArrayList<String>();
		attrs.add(cfg.getProvisioningEngine().getUserIDAttribute());
		LDAPSearchResults res = null;
		LDAPEntry entry = null;
		
		boolean found = false;
		
		try {
			res = cfg.getMyVD().search(constraint, 2, equal("objectClass",cfg.getCfg().getUserObjectClass()).toString(), attrs);
			
			
			
			
			
			
				
			
			
			
			
			while (res.hasMore()) {
				entry = res.next();
				
				
				Approvers approver = getApproverByDN(approval,emailTemplate,cfg,session, entry.getDN(),sendNotification);
				if (approver == null) {
					continue;
				}
				
				found = true;
				
				AllowedApprovers allowedApprover = new AllowedApprovers();
				
				allowedApprover.setApprovals(approval);
				allowedApprover.setApprovers(approver);
				session.save(allowedApprover);
			}
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not find approvers",e);
		}
		
		return found;
		
	}

	public static boolean loadFilterApprovers(Approvals approval,String emailTemplate,ConfigManager cfg,Session session, int id, String constraint,boolean sendNotification) throws ProvisioningException {
		ArrayList<String> attrs = new ArrayList<String>();
		//attrs.add(cfg.getProvisioningEngine().getUserIDAttribute());
		LDAPSearchResults res = null;
		LDAPEntry entry = null;
		boolean found = false;
		
		try {
			res = cfg.getMyVD().search(cfg.getCfg().getLdapRoot(), 2, constraint, attrs);
			
			
			
			
				
			
			
			
			
			while (res.hasMore()) {
				entry = res.next();
				LDAPAttribute attr = entry.getAttribute(cfg.getProvisioningEngine().getUserIDAttribute());
				if (attr == null) {
					continue;
				}
				
				if (sendNotification) {
					if (entry.getAttribute("mail") == null) {
						StringBuffer b = new StringBuffer();
						b.append("No email address for ").append(entry.getDN());
						logger.warn(b.toString());
					} else {
						String mail = entry.getAttribute("mail").getStringValue();
						cfg.getProvisioningEngine().sendNotification(mail, emailTemplate,new User(entry));
					}
				}
				String uid = attr.getStringValue();
				
				Approvers approver = getApprover(approval,emailTemplate,cfg,session,uid,entry);
				if (approver == null) {
					continue;
				}
				
				found = true;
				
				AllowedApprovers allowed = new AllowedApprovers();
				allowed.setApprovals(approval);
				allowed.setApprovers(approver);
				session.save(allowed);
			}
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not find approvers",e);
		}
		
		
		return found;
	
		
	}

	public static boolean loadStaticGroupApprovers(Approvals approval,String emailTemplate,ConfigManager cfg,Session session, int id, String constraint,boolean sendNotification) throws ProvisioningException {
		ArrayList<String> attrs = new ArrayList<String>();
		attrs.add(cfg.getCfg().getGroupMemberAttribute());
		LDAPSearchResults res = null;
		LDAPEntry entry = null;
		
		boolean found = false;
		
		try {
			
			res = cfg.getMyVD().search(constraint, 0, "(objectClass=*)", attrs);
			if (res.hasMore()) {
				entry = res.next();
			}
			while (res.hasMore()) res.next();
		} catch (LDAPException e) {
			throw new ProvisioningException("Could not find group",e);
		}
		
		if (entry != null) {
			LDAPAttribute members = entry.getAttribute(cfg.getCfg().getGroupMemberAttribute());
			String[] dns = members != null ? members.getStringValueArray() : new String[0];
			
			if (dns.length == 0) {
				StringBuffer b = new StringBuffer();
				b.append(constraint).append(" does not have any members");
				logger.warn(b.toString());
			}
			
			try {
				
				
				for (String dn : dns) {
					
					Approvers approver = getApproverByDN(approval,emailTemplate,cfg,session,dn,sendNotification);
					if (approver == null) {
						continue;
					}
					
					AllowedApprovers allowed = new AllowedApprovers();
					allowed.setApprovals(approval);
					allowed.setApprovers(approver);
					session.save(allowed);
					
					found = true;
				}
				
				
			} catch (Exception e) {
				throw new ProvisioningException("Could not load approvers",e);
			}
		}
		
		return found;
		
	}

	public static Approvers getApproverByDN(Approvals approval,String emailTemplate,ConfigManager cfg,Session session, String dn,boolean sendNotification) throws ProvisioningException {
		
		
		try {
			ArrayList<String> attrs = new ArrayList<String>();
			//attrs.add(cfg.getProvisioningEngine().getUserIDAttribute());
			LDAPEntry entry = null;
			try {
				LDAPSearchResults res = cfg.getMyVD().search(dn, 0, "(objectClass=*)", attrs);
				
				if (! res.hasMore()) {
					if (logger.isDebugEnabled()) {
						logger.debug("Can not find '" + dn + "'");
					}
					return null;
				}
				entry = res.next();
				while (res.hasMore()) res.next();
			} catch (LDAPException e) {
				if (e.getResultCode() == 32) {
					if (logger.isDebugEnabled()) {
						logger.debug("Can not find '" + dn + "'");
					}
					return null;
				} else {
					throw e;
				}
			}
			
			
			
			if (logger.isDebugEnabled()) {
				logger.debug("Approver DN - " + entry.getDN());
				LDAPAttributeSet attrsx = entry.getAttributeSet();
				for (Object o : attrsx) {
					LDAPAttribute attrx = (LDAPAttribute) o;
					for (String val : attrx.getStringValueArray()) {
						logger.debug("Approver Attribute '" + attrx.getName() + "'='" + val + "'");
					}
				}
			}
			
			String userID = entry.getAttribute(cfg.getProvisioningEngine().getUserIDAttribute()).getStringValue();
			
			if (entry.getAttribute("mail") == null) {
				StringBuffer b = new StringBuffer();
				b.append("No email address for ").append(dn);
				logger.warn(b.toString());
			} else {
				String mail = entry.getAttribute("mail").getStringValue();
				
				if (sendNotification) {
					cfg.getProvisioningEngine().sendNotification(mail, emailTemplate,new User(entry));
				}
			}
			
			return getApprover(approval,emailTemplate,cfg,session, userID,entry);
			
			
		} catch (LDAPReferralException le) {
			
			StringBuffer b = new StringBuffer();
			b.append("DN : '").append(dn).append("' not found");
			logger.warn(b.toString());
			return null;
		
		} catch (LDAPException le) {
			if (le.getResultCode() == 32) {
				StringBuffer b = new StringBuffer();
				b.append("DN : '").append(dn).append("' not found");
				logger.warn(b.toString());
				return null;
			} else {
				throw new ProvisioningException("could not create approver",le);
			}
		}   catch (Exception e) {
			throw new ProvisioningException("Could not create approver",e);
		}
	}

	public static Approvers getApprover(Approvals approval,String emailTemplate,ConfigManager cfg,Session session, String userID,LDAPEntry approver)
			throws SQLException {
		
		
		Query query = session.createQuery("FROM Approvers WHERE userKey = :user_key");
		query.setParameter("user_key", userID);
		List<Approvers> approvers = query.list();
		Approvers approverObj = null;
		
		
		
		
		if (logger.isDebugEnabled()) {
			logger.debug("Approver UserID : " + userID);
		}
		
		
		int approverID;
		
		if (approvers.size() == 0) {
			
			approverObj = new Approvers();
			approverObj.setUserKey(userID);
			session.save(approverObj);
			
			
			approverID = approverObj.getId();
		} else {
			approverObj = approvers.get(0);
			approverID = approverObj.getId();
		}
		
		
		
		
		
		
		
		
		boolean changed = false;
		
		for (String attrName : cfg.getProvisioningEngine().getApproverAttributes()) {
			
			boolean found = false;
			
			for (ApproverAttributes appAttr : approverObj.getApproverAttributeses()) {
				if (attrName.equalsIgnoreCase(appAttr.getName())) {
					found = true;
					LDAPAttribute approverAttr = approver.getAttribute(attrName);
					if (approverAttr != null) {
						if (! approverAttr.getStringValue().equals(appAttr.getValue())) {
							appAttr.setValue(approverAttr.getStringValue());
							session.save(appAttr);
						}
					}
					
				}
			}
			
			if (! found) {
				ApproverAttributes attr = new ApproverAttributes();
				attr.setName(attrName);
				LDAPAttribute approverAttr = approver.getAttribute(attrName);
				if (approverAttr != null) {
					attr.setValue(approverAttr.getStringValue());
					attr.setApprovers(approverObj);
					approverObj.getApproverAttributeses().add(attr);
					session.save(attr);
				} 
				
				changed = true;
			}
			
		}
		
		return approverObj;
		
		
	}

	public static boolean loadCustomApprovers(Approvals approval, String emailTemplate,
			ConfigManager cfg, Session session, int userID,
			String constraint, boolean sendNotification,CustomAuthorization caz,String customParams[]) throws ProvisioningException {
		boolean found = false;
		try {
			caz.loadConfigManager(cfg);
		
			
			
			List<String> approvalDNs = caz.listPossibleApprovers(customParams);
			for (String approverDN : approvalDNs) {
				
				Approvers approver = getApproverByDN(approval,emailTemplate,cfg,session,approverDN,sendNotification);
				if (approver == null) {
					continue;
				}
				
				AllowedApprovers allowed = new AllowedApprovers();
				allowed.setApprovals(approval);
				allowed.setApprovers(approver);
				session.save(allowed);
				
				found = true;
			}
			
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not load approvers",e);
		}
		
		
		return found;
			
		
		
	}
}
