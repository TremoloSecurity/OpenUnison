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


package com.tremolosecurity.provisioning.util;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPReferralException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.proxy.az.CustomAuthorization;

public class AzUtils {
	static Logger logger = Logger.getLogger(AzUtils.class);
	
	
	
	
	
	
	
	

	

	public static boolean loadDNApprovers(int approvalId,String emailTemplate,ConfigManager cfg,Connection con, int id2, String constraint,boolean sendNotification) throws ProvisioningException {
		ArrayList<String> attrs = new ArrayList<String>();
		attrs.add(cfg.getProvisioningEngine().getUserIDAttribute());
		LDAPSearchResults res = null;
		LDAPEntry entry = null;
		
		boolean found = false;
		
		try {
			res = cfg.getMyVD().search(constraint, 2, "(objectClass=inetOrgPerson)", attrs);
			
			PreparedStatement ps = con.prepareStatement("INSERT INTO allowedApprovers(approval,approver) VALUES (?,?)");
			
			
				
			
			
			
			
			while (res.hasMore()) {
				entry = res.next();
				
				
				int approverID = getApproverIDByDN(approvalId,emailTemplate,cfg,con, entry.getDN(),sendNotification);
				if (approverID == -1) {
					continue;
				}
				
				found = true;
				
				ps.setInt(1, approvalId);
				ps.setInt(2, approverID);
				ps.executeUpdate();
			}
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not find approvers",e);
		}
		
		return found;
		
	}

	public static boolean loadFilterApprovers(int approvalId,String emailTemplate,ConfigManager cfg,Connection con, int id, String constraint,boolean sendNotification) throws ProvisioningException {
		ArrayList<String> attrs = new ArrayList<String>();
		//attrs.add(cfg.getProvisioningEngine().getUserIDAttribute());
		LDAPSearchResults res = null;
		LDAPEntry entry = null;
		boolean found = false;
		
		try {
			res = cfg.getMyVD().search("o=Tremolo", 2, constraint, attrs);
			
			PreparedStatement ps = con.prepareStatement("INSERT INTO allowedApprovers(approval,approver) VALUES (?,?)");
			
			
				
			
			
			
			
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
				
				int approverID = getApproverID(approvalId,emailTemplate,cfg,con,uid,entry);
				if (approverID == -1) {
					continue;
				}
				
				found = true;
				
				ps.setInt(1, id);
				ps.setInt(2, approverID);
				ps.executeUpdate();
			}
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not find approvers",e);
		}
		
		
		return found;
	
		
	}

	public static boolean loadStaticGroupApprovers(int approvalId,String emailTemplate,ConfigManager cfg,Connection con, int id, String constraint,boolean sendNotification) throws ProvisioningException {
		ArrayList<String> attrs = new ArrayList<String>();
		attrs.add("uniqueMember");
		LDAPSearchResults res = null;
		LDAPEntry entry = null;
		
		boolean found = false;
		
		try {
			
			res = cfg.getMyVD().search(constraint, 0, "(objectClass=*)", attrs);
			res.hasMore();
			entry = res.next();
		} catch (LDAPException e) {
			throw new ProvisioningException("Could not find group",e);
		}
		
		LDAPAttribute members = entry.getAttribute("uniqueMember");
		String[] dns = members != null ? members.getStringValueArray() : new String[0];
		
		if (dns.length == 0) {
			StringBuffer b = new StringBuffer();
			b.append(constraint).append(" does not have any members");
			logger.warn(b.toString());
		}
		
		try {
			PreparedStatement ps = con.prepareStatement("INSERT INTO allowedApprovers(approval,approver) VALUES (?,?)");
			
			for (String dn : dns) {
				
				int approverID = getApproverIDByDN(approvalId,emailTemplate,cfg,con,dn,sendNotification);
				if (approverID == -1) {
					continue;
				}
				
				ps.setInt(1, id);
				ps.setInt(2, approverID);
				ps.executeUpdate();
				found = true;
			}
			
			ps.close();
		} catch (Exception e) {
			throw new ProvisioningException("Could not load approvers",e);
		}
		
		return found;
		
	}

	public static int getApproverIDByDN(int approvalId,String emailTemplate,ConfigManager cfg,Connection con, String dn,boolean sendNotification) throws ProvisioningException {
		
		
		try {
			ArrayList<String> attrs = new ArrayList<String>();
			//attrs.add(cfg.getProvisioningEngine().getUserIDAttribute());
			
			LDAPSearchResults res = cfg.getMyVD().search(dn, 0, "(objectClass=*)", attrs);
			
			if (! res.hasMore()) {
				if (logger.isDebugEnabled()) {
					logger.debug("Can not find '" + dn + "'");
				}
				return -1;
			}
			
			LDAPEntry entry = res.next();
			
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
			
			int approverID = getApproverID(approvalId,emailTemplate,cfg,con, userID,entry);
			
			return approverID;
		} catch (LDAPReferralException le) {
			
			StringBuffer b = new StringBuffer();
			b.append("DN : '").append(dn).append("' not found");
			logger.warn(b.toString());
			return -1;
		
		} catch (LDAPException le) {
			if (le.getResultCode() == 32) {
				StringBuffer b = new StringBuffer();
				b.append("DN : '").append(dn).append("' not found");
				logger.warn(b.toString());
				return -1;
			} else {
				throw new ProvisioningException("could not create approver",le);
			}
		}   catch (Exception e) {
			throw new ProvisioningException("Could not create approver",e);
		}
	}

	public static int getApproverID(int id,String emailTemplate,ConfigManager cfg,Connection con, String userID,LDAPEntry approver)
			throws SQLException {
		PreparedStatement ps = con.prepareStatement("SELECT id FROM approvers WHERE userKey=?");
		ps.setString(1, userID);
		ResultSet rs = ps.executeQuery();
		
		int approverID;
		
		if (! rs.next()) {
			PreparedStatement psi = con.prepareStatement("INSERT INTO approvers (userKey) VALUES (?)",Statement.RETURN_GENERATED_KEYS);
			psi.setString(1, userID);
			psi.executeUpdate();
			ResultSet keys = psi.getGeneratedKeys();
			keys.next();
			approverID = keys.getInt(1);
			keys.close();
			psi.close();
		} else {
			approverID = rs.getInt("id");
		}
		
		rs.close();
		
		con.setAutoCommit(false);
		for (String attrName : cfg.getProvisioningEngine().getApproverAttributes()) {
			
			if (logger.isDebugEnabled()) {
				logger.debug("Setting approval attribute '" + attrName + "' to '" + approver.getAttribute(attrName).getStringValue() + "' for id " + Integer.toString(approverID));
			}
			
			StringBuffer sb = new StringBuffer("UPDATE approvers SET ").append(attrName).append("=? WHERE id=?");
			PreparedStatement psUpdate = con.prepareStatement(sb.toString());
			psUpdate.setString(
					1, approver.getAttribute(attrName).getStringValue());
			psUpdate.setInt(2, approverID);
			psUpdate.executeUpdate();
		}
		con.commit();
		
		return approverID;
	}

	public static boolean loadCustomApprovers(int approvalId, String emailTemplate,
			ConfigManager cfg, Connection con, int userID,
			String constraint, boolean sendNotification,CustomAuthorization caz) throws ProvisioningException {
		boolean found = false;
		try {
			caz.loadConfigManager(cfg);
			PreparedStatement ps = con.prepareStatement("INSERT INTO allowedApprovers(approval,approver) VALUES (?,?)");
			
			List<String> approvalDNs = caz.listPossibleApprovers();
			for (String approverDN : approvalDNs) {
				
				int approverID = getApproverIDByDN(approvalId,emailTemplate,cfg,con,approverDN,sendNotification);
				if (approverID == -1) {
					continue;
				}
				
				ps.setInt(1, approvalId);
				ps.setInt(2, approverID);
				ps.executeUpdate();
				found = true;
			}
			
			ps.close();
		} catch (Exception e) {
			throw new ProvisioningException("Could not load approvers",e);
		}
		
		
		return found;
			
		
		
	}
}
