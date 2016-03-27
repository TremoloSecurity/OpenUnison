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


package com.tremolosecurity.provisioning.listeners;

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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.jms.JMSException;
import javax.jms.Message;
import javax.jms.ObjectMessage;

import org.apache.log4j.Logger;

import com.cedarsoftware.util.io.JsonReader;
import com.cedarsoftware.util.io.JsonWriter;
import com.google.gson.Gson;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPReferralException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.json.Token;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.UnisonMessageListener;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.tasks.Approval;
import com.tremolosecurity.saml.Attribute;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.*;

public class UpdateApprovalAZListener extends UnisonMessageListener {
	static Logger logger = Logger.getLogger(UpdateApprovalAZListener.class.getName());
	@Override
	public void onMessage(ConfigManager cfg, Object payload,Message msg)
			throws ProvisioningException {
		
		HashMap<Integer,String> approval = null;
	
		approval = (HashMap<Integer,String>)  payload;
		
		
		int approvalID = approval.keySet().iterator().next();
		String workflow = approval.get(approvalID);
		
		Connection con = null;
		try {
			con = cfg.getProvisioningEngine().getApprovalDBConn();
			con.setAutoCommit(false);
			
			this.updateAllowedApprovals(cfg, con, approvalID, workflow);
			
			con.commit();
			
		} catch (Throwable t) {
			try {
				if (con != null) {
					con.rollback();
				}
			} catch (Exception e) {}
			
			throw new ProvisioningException("Could not update approvers",t);
		} finally {
			if (con != null) {
				try {
					con.close();
				} catch (SQLException e) {
					
				}
			}
		}

	}

	@Override
	public void init(ConfigManager cfg, HashMap<String, Attribute> attributes)
			throws ProvisioningException {
		

	}

	private void updateAllowedApprovals(ConfigManager cfg,Connection con, int approvalID,
			String workflowObj) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, ClassNotFoundException, ProvisioningException, SQLException, InvalidAlgorithmParameterException {
		SecretKey decryptionKey = cfg.getSecretKey(cfg.getCfg().getProvisioning().getApprovalDB().getEncryptionKey());
		Gson gson = new Gson();
		Token token = gson.fromJson(workflowObj, Token.class);
		
		byte[] iv = org.bouncycastle.util.encoders.Base64.decode(token.getIv());
		
		
	    IvParameterSpec spec =  new IvParameterSpec(iv);
	    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, decryptionKey,spec);
	    
		byte[] encBytes = org.bouncycastle.util.encoders.Base64.decode(token.getEncryptedRequest());
		
		String json = new String(cipher.doFinal(encBytes));
		Workflow wf = (Workflow) JsonReader.jsonToJava(json);
		
		Approval approval = (Approval) wf.findCurrentApprovalTask();
		
		
		if (approval == null) {
			throw new ProvisioningException("Could not locate approval step");
		}
		
		Set<Integer> currentApprovers = new HashSet<Integer>();
		PreparedStatement findApprovers = con.prepareStatement("SELECT approvers.id,approvers.userKey from allowedApprovers inner join approvers on allowedApprovers.approver=approvers.id WHERE approval=?");
		findApprovers.setInt(1, approvalID);
		ResultSet rsApprovers = findApprovers.executeQuery();
		while (rsApprovers.next()) {
			currentApprovers.add(rsApprovers.getInt("id"));
		}
		rsApprovers.close();
		
		con.setAutoCommit(false);
		PreparedStatement delAllowedApprovers = con.prepareStatement("DELETE FROM allowedApprovers WHERE approval=?");
		delAllowedApprovers.setInt(1, approvalID);
		delAllowedApprovers.executeUpdate();
		delAllowedApprovers.close();
		
		approval.updateAllowedApprovals(con,cfg,wf.getRequest());
		
		//need to write the approval back to the db
		json = JsonWriter.objectToJson(wf);
		
		
		cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, decryptionKey);
		
		
		byte[] encJson = cipher.doFinal(json.getBytes("UTF-8"));
		String base64d = new String(org.bouncycastle.util.encoders.Base64.encode(encJson));
		
		token = new Token();
		token.setEncryptedRequest(base64d);
		token.setIv(new String(org.bouncycastle.util.encoders.Base64.encode(cipher.getIV())));
		
		//String base64 = new String(org.bouncycastle.util.encoders.Base64.encode(baos.toByteArray()));
		
		PreparedStatement ps = con.prepareStatement("UPDATE approvals SET workflowObj=? WHERE id=?");
		ps.setString(1, gson.toJson(token));
		ps.setInt(2, approval.getId());
		ps.executeUpdate();
		
		
		con.commit();
		
		
		findApprovers.setInt(1, approvalID);
		rsApprovers = findApprovers.executeQuery();
		
		while (rsApprovers.next()) {
			int id = rsApprovers.getInt("id");
			if (! currentApprovers.contains(id)) {
				
				
				this.sendNotification(approval.getEmailTemplate(), cfg, con, rsApprovers.getString("userKey"));
			}
		}
		rsApprovers.close();
		
		
	}
	
	private void sendNotification(String emailTemplate,ConfigManager cfg,Connection con, String userKey) throws ProvisioningException {
		
		
		try {
			ArrayList<String> attrs = new ArrayList<String>();
			//attrs.add("mail");
			//attrs.add(cfg.getProvisioningEngine().getUserIDAttribute());
			
			LDAPSearchResults res = cfg.getMyVD().search("o=Tremolo", 2, equal(cfg.getProvisioningEngine().getUserIDAttribute(),userKey).toString(), attrs);
			
			if (! res.hasMore()) {
				if (logger.isDebugEnabled()) {
					logger.debug("Can not find '" + userKey + "'");
				}
				return;
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
				b.append("No email address for ").append(userKey);
				logger.warn(b.toString());
			} else {
				String mail = entry.getAttribute("mail").getStringValue();
				logger.debug("Sedning notification to '" + mail + "'");
				cfg.getProvisioningEngine().sendNotification(mail, emailTemplate,new User(entry));
			}
			
		} catch (LDAPReferralException le) {
			
			StringBuffer b = new StringBuffer();
			b.append("User : '").append(userKey).append("' not found");
			logger.warn(b.toString());
			
		
		} catch (LDAPException le) {
			if (le.getResultCode() == 32) {
				StringBuffer b = new StringBuffer();
				b.append("User : '").append(userKey).append("' not found");
				logger.warn(b.toString());
			} else {
				throw new ProvisioningException("could not create approver",le);
			}
		}   catch (Exception e) {
			throw new ProvisioningException("Could not create approver",e);
		}
	}
}
