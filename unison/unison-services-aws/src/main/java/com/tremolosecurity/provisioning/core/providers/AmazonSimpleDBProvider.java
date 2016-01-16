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


package com.tremolosecurity.provisioning.core.providers;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.Iterator;
import java.util.List;

import org.apache.log4j.Logger;

import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.simpledb.AmazonSimpleDBClient;
import com.amazonaws.services.simpledb.model.CreateDomainRequest;
import com.amazonaws.services.simpledb.model.DeleteAttributesRequest;
import com.amazonaws.services.simpledb.model.GetAttributesRequest;
import com.amazonaws.services.simpledb.model.GetAttributesResult;
import com.amazonaws.services.simpledb.model.Item;
import com.amazonaws.services.simpledb.model.PutAttributesRequest;
import com.amazonaws.services.simpledb.model.ReplaceableAttribute;
import com.amazonaws.services.simpledb.model.SelectRequest;
import com.amazonaws.services.simpledb.model.SelectResult;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPModification;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.UserStoreProvider;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.saml.Attribute;



public class AmazonSimpleDBProvider implements UserStoreProvider {

	static Logger logger = Logger.getLogger(AmazonSimpleDBProvider.class);
	AmazonSimpleDBClient sdb;
	String accessKey;
	String secretKey;
	String uidAttrName;
	String userDomain;
	String groupDomain;
	private String groupAttrName;
	private ConfigManager cfgMgr;
	
	String name;
	
	public static  Set<String> CN = new HashSet<String>();
	
	static {
		CN.add("cn");
	}
	
	@Override
	public void createUser(User user, Set<String> attributes,Map<String,Object> request)
			throws ProvisioningException {
		
		
		int approvalID = 0;
		
		
		
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		Iterator<String> it = user.getAttribs().keySet().iterator();
		
		String userid = null;
		
		ArrayList<ReplaceableAttribute> attrs = new ArrayList<ReplaceableAttribute>();
		
		while (it.hasNext()) {
			String attrName = it.next();
			if (attributes.contains(attrName)) {
				Attribute attr = user.getAttribs().get(attrName);
				
				Iterator<String> vals = attr.getValues().iterator();
				while (vals.hasNext()) {
					attrs.add(new ReplaceableAttribute(attr.getName().toLowerCase(),vals.next(),false));
				}
				
				
			}
			
			if (attrName.equalsIgnoreCase(this.uidAttrName)) {
				userid = user.getAttribs().get(attrName).getValues().get(0);
			}
			
		}
		
		if (userid == null) {
			throw new ProvisioningException("No valid userid attribute");
		}
		
		sdb.putAttributes(new PutAttributesRequest(this.userDomain,userid,attrs));

		this.cfgMgr.getProvisioningEngine().logAction(this.name,true, ActionType.Add, approvalID, workflow, "userName", userid);
		
		for (String attrName : user.getAttribs().keySet()) {
			Attribute attr = user.getAttribs().get(attrName);
			if (! attributes.contains(attr.getName())) {
				continue;
			}
			
			this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Add, approvalID, workflow, attrName, user.getAttribs().get(attrName).getValues().get(0));
			
		}
		
		boolean ok = false;
		while (!ok) {
			try {
				Thread.sleep(10);
			} catch (InterruptedException e) {
				
			}
			
			try {
				if (this.findUser(userid, attributes,request) != null) {
					ok = true;
				} else {
					
				}
			} catch (Exception e) {
				
			}
			
		}
		
		Iterator<String> groupNames = user.getGroups().iterator();
		
		while (groupNames.hasNext()) {
			String groupName = groupNames.next();
			
			SelectResult res = this.sdb.select(new SelectRequest(this.getGroupSelect(groupName)));
			
			if (res.getItems().size() == 0) {
				attrs = new ArrayList<ReplaceableAttribute>();
				attrs.add(new ReplaceableAttribute("cn",groupName,false));
				sdb.putAttributes(new PutAttributesRequest(groupDomain,groupName,attrs));
			}
			
			attrs = new ArrayList<ReplaceableAttribute>();
			attrs.add(new ReplaceableAttribute("uniquemember",userid,false));
			sdb.putAttributes(new PutAttributesRequest(this.groupDomain,groupName,attrs));
			
			this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Add, approvalID, workflow, "group", groupName);
			
			
			ok = false;
			while (! ok) {
				try {
					Thread.sleep(1000);
				} catch (InterruptedException e) {
					
				}
				
				StringBuffer select = new StringBuffer();
				select.append("SELECT uniquemember FROM `").append(this.groupDomain).append("` WHERE cn='").append(groupName).append("' AND uniquemember='").append(userid).append("'");
				
				res = this.sdb.select(new SelectRequest(select.toString()));
				
				ok = res.getItems().size() > 0;
			}
			
		}
		
		
	}

	@Override
	public void syncUser(User user, boolean addOnly, Set<String> attributes,Map<String,Object> request)
			throws ProvisioningException {
		User amazonUser = this.findUser(user.getAttribs().get(this.uidAttrName).getValues().get(0), attributes,request);
		if (amazonUser == null) {
			this.createUser(user, attributes,request);
			return;
		}
		
		
		int approvalID = 0;
		
		
		
		
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		String userid = user.getAttribs().get(this.uidAttrName).getValues().get(0);
		
		
		Set<String> done = new HashSet<String>();
		
		Iterator<String> amazonAttrNames = amazonUser.getAttribs().keySet().iterator();
		while (amazonAttrNames.hasNext()) {
			String amznAttrName = amazonAttrNames.next();
			done.add(amznAttrName);
			Attribute userAttr = user.getAttribs().get(amznAttrName);
			if (userAttr == null) {
				if (addOnly) {
					//do nothing
				} else {
					ArrayList<com.amazonaws.services.simpledb.model.Attribute> list = new ArrayList<com.amazonaws.services.simpledb.model.Attribute>();
					list.add(new com.amazonaws.services.simpledb.model.Attribute(amznAttrName.toLowerCase(),null));
					sdb.deleteAttributes(new DeleteAttributesRequest(this.userDomain,amazonUser.getUserID(),list));
					boolean ok = false;
					while (! ok) {
						try {
							Thread.sleep(500);
						} catch (InterruptedException e) {
							
						}
						
						StringBuffer select = new StringBuffer();
						select.append("SELECT uid FROM `").append(this.userDomain).append("` WHERE uid='").append(userid).append("' AND ").append(amznAttrName).append(" IS NOT NULL");
						
						SelectResult res = this.sdb.select(new SelectRequest(select.toString()));
						
						ok = res.getItems().size() == 0;
					}
				}
			} else {
				Set<String> vals = new HashSet<String>();
				vals.addAll(userAttr.getValues());
				
				List<String> amznVals = amazonUser.getAttribs().get(amznAttrName).getValues();
				
				
				
				for (String val : amznVals) {
					
					if (vals.contains(val)) {
						vals.remove(val);
					} else {
						if (! addOnly ) {
							ArrayList<com.amazonaws.services.simpledb.model.Attribute> list = new ArrayList<com.amazonaws.services.simpledb.model.Attribute>();
							list.add(new com.amazonaws.services.simpledb.model.Attribute(userAttr.getName().toLowerCase(),val));
							sdb.deleteAttributes(new DeleteAttributesRequest(this.userDomain,amazonUser.getUserID(),list));
							this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Delete, approvalID, workflow, userAttr.getName().toLowerCase(), val);
							boolean ok = false;
							while (! ok) {
								try {
									Thread.sleep(500);
								} catch (InterruptedException e) {
									
								}
								
								StringBuffer select = new StringBuffer();
								select.append("SELECT uid FROM `").append(this.userDomain).append("` WHERE uid='").append(userid).append("' AND ").append(userAttr.getName().toLowerCase()).append("='").append(val).append("'");
								
								SelectResult res = this.sdb.select(new SelectRequest(select.toString()));
								
								ok = res.getItems().size() == 0;
							}
						}
					}
				}
				
				if (vals.size() > 0) {
					ArrayList<com.amazonaws.services.simpledb.model.ReplaceableAttribute> list = new ArrayList<com.amazonaws.services.simpledb.model.ReplaceableAttribute>();
					
					
					
					Iterator<String> itv = vals.iterator();
					
					while (itv.hasNext()) {
						String val = itv.next();
						list.add(new com.amazonaws.services.simpledb.model.ReplaceableAttribute(userAttr.getName().toLowerCase(),val,false));
					}
					
					sdb.putAttributes(new PutAttributesRequest(this.userDomain,amazonUser.getUserID(),list));
					
					itv = vals.iterator();
					
					while (itv.hasNext()) {
						String val = itv.next();
						this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Replace, approvalID, workflow, userAttr.getName().toLowerCase(), val);
					}
					
					
					
					try {
						Thread.sleep(1000);
					} catch (InterruptedException e) {
						
					}
				
				}
				
				
			
			}
			
			Iterator<String> itattr = user.getAttribs().keySet().iterator();
			while (itattr.hasNext()) {
				String name = itattr.next();
				if (attributes.contains(name) && ! done.contains(name))  {
					ArrayList<com.amazonaws.services.simpledb.model.ReplaceableAttribute> list = new ArrayList<com.amazonaws.services.simpledb.model.ReplaceableAttribute>();
					for (String val : user.getAttribs().get(name).getValues()) {
						list.add(new com.amazonaws.services.simpledb.model.ReplaceableAttribute(name.toLowerCase(),val,false));
					}
					
					sdb.putAttributes(new PutAttributesRequest(this.userDomain,amazonUser.getUserID(),list));
					
					for (String val : user.getAttribs().get(name).getValues()) {
						this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Add, approvalID, workflow, name, val);
					}
					
					try {
						Thread.sleep(1000);
					} catch (InterruptedException e) {
						
					}
				}
			}
			
			String select = this.getGroupSelect(amazonUser.getUserID());
			
			SelectResult res = this.sdb.select(new SelectRequest(select));
			done.clear();
			for (Item group : res.getItems()) {
				String name = group.getName();
				if (! user.getGroups().contains(name) && ! addOnly) {
					ArrayList<com.amazonaws.services.simpledb.model.Attribute> list = new ArrayList<com.amazonaws.services.simpledb.model.Attribute>();
					list.add(new com.amazonaws.services.simpledb.model.Attribute("uniquemember",amazonUser.getUserID()));
					sdb.deleteAttributes(new DeleteAttributesRequest(this.groupDomain,name,list));
					
					this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Delete, approvalID, workflow, "group",name);
					try {
						Thread.sleep(500);
					} catch (InterruptedException e) {
						
					}
				}
				
				done.add(name);
			}
			
			
			for (String groupName : user.getGroups()) {
				if (done.contains(groupName)) {
					continue;
				}
				
				ArrayList<com.amazonaws.services.simpledb.model.ReplaceableAttribute> list = new ArrayList<com.amazonaws.services.simpledb.model.ReplaceableAttribute>();
				list.add(new com.amazonaws.services.simpledb.model.ReplaceableAttribute("uniquemember",amazonUser.getUserID(),false));
				sdb.putAttributes(new PutAttributesRequest(this.groupDomain,groupName,list));
				this.cfgMgr.getProvisioningEngine().logAction(this.name,false, ActionType.Add, approvalID, workflow, "group",groupName);
			}
			
			
		}
		
		

	}

	@Override
	public void deleteUser(User user,Map<String,Object> request) throws ProvisioningException {
		
		
		int approvalID = 0;
		
		
		
		
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		String userid = user.getAttribs().get(this.uidAttrName).getValues().get(0);
		this.sdb.deleteAttributes(new DeleteAttributesRequest(this.userDomain,userid));
		this.cfgMgr.getProvisioningEngine().logAction(this.name,true, ActionType.Delete, approvalID, workflow, "userName",userid);
		try {
			Thread.sleep(1000);
		} catch (InterruptedException e) {
			
		}
	}

	@Override
	public User findUser(String userID, Set<String> attributes,Map<String,Object> request)
			throws ProvisioningException {
		
		String select = this.getUserSelect(userID,attributes);
		if (logger.isDebugEnabled()) {
			logger.debug("SELECT : \"" + select + "\"");
		}
		
		SelectResult res = this.sdb.select(new SelectRequest(select));
		
		if (res.getItems().size() == 0) {
			return null;
			
		}
		
		Item item = res.getItems().get(0);
		
		Map<String,Attribute> attrs = new HashMap<String,Attribute>();
		List<com.amazonaws.services.simpledb.model.Attribute> itemAttrs = item.getAttributes();
		Iterator<com.amazonaws.services.simpledb.model.Attribute> it = itemAttrs.iterator();
		
		while (it.hasNext()) {
			com.amazonaws.services.simpledb.model.Attribute itemAttr = it.next();
			String name = itemAttr.getName();
			String value = itemAttr.getValue();
			Attribute attr = attrs.get(name);
			if (attr == null) {
				attr = new Attribute(name);
				attrs.put(name, attr);
			}
			attr.getValues().add(value);
			
		}
		
		User user = new User(attrs.get(this.uidAttrName).getValues().get(0));
		user.getAttribs().putAll(attrs);
		
		select = this.getGroupSelect(userID);
		
		res = this.sdb.select(new SelectRequest(select));
		
		for (Item group : res.getItems()) {
			String name = group.getName();
			user.getGroups().add(name);
		}
		
		return user;
		
	}

	
	private String getUserSelect(String userID,Set<String> attributes) {
		return this.getSelect(this.userDomain, this.uidAttrName, userID, attributes);
	}
	
	private String getGroupSelect(String userID) {
		return this.getSelect(groupDomain, "uniqueMember", userID, AmazonSimpleDBProvider.CN);
	}
	
	private String getSelect(String domain,String attrName,String attrId,Set<String> attributes) {
		StringBuffer buf = new StringBuffer();
		buf.append("SELECT ");
		
		Iterator<String> it = attributes.iterator();
		while (it.hasNext()) {
			buf.append(it.next().toLowerCase());
			if (it.hasNext()) {
				buf.append(",");
			}
		}
		
		buf.append(" FROM `").append(domain).append("` WHERE ").append(attrName.toLowerCase()).append("='").append(attrId).append("'");
		return buf.toString();
	}
	
	@Override
	public void init(Map<String, Attribute> cfg,ConfigManager cfgMgr,String name)
			throws ProvisioningException {
		
		this.name = name;
		
		this.cfgMgr = cfgMgr;
		this.userDomain = cfg.get("userDomain").getValues().get(0);
		this.groupDomain = cfg.get("groupDomain").getValues().get(0);
		
		this.accessKey = cfg.get("accessKey").getValues().get(0);
		this.secretKey = cfg.get("secretKey").getValues().get(0);
		this.uidAttrName = cfg.get("uidAttributeName").getValues().get(0);
		
		
		sdb = new AmazonSimpleDBClient(new BasicAWSCredentials(accessKey,secretKey));
		

	}

	@Override
	public void setUserPassword(User user,Map<String,Object> request) throws ProvisioningException {
		// TODO Auto-generated method stub
		
	}

}
