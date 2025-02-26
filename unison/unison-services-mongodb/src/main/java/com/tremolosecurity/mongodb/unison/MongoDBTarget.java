/*******************************************************************************
 * Copyright 2016 Tremolo Security, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.tremolosecurity.mongodb.unison;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.logging.log4j.Logger;
import org.bson.Document;
import org.bson.types.ObjectId;

import com.mongodb.DB;
import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import com.mongodb.client.FindIterable;
import com.mongodb.client.ListCollectionsIterable;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoIterable;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.UserStoreProvider;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.server.StopableThread;
import static com.mongodb.client.model.Filters.*;

public class MongoDBTarget implements UserStoreProvider {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(MongoDBTarget.class.getName());
	
	String name;
	String database;
	String collectionAttributeName;
	
	String userObjectClass;
	String userRDN;
	String userIdAttribute;
	
	String groupIdAttribute;
	String groupObjectClass;
	String groupRDN;
	String groupMemberAttribute;
	String groupUserIdAttribute;
	
	boolean supportExternalUsers;
	
	MongoClient mongo;

	private ConfigManager cfgMgr;
	

	public MongoClient getMongo() {
		return this.mongo;
	}
	
	public void createUser(User user, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		Document doc = new Document();
		String collection = null;
		
		String groupIdAttr = null;
		
		for (String attr : attributes) {
			if (user.getAttribs().containsKey(attr)) {
				if (attr.equalsIgnoreCase(this.collectionAttributeName)) {
					collection = user.getAttribs().get(attr).getValues().get(0);
				} else {
					
					if (attr.equalsIgnoreCase(this.groupUserIdAttribute)) {
						groupIdAttr = user.getAttribs().get(attr).getValues().get(0);
					}
					
					Attribute attribute = user.getAttribs().get(attr);
					if (attribute.getValues().size() == 1) {
						doc.append(attr, attribute.getValues().get(0));
					} else {
						doc.append(attr, attribute.getValues());
					}
				}
			}
		}
		
		doc.append("unisonRdnAttributeName",this.userRDN);
		doc.append("objectClass", this.userObjectClass);
		
		if (collection == null) {
			throw new ProvisioningException("no collection specified");
		} else {
			this.mongo.getDatabase(database).getCollection(collection).insertOne(doc);
		}
		
		this.cfgMgr.getProvisioningEngine().logAction(name,true, ActionType.Add,  approvalID, workflow, "_id", doc.get("_id").toString());
		this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Add,  approvalID, workflow, "unisonRdnAttributeName", this.userRDN);
		this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Add,  approvalID, workflow, "collection", collection);
		
		for (String attr : attributes) {
			if (user.getAttribs().containsKey(attr)) {
				if (attr.equalsIgnoreCase(this.collectionAttributeName)) {
					
				} else {
					Attribute attribute = user.getAttribs().get(attr);
					
					for (String val : attribute.getValues()) {
						this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Add,  approvalID, workflow, attribute.getName(), val);
					}
					
					
				}
			}
		}
		
		addGroupsToUser(user, user.getGroups(),approvalID, workflow);
		
		
		
		
		
		

	}

	private void addGroupsToUser(User user, List<String> groupsToAddTo, int approvalID, Workflow workflow) throws ProvisioningException {
		for (String collectionName : mongo.getDatabase(database).listCollectionNames()) {
			FindIterable<Document> groups = mongo.getDatabase(this.database).getCollection(collectionName).find( and (eq("objectClass",this.groupObjectClass),in(this.groupIdAttribute,groupsToAddTo))  );
			
			for (Document group : groups) {
				Document newGroup = new Document();
				
				Object o = group.get(this.groupMemberAttribute);
				ArrayList<String> groupMembers = new ArrayList<String>();
				if (o != null) {
					if (o instanceof List) {
						groupMembers.addAll((List) o);
					} else {
						groupMembers.add((String) o);
					}
				}
				
				
				
				if (! groupMembers.contains(user.getAttribs().get(this.groupUserIdAttribute).getValues().get(0))) {
					groupMembers.add(user.getAttribs().get(this.groupUserIdAttribute).getValues().get(0));
					
				}
				
				
				if (groupMembers.size() > 1) {
					newGroup.append(this.groupMemberAttribute, groupMembers);
				} else if (groupMembers.size() == 1) {
					newGroup.append(this.groupMemberAttribute, groupMembers.get(0));
				}
				
				if (groupMembers.size() > 0) {
					Document setGroup = new Document("$set",newGroup);
					mongo.getDatabase(database).getCollection(collectionName).updateOne(eq("_id",group.getObjectId("_id")), setGroup);
					this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Add,  approvalID, workflow, "group", group.getString(this.groupIdAttribute));
					
				}
			}
		}
	}
	
	private void rmGroupsFromUser(User user, List<String> groupsToAddTo, int approvalID, Workflow workflow) throws ProvisioningException {
		for (String collectionName : mongo.getDatabase(database).listCollectionNames()) {
			FindIterable<Document> groups = mongo.getDatabase(this.database).getCollection(collectionName).find( and (eq("objectClass",this.groupObjectClass),in(this.groupIdAttribute,groupsToAddTo))  );
			
			for (Document group : groups) {
				Document newGroup = new Document();
				
				Object o = group.get(this.groupMemberAttribute);
				ArrayList<String> groupMembers = new ArrayList<String>();
				if (o != null) {
					if (o instanceof List) {
						groupMembers.addAll((List) o);
					} else {
						groupMembers.add((String) o);
					}
				}
				
				
				
				if (groupMembers.contains(user.getAttribs().get(this.groupUserIdAttribute).getValues().get(0))) {
					groupMembers.remove(user.getAttribs().get(this.groupUserIdAttribute).getValues().get(0));
					
				}
				
				
				if (groupMembers.size() > 1) {
					newGroup.append(this.groupMemberAttribute, groupMembers);
				} else if (groupMembers.size() == 1) {
					newGroup.append(this.groupMemberAttribute, groupMembers.get(0));
				} else {
					newGroup.append(this.groupMemberAttribute, "");
				}
				
				if (groupMembers.size() > 0) {
					Document setGroup = new Document("$set",newGroup);
					mongo.getDatabase(database).getCollection(collectionName).updateOne(eq("_id",group.getObjectId("_id")), setGroup);
					this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Delete,  approvalID, workflow, "group", group.getString(this.groupIdAttribute));
					
				} else {
					Document setGroup = new Document("$unset",newGroup);
					mongo.getDatabase(database).getCollection(collectionName).updateOne(eq("_id",group.getObjectId("_id")), setGroup);
					this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Delete,  approvalID, workflow, "group", group.getString(this.groupIdAttribute));
				}
			}
		}
	}

	public void setUserPassword(User user, Map<String, Object> request) throws ProvisioningException {
		throw new ProvisioningException("Password not supported");

	}

	public void syncUser(User user, boolean addOnly, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		
		
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		User fromServer = this.findUser(user.getUserID(), attributes, request);
		
		if (fromServer == null || ((! this.supportExternalUsers) && (! fromServer.getAttribs().containsKey("_id")))) {
			this.createUser(user, attributes, request);
		} else {
			if (user.getAttribs().containsKey("_id")) {
				updateAttributes(user, addOnly, attributes, approvalID, workflow, fromServer);
			}
			
			updateGroups(user, addOnly, approvalID, workflow, fromServer);
			
			
		}

	}

	private void updateGroups(User user, boolean addOnly, int approvalID, Workflow workflow, User fromServer)
			throws ProvisioningException {
		ArrayList<String> groupsToAdd = new ArrayList<String>();
		ArrayList<String> groupsToRm = new ArrayList<String>();
		for (String groupFromUser : user.getGroups()) {
			if (! fromServer.getGroups().contains(groupFromUser)) {
				groupsToAdd.add(groupFromUser);
			}
		}
		
		if (! addOnly) {
			for (String groupFromServer : fromServer.getGroups()) {
				if (! user.getGroups().contains(groupFromServer)) {
					groupsToRm.add(groupFromServer);
				}
			}
		}
		
		if (! groupsToAdd.isEmpty()) {
			this.addGroupsToUser(user, groupsToAdd, approvalID, workflow);
		}
		
		if (! groupsToRm.isEmpty()) {
			this.rmGroupsFromUser(user, groupsToRm, approvalID, workflow);
		}
	}

	private void updateAttributes(User user, boolean addOnly, Set<String> attributes, int approvalID, Workflow workflow,
			User fromServer) throws ProvisioningException {
		Document addChanges = new Document();
		Document unsetChanges = new Document();
		HashMap<String,List<String>> valsToAdd = new HashMap<String,List<String>>();
		HashMap<String,List<String>> valsToDel = new HashMap<String,List<String>>();
		
		syncUserToServer(user, addOnly, attributes, fromServer, addChanges, unsetChanges,valsToAdd, valsToDel);
		deleteAttrsFromServer(user, addOnly, attributes, fromServer, unsetChanges, valsToDel);
		
		if (! addChanges.isEmpty()) {
			Document updateAttrs = new Document("$set",addChanges);
			String collection = fromServer.getAttribs().get(this.collectionAttributeName).getValues().get(0);
			String id = fromServer.getAttribs().get("_id").getValues().get(0);
			mongo.getDatabase(this.database).getCollection(collection).updateOne(eq("_id",new ObjectId(id)), updateAttrs);
		}
		
		if (! unsetChanges.isEmpty()) {
			Document updateAttrs = new Document("$unset",unsetChanges);
			String collection = fromServer.getAttribs().get(this.collectionAttributeName).getValues().get(0);
			String id = fromServer.getAttribs().get("_id").getValues().get(0);
			mongo.getDatabase(this.database).getCollection(collection).updateOne(eq("_id",new ObjectId(id)), updateAttrs);
		}
		
		
		
		
		for (String attrName : valsToAdd.keySet()) {
			for (String val : valsToAdd.get(attrName)) {
				this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Add,  approvalID, workflow, attrName, val);
			}
		}
		
		for (String attrName : valsToDel.keySet()) {
			for (String val : valsToDel.get(attrName)) {
				this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Delete,  approvalID, workflow, attrName, val);
			}
		}
	}

	private void deleteAttrsFromServer(User user, boolean addOnly, Set<String> attributes, User fromServer,
			Document unsetChanges, HashMap<String, List<String>> valsToDel) {
		if (! addOnly) {
			for (String attrNameFromServer : fromServer.getAttribs().keySet()) {
				if (attributes.contains(attrNameFromServer)) {
					Attribute attrFromServer = fromServer.getAttribs().get(attrNameFromServer);
					Attribute attrFromUser = user.getAttribs().get(attrNameFromServer);
					if (attrFromUser == null) {
						//attribute to be removed
						ArrayList<String> vals = new ArrayList<String>();
						vals.addAll(attrFromServer.getValues());
						valsToDel.put(attrNameFromServer, vals);
						unsetChanges.append(attrNameFromServer, "");
					}
				}
			}
		}
	}

	private void syncUserToServer(User user, boolean addOnly, Set<String> attributes, User fromServer,
			Document addChanges, Document unsetChanges, HashMap<String, List<String>> valsToAdd, HashMap<String, List<String>> valsToDel) {
		for (String attrNameFromUser : user.getAttribs().keySet()) {
			
			
			if (attributes.contains(attrNameFromUser) && ! attrNameFromUser.equalsIgnoreCase(this.collectionAttributeName) && ! attrNameFromUser.equalsIgnoreCase("_id")) {
				Attribute attrFromUser = user.getAttribs().get(attrNameFromUser);
				Attribute attrFromServer = fromServer.getAttribs().get(attrNameFromUser);
				
				if (attrFromServer == null) {
					//doesnt exist, need to do an add
					addChanges.append(attrNameFromUser, attrFromUser.getValues());
					valsToAdd.put(attrNameFromUser, attrFromUser.getValues());
				} else {
					ArrayList<String> attrValsToAdd = new ArrayList<String>();
					ArrayList<String> attrValsToRm = new ArrayList<String>();
					HashSet<String> valsFromServer = new HashSet<String>();
					
					for (String val : fromServer.getAttribs().get(attrNameFromUser).getValues()) {
						valsFromServer.add(val.toLowerCase());
					}
					
					for (String valUser : user.getAttribs().get(attrNameFromUser).getValues()) {
						if (! valsFromServer.contains(valUser.toLowerCase())) {
							//add the value
							attrValsToAdd.add(valUser);
						}
					}
					
					if (! addOnly) {
						HashSet<String> valsFromUser = new HashSet<String>();
						for (String val : user.getAttribs().get(attrNameFromUser).getValues()) {
							valsFromUser.add(val.toLowerCase());
						}
						
						for (String val : fromServer.getAttribs().get(attrNameFromUser).getValues()) {
							if (! valsFromUser.contains(val.toLowerCase())) {
								attrValsToRm.add(val);
							}
						}
					}
					
					
					if (! attrValsToAdd.isEmpty() || ! attrValsToRm.isEmpty()) {
					
						ArrayList<String> newVals = new ArrayList<String>();
						newVals.addAll(fromServer.getAttribs().get(attrNameFromUser).getValues());
						
						newVals.removeAll(attrValsToRm);
						newVals.addAll(attrValsToAdd);
						
						valsToAdd.put(attrNameFromUser, attrValsToAdd);
						if (! attrValsToRm.isEmpty()) {
							valsToDel.put(attrNameFromUser, attrValsToRm);
						}
						
						if (newVals.isEmpty()) {
							unsetChanges.append(attrNameFromUser, "");
						} else {
							if (newVals.size() > 1) {
								addChanges.append(attrNameFromUser, newVals);
							} else {
								addChanges.append(attrNameFromUser, newVals.get(0));
							}
							
						}
					}
					
				}
			} 
		}
	}

	public void deleteUser(User user, Map<String, Object> request) throws ProvisioningException {
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		
		if (! user.getAttribs().containsKey(this.groupUserIdAttribute)) {
			HashSet<String> attrs = new HashSet<String>();
			attrs.add(this.userIdAttribute);
			attrs.add(this.groupUserIdAttribute);
			user = this.findUser(user.getUserID(), attrs, request);
			if (user == null) {
				return;
			}
		}
		

		
		String groupMemberID = user.getAttribs().get(this.groupUserIdAttribute).getValues().get(0);
		
		MongoIterable<String> collections = mongo.getDatabase(this.database).listCollectionNames();
		for (String collection : collections) {
			Document deleted = mongo.getDatabase(this.database).getCollection(collection).findOneAndDelete(and(eq("objectClass",this.userObjectClass),eq(this.userIdAttribute,user.getUserID())));
			if (deleted != null) {
				this.cfgMgr.getProvisioningEngine().logAction(name,true, ActionType.Delete,  approvalID, workflow, "_id", deleted.get("_id").toString());
			} else {
				//check to see if any groups references this object
				FindIterable<Document> groups = mongo.getDatabase(this.database).getCollection(collection).find(and(eq("objectClass", this.groupObjectClass), eq(this.groupMemberAttribute, groupMemberID)));
				for (Document group : groups) {
					Object o = group.get(this.groupMemberAttribute);
					if (o instanceof String) {
						//one value, not mine
						Document newVals = new Document();
						newVals.append(this.groupMemberAttribute, "");
						Document setGroup = new Document("$unset", newVals);
						mongo.getDatabase(database).getCollection(collection).updateOne(eq("_id", group.getObjectId("_id")), setGroup);
						this.cfgMgr.getProvisioningEngine().logAction(name, false, ActionType.Delete, approvalID, workflow, "group", group.getString(this.groupIdAttribute));
					} else {
						List<String> members = (List<String>) o;
						members.remove(groupMemberID);
						Document newVals = new Document();
						newVals.append(this.groupMemberAttribute, members);
						Document setGroup = new Document("$set", newVals);
						mongo.getDatabase(database).getCollection(collection).updateOne(eq("_id", group.getObjectId("_id")), setGroup);
						this.cfgMgr.getProvisioningEngine().logAction(name, false, ActionType.Delete, approvalID, workflow, "group", group.getString(this.groupIdAttribute));
					}
				}
			}
			
		}

	}

	public User findUser(String userID, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		MongoIterable<String> colNames = mongo.getDatabase(this.database).listCollectionNames();
		
		for (String col : colNames) {
			FindIterable<Document> searchRes = mongo.getDatabase(this.database).getCollection(col).find(and(eq("objectClass",this.userObjectClass),eq(this.userIdAttribute,userID)));
			Document doc = searchRes.first();
			if (doc != null) {
				User user = new User(userID);
				for (String attrName : attributes) {
					Object o = doc.get(attrName);
					if (o != null) {
						if (o instanceof List) {
							List l = (List) o;
							Attribute attr = new Attribute(attrName);
							attr.getValues().addAll(l);
							user.getAttribs().put(attrName, attr);
						} else {
							Attribute attr = new Attribute(attrName);
							attr.getValues().add(o.toString());
							user.getAttribs().put(attrName, attr);
						}
					}
				}
				
				MongoIterable<String> colNamesG = mongo.getDatabase(this.database).listCollectionNames();
				
				for (String colG : colNamesG) {
					
					FindIterable<Document> searchResG = mongo.getDatabase(this.database).getCollection(colG).find(and(eq("objectClass",this.groupObjectClass),eq(this.groupMemberAttribute,doc.getString(this.groupUserIdAttribute))));
					for (Document g : searchResG) {
						user.getGroups().add(g.getString(this.groupIdAttribute));
					}
				}
				
				user.getAttribs().put(this.collectionAttributeName, new Attribute(this.collectionAttributeName,col));
				user.getAttribs().put("_id", new Attribute("_id",doc.getObjectId("_id").toString()));
				
				return user;
			}
		}
		
		//if we're here, there's no entry in the mongo
		if (this.supportExternalUsers) {
			try {
				LDAPSearchResults res = this.searchExternalUser(userID);
				if (! res.hasMore()) {
					return null;
				} else {
					LDAPEntry ldap = res.next();
					while (res.hasMore()) res.next();
					LDAPAttribute attr = ldap.getAttribute(this.groupUserIdAttribute);
					if (attr == null) {
						return null;
					}
					String groupMemberID = attr.getStringValue();
					User user = new User(userID);
					user.getAttribs().put(this.userIdAttribute, new Attribute(this.userIdAttribute,userID));
					
					MongoIterable<String> colNamesG = mongo.getDatabase(this.database).listCollectionNames();
					
					for (String colG : colNamesG) {
						
						FindIterable<Document> searchResG = mongo.getDatabase(this.database).getCollection(colG).find(and(eq("objectClass",this.groupObjectClass),eq(this.groupMemberAttribute,groupMemberID)));
						for (Document g : searchResG) {
							user.getGroups().add(g.getString(this.groupIdAttribute));
						}
					}
					
					
					return user;
					
					
					
					
				}
			} catch (LDAPException e) {
				throw new ProvisioningException("Error searching for external user",e);
			}
		} else {
			return null;
		}
		
		
		
	}
	
	private LDAPSearchResults searchExternalUser(String userID)
			throws LDAPException {
		LDAPSearchResults res;
		ArrayList<String> attrs = new ArrayList<String>();
		attrs.add(this.groupUserIdAttribute);
		StringBuffer filter = new StringBuffer();
		filter.append("(").append(this.userIdAttribute).append("=").append(userID).append(")");
		res = this.cfgMgr.getMyVD().search(GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getLdapRoot(), 2, filter.toString(), attrs);
		return res;
	}

	public void init(Map<String, Attribute> cfg, ConfigManager cfgMgr, String name) throws ProvisioningException {
		this.cfgMgr = cfgMgr;
		this.name = name;
		this.mongo = new MongoClient(new MongoClientURI(cfg.get("url").getValues().get(0)));
		this.database = cfg.get("database").getValues().get(0);
		
		this.userObjectClass = cfg.get("userObjectClass").getValues().get(0);
		this.userRDN = cfg.get("userRDN").getValues().get(0);
		this.userIdAttribute = cfg.get("userIdAttribute").getValues().get(0);
		this.groupIdAttribute = cfg.get("groupIdAttribute").getValues().get(0);
		this.groupObjectClass = cfg.get("groupObjectClass").getValues().get(0);
		this.groupRDN = cfg.get("groupRDN").getValues().get(0);
		this.groupMemberAttribute = cfg.get("groupMemberAttribute").getValues().get(0);
		this.groupUserIdAttribute = cfg.get("groupUserIdAttribute").getValues().get(0);
		this.supportExternalUsers = cfg.get("supportExternalUsers").getValues().get(0).equalsIgnoreCase("true");
		this.collectionAttributeName = cfg.get("collectionAttributeName").getValues().get(0);
		
		cfgMgr.addThread(new StopableThread() {

			public void run() {
				
				
			}

			public void stop() {
				mongo.close();
				
			}});

	}

	public String getDatabaseName() {
		return this.database;
	}

	public Object getGroupObjectClassName() {
		return this.groupObjectClass;
	}

	public String getGroupNameAttribute() {
		return this.groupRDN;
	}

	@Override
	public void shutdown() throws ProvisioningException {
		this.mongo.close();
		
	}

}
