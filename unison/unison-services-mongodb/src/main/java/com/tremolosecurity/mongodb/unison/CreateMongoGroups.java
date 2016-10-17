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
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.Logger;
import org.bson.Document;

import com.mongodb.MongoClient;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;
import static com.mongodb.client.model.Filters.*;

public class CreateMongoGroups implements CustomTask {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(CreateMongoGroups.class.getName());
	
	String collectionName;
	String targetName;
	List<String> requestAttributes;
	
	transient WorkflowTask task;
	transient MongoDBTarget target;
	
	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		this.task = task;
		this.collectionName = params.get("collectionName").getValues().get(0);
		this.targetName = params.get("targetName").getValues().get(0);
		this.requestAttributes = new ArrayList<String>();
		
		if (params.get("requestAttributes") != null) {
			this.requestAttributes.addAll(params.get("requestAttributes").getValues());
		}
		
		this.target = (MongoDBTarget) task.getConfigManager().getProvisioningEngine().getTarget(targetName).getProvider();
	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		this.task = task;
		this.target = (MongoDBTarget) task.getConfigManager().getProvisioningEngine().getTarget(targetName).getProvider();
	}

	@Override
	public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
		
		 
		
		MongoClient client = this.target.getMongo();
		
		Iterable<String> toCheck = user.getGroups();
		
		checkGroups(user, client, toCheck);
		
		ArrayList<String> vals = new ArrayList<String>();
		
		for (String attributeName : this.requestAttributes) {
			if (request.get(attributeName) != null) {
				vals.add((String) request.get(attributeName));
			}
			
		}
		
		checkGroups(user, client, vals);
		
		
		return true;
	}

	private void checkGroups(User user, MongoClient client,
			Iterable<String> toCheck) {
		
		HashSet<String> groupsThatDontExist = new HashSet<String>();
		
		for (String collectionName : client.getDatabase(this.target.getDatabaseName()).listCollectionNames()) {
			for (String groupName : toCheck) {
				if (client.getDatabase(this.target.getDatabaseName()).getCollection(collectionName).find(and( eq("objectClass",this.target.getGroupObjectClassName()) , eq(this.target.getGroupNameAttribute() , groupName ) ) ).first() == null) {
					groupsThatDontExist.add(groupName);
				}
			}
		}
		
		for (String groupName : groupsThatDontExist) {
			Document doc = new Document();
			doc.append("unisonRdnAttributeName",target.getGroupNameAttribute());
			doc.append("objectClass", target.getGroupObjectClassName());
			doc.append(target.getGroupNameAttribute(), groupName);
			client.getDatabase(target.getDatabaseName()).getCollection(collectionName).insertOne(doc);
			logger.warn("Group created : '" + groupName + "'");
		}
	}

}
