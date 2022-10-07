//    Copyright 2020 Tremolo Security, Inc.
// 
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
// 
//        http://www.apache.org/licenses/LICENSE-2.0
// 
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

package com.tremolosecurity.provisioning.customTasks;

import java.util.ArrayList;
import java.util.Map;

import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.octetstring.jdbcLdap.sql.LdapResultSet;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningParams;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.service.util.TremoloUser;
import com.tremolosecurity.provisioning.service.util.WFCall;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;

import org.apache.logging.log4j.Logger;

/**
 * DeleteGroupMembers
 */
public class DeleteGroupMembers implements CustomTask {

    String workflowName;
    String uidAttribute;
    String groupNameAttribute;

    String groupToDelete;

    String requestor;

    static Logger logger = org.apache.logging.log4j.LogManager.getLogger(DeleteGroupMembers.class.getName());

    transient WorkflowTask task;

    @Override
    public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
        String localWorkflowName = task.renderTemplate(this.workflowName, request);
        String localGroupToDelete = task.renderTemplate(this.groupToDelete, request);
        String localGroupNameAttribute = task.renderTemplate(this.groupNameAttribute, request);
        

        String memberAttr = task.getConfigManager().getCfg().getGroupMemberAttribute();
        String[] members = null;
        String groupName = null;

        try {
            LDAPSearchResults rs = task.getConfigManager().getMyVD().search(localGroupToDelete, 0, "(objectClass=*)",
                    new ArrayList<String>());

            if (!rs.hasMore()) {
            	logger.warn(String.format("Could not find group %s, skipping", localGroupToDelete));
            } else {
            	
            
	            LDAPEntry group = rs.next();
	            while (rs.hasMore()) rs.next();
	
	            
	            
	            if (group.getAttribute(memberAttr) != null) {
	            	members = group.getAttribute(memberAttr).getStringValueArray();
	            } else {
	            	members = new String[] {};
	            }
	            
	            if (group.getAttribute(localGroupNameAttribute) != null) {
	            	groupName = group.getAttribute(localGroupNameAttribute).getStringValue();
	            } else {
	            	throw new ProvisioningException("Group '" + localGroupToDelete + "' has no '" + localGroupNameAttribute + "' attribute");
	            }
            }
            
        } catch (LDAPException e) {
            throw new ProvisioningException("Could not load from group",e);
        }
        
        if (members != null) {
	        for (String member : members) {
	            try {
	                LDAPSearchResults rs = task.getConfigManager().getMyVD().search(member, 0, "(objectClass=*)",
	                        new ArrayList<String>());
	
	                rs.hasMore();
	                LDAPEntry ldapMember = rs.next();
	
	                TremoloUser userToUpdate = new TremoloUser();
	                userToUpdate.setUid(ldapMember.getAttribute(this.uidAttribute).getStringValue());
	                userToUpdate.getAttributes().add(new Attribute(this.uidAttribute,userToUpdate.getUid()));
	                
	
	                Workflow wf = task.getConfigManager().getProvisioningEngine().getWorkFlow(localWorkflowName);
	                
	                
	                WFCall call = new WFCall();
	                call.setReason("removing from to be deleted group " + localGroupToDelete);
	                call.setUidAttributeName(this.uidAttribute);
	                call.setUser(userToUpdate);
	                call.setRequestor(this.requestor);
	                call.getRequestParams().put(ProvisioningParams.UNISON_EXEC_TYPE, ProvisioningParams.UNISON_EXEC_SYNC);
	                call.getRequestParams().put("openunison_grouptoremove", groupName);
	                wf.executeWorkflow(call);
	
	
	            } catch (LDAPException e) {
	                logger.warn("Could not remove user '" + member + "'",e);
	            }
	        }
        }

        return true;
    }

    @Override
    public void init(WorkflowTask task, Map<String, Attribute> config) throws ProvisioningException {
        this.workflowName = config.get("removeWorkflow").getValues().get(0);
        this.uidAttribute = config.get("uidAttributeName").getValues().get(0);
        this.groupToDelete = config.get("groupToDelete").getValues().get(0);
        this.groupNameAttribute = config.get("groupNameAttribute").getValues().get(0);
        
        this.requestor = config.get("requestor").getValues().get(0);
        this.task = task;
	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		this.task = task;
	}

    
}