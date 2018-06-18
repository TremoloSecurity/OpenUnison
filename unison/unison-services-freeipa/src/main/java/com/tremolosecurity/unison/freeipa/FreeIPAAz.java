//    Copyright 2018 Tremolo Security, Inc.
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

package com.tremolosecurity.unison.freeipa;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.az.AzException;
import com.tremolosecurity.proxy.az.CustomAuthorization;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.freeipa.json.IPACall;
import com.tremolosecurity.unison.freeipa.json.IPAResponse;

import org.apache.directory.ldap.client.api.search.FilterBuilder;

/**
 * FreeIPAAz
 */
public class FreeIPAAz implements CustomAuthorization{

    String targetName;
    String uidAttributeName;
    

	@Override
	public void init(Map<String, Attribute> config) throws AzException {
        this.targetName = config.get("targetName").getValues().get(0);
        this.uidAttributeName = config.get("uidAttributeName").getValues().get(0);
	}

	@Override
	public void loadConfigManager(ConfigManager cfg) throws AzException {
        
	}

	@Override
	public void setWorkflow(Workflow wf) throws AzException {
		
	}

	@Override
	public boolean isAuthorized(AuthInfo subject, String... params) throws AzException {
		try {
            FreeIPATarget ipa = (FreeIPATarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(this.targetName).getProvider();
            String groupName = params[0];
            HashSet<String> attributes = new HashSet<String>();
            attributes.add(this.uidAttributeName);
            HashMap<String,Object> request = new HashMap<String,Object>();
            User fromTarget = ipa.findUser(subject.getAttribs().get(this.uidAttributeName).getValues().get(0), attributes, request);

            boolean found = false;

            for (String userGroupName : fromTarget.getGroups()) {
                if (userGroupName.equalsIgnoreCase(groupName)) {
                    found = true;
                }
            }

            return found;

		} catch (ProvisioningException e) {
			throw new AzException("Unable to process",e);
		}
	}

	@Override
	public List<String> listPossibleApprovers(String... params) throws AzException {
        ConfigManager cfg = GlobalEntries.getGlobalEntries().getConfigManager();
        try {
            FreeIPATarget ipa = (FreeIPATarget) cfg.getProvisioningEngine().getTarget(this.targetName).getProvider();
            
            IPACall showGroup = new IPACall();
            showGroup.setId(0);
            showGroup.setMethod("group_show");
            ArrayList<String> groupName = new ArrayList<String>();
            groupName.add(params[0]);
            showGroup.getParams().add(groupName);

            HashMap<String,String> additionalParams = new HashMap<String,String>();
            additionalParams.put("no_members", "true");
            showGroup.getParams().add(additionalParams);

            IPAResponse resp = ipa.executeIPACall(showGroup);
            
            ArrayList<FilterBuilder> checks = new ArrayList<FilterBuilder>();

            if (((Map)resp.getResult().getResult()).containsKey("ipaexternalmember")) {
                List<String> vals = (List<String>) ((Map)resp.getResult().getResult()).get("ipaexternalmember");
                for (String val : vals) {
                    checks.add(equal(this.uidAttributeName,val));
                }
            }

            FilterBuilder[] filters = new FilterBuilder[checks.size()];
            checks.toArray(filters);

            String filter = or(filters).toString();

            ArrayList<String> attrsToGet = new ArrayList<String>();
            attrsToGet.add("1.1");
            LDAPSearchResults ldapSearch = cfg.getMyVD().search(cfg.getCfg().getLdapRoot(), 2, filter, attrsToGet);

            ArrayList<String> approvers = new ArrayList<String>();
            while (ldapSearch.hasMore()) {
                approvers.add(ldapSearch.next().getDN());
            }

            return approvers;
        } catch (Exception e) {
            throw new AzException("Could not process authorization",e);
        }
	}

    
}