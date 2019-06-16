/*******************************************************************************
 * Copyright 2019 Tremolo Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.tremolosecurity.unison.proxy.auth.github;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.directory.ldap.client.api.search.FilterBuilder;

import com.novell.ldap.LDAPException;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.az.AzException;
import com.tremolosecurity.proxy.az.CustomAuthorization;
import com.tremolosecurity.saml.Attribute;

import net.sourceforge.myvd.util.EntryUtil;

public class GithubTeamRule implements CustomAuthorization {

	@Override
	public void init(Map<String, Attribute> config) throws AzException {
		

	}

	@Override
	public void loadConfigManager(ConfigManager cfg) throws AzException {
		

	}

	@Override
	public void setWorkflow(Workflow wf) throws AzException {
		

	}

	@Override
	public boolean isAuthorized(AuthInfo subject, String... params) throws AzException {
		if (params.length == 0) {
			//No parameters, allways true
			return true;
		}
		
		List<FilterBuilder> comps = new ArrayList<FilterBuilder>();
		for (String param : params) {
			if (param.endsWith("/")) {
				comps.add(equal("githubOrgs",param.substring(0,param.indexOf("/"))));
			} else {
				comps.add(equal("githubTeams",param));
			}
		}
		
		FilterBuilder[] ands = new FilterBuilder[comps.size()];
		comps.toArray(ands);
		String filterString = or(ands).toString();
		
		net.sourceforge.myvd.types.Filter filter;
		try {
			filter = new net.sourceforge.myvd.types.Filter(filterString);
		} catch (LDAPException e) {
			throw new AzException("Could not build authorization rule",e);
		}
		
		return filter.getRoot().checkEntry(subject.createLDAPEntry());
		
	}

	@Override
	public List<String> listPossibleApprovers(String... params) throws AzException {
		
		return new ArrayList<String>();
	}

}
