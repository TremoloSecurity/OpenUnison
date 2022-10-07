/*******************************************************************************
 * Copyright 2022 Tremolo Security, Inc.
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

package com.tremolosecurity.scalejs.register.dynamicSource;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.kohsuke.github.GHTeam;

import com.tremolosecurity.provisioning.core.providers.GitHubProvider;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.scalejs.cfg.ScaleAttribute;
import com.tremolosecurity.scalejs.sdk.SourceList;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.util.NVP;

public class LoadTeamsFromGitHub implements SourceList {
	
	static Logger logger = Logger.getLogger(LoadTeamsFromGitHub.class.getName());
	
	String targetName;
	String errorMessage;
	int maxEntries;

	private boolean dynSearch;

	@Override
	public void init(ScaleAttribute attribute, Map<String, Attribute> config) {
		if ( config.get("targetName") == null) {
			logger.error("targetName is not configured");
		} else {
			this.targetName = config.get("targetName").getValues().get(0);
		}
		errorMessage = config.get("errorMessage").getValues().get(0);
		maxEntries = Integer.parseInt(config.get("maxEntries").getValues().get(0));
		dynSearch = attribute.getType().equalsIgnoreCase("text-list");

	}

	@Override
	public List<NVP> getSourceList(HttpFilterRequest request) throws Exception {
		if (targetName == null) {
			throw new Exception("targetName not configured");
		}
		
		GitHubProvider github = (GitHubProvider) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(targetName).getProvider();
		Map<String,GHTeam> teams = github.getOrganization().getTeams();
		
		
		ArrayList<NVP> toReturn = new ArrayList<NVP>();
		
		String search = request.getParameter("search") != null ? request.getParameter("search").getValues().get(0) : null;
		
		if (search == null ) {
			for (String teamName : teams.keySet()) {
				String teamWithOrg = String.format("%s/%s", github.getOrgName(),teamName);
				toReturn.add(new NVP(teamWithOrg,teamWithOrg));
			}
		} else {
			int i = 0;
			
			for (String teamName : teams.keySet()) {
				if (teamName.contains(search)) {
					String teamWithOrg = String.format("%s/%s", github.getOrgName(),teamName);
					toReturn.add(new NVP(teamWithOrg,teamWithOrg));
					i++;
					if (i > this.maxEntries) {
						break;
					}
				}
			}
		}
		
		Collections.sort(toReturn, new Comparator<NVP>() {

			@Override
			public int compare(NVP arg0, NVP arg1) {
				return arg0.getName().compareTo(arg1.getName());
			}});
		
		return toReturn;
	}

	@Override
	public String validate(String value, HttpFilterRequest request) throws Exception {
		if (targetName == null) {
			throw new Exception("targetName not configured");
		}
		
		GitHubProvider github = (GitHubProvider) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(targetName).getProvider();
		
		String team = value.substring(value.indexOf('/') + 1);
		
		try {
			GHTeam fromgh = github.getOrganization().getTeamByName(team);
			if (fromgh == null) {
				return String.format("Team %s does not exist in %s", team,github.getOrgName());
			} else {
				return null;
			}
		} catch (IOException e) {
			return String.format("Team %s does not exist in %s", team,github.getOrgName());
		}
	}

}
