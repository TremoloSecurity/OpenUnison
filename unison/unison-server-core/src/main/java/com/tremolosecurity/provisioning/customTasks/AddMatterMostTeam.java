/*******************************************************************************
 * Copyright 2020 Tremolo Security, Inc.
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
package com.tremolosecurity.provisioning.customTasks;

import java.io.IOException;
import java.util.Map;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.core.providers.MatterMostProvider;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

public class AddMatterMostTeam implements CustomTask {
	
	String target;
	String teamName;

	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		this.target = params.get("target").getValues().get(0);
		this.teamName = params.get("teamName").getValues().get(0);

	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		

	}

	@Override
	public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
		MatterMostProvider mm = (MatterMostProvider) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(target).getProvider();
		HttpCon con = null;
		
		
		try {
			con = mm.createClient();
			StringBuilder sb = new StringBuilder();
			sb.append("/api/v4/teams/name/").append(teamName);
			
			String jsonResp = mm.callWS(con, sb.toString());
			
			JSONObject team = (JSONObject) new JSONParser().parse(jsonResp);
			String teamId = (String) team.get("id");
			if (teamId == null) {
				throw new ProvisioningException("Team '" + teamName + "' does not exist");
			}
			
			JSONObject userFromMM = mm.loadUserJson(user.getUserID(), con);
			
			if (userFromMM == null) {
				throw new ProvisioningException("User '" + user.getUserID() + "' does not exist");
			}
			
			String userId = (String) userFromMM.get("id");
			
			if (userId == null) {
				throw new ProvisioningException("User '" + user.getUserID() + "' does not exist");
			}
			
			JSONObject addTeam = new JSONObject();
			addTeam.put("team_id", teamId);
			addTeam.put("user_id", userId);
			
			sb.setLength(0);
			sb.append("/api/v4/teams/").append(teamId).append("/members");
			
			mm.callWSPost(con, sb.toString(), addTeam.toString());
			
			
		} catch (Exception e) {
			throw new ProvisioningException("Could not add team",e);
		} finally {
			if (con != null) {
				try {
					con.getHttp().close();
				} catch (IOException e) {
					
				}
				
				con.getBcm().close();
			}
		}
		
		
		return true;
	}

}
