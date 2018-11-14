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
package com.tremolosecurity.idp.providers.oidc.model.jobs;

import java.util.HashMap;

import org.quartz.JobExecutionContext;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.idp.providers.OpenIDConnectIdP;
import com.tremolosecurity.idp.providers.oidc.db.DbOidcSessionStore;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.scheduler.UnisonJob;
import com.tremolosecurity.server.GlobalEntries;

public class ClearSessions extends UnisonJob {

	static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(ClearSessions.class.getName());
	
	@Override
	public void execute(ConfigManager cfg, JobExecutionContext job) throws ProvisioningException {
		
		
		
		String idpName = job.getJobDetail().getJobDataMap().getString("idpName");
		HashMap<String,OpenIDConnectIdP> oidcIdPs = (HashMap<String, OpenIDConnectIdP>) GlobalEntries.getGlobalEntries().get(OpenIDConnectIdP.UNISON_OPENIDCONNECT_IDPS);
		if (oidcIdPs == null) {
			logger.warn("No openid connect identity providers available yet");
			return;
		}
		
		
		OpenIDConnectIdP idp = oidcIdPs.get(idpName);
		
		
		
		idp.clearExpiredSessions();
		

	}

}
