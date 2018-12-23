/*******************************************************************************
 * Copyright 2018 Tremolo Security, Inc.
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
package com.tremolosecurity.unison.openshiftv3.jobs;

import java.io.IOException;

import org.apache.logging.log4j.Logger;
import org.quartz.JobExecutionContext;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.scheduler.UnisonJob;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;


public class DeleteObject extends UnisonJob {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(DeleteObject.class.getName());

	@Override
	public void execute(ConfigManager configManager, JobExecutionContext context) throws ProvisioningException {
		if (configManager == null || configManager.getProvisioningEngine() == null) {
			logger.warn("System not fully initialized");
			return;
		}
		
		
		String target = context.getJobDetail().getJobDataMap().getString("target");
		String uri = context.getJobDetail().getJobDataMap().getString("uri");
		
		OpenShiftTarget os = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(target).getProvider();
		HttpCon con = null;
		
		try {
			con = os.createClient();
			String token = os.getAuthToken();
			os.callWSDelete(token, con, uri);
		} catch (Exception e) {
			throw new ProvisioningException("Could not clear object",e);
		} finally {
			if (con != null) {
				con.getBcm().close();
				try {
					con.getHttp().close();
				} catch (IOException e) {
					logger.warn("Could not close connection",e);
				}
			}
		}
		
	}

}
