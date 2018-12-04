/*
Copyright 2015, 2016 Tremolo Security, Inc.

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


package com.tremolosecurity.provisioning.scheduler;

import java.io.Serializable;
import java.util.HashMap;

import org.apache.logging.log4j.Logger;
import org.quartz.DisallowConcurrentExecution;
import org.quartz.Job;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

/**
 * Job for executing a scheduled job in Unison
 * 
 *
 */
@DisallowConcurrentExecution
public abstract class UnisonJob implements Job {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(UnisonJob.class.getName());
	
	/**
	 * Method called to execute the job
	 * @param configManager
	 * @param context
	 * @throws ProvisioningException
	 */
	public abstract void execute(ConfigManager configManager, JobExecutionContext context) throws ProvisioningException;

	@Override
	public void execute(JobExecutionContext context)
			throws JobExecutionException {
		try {
			
			this.execute((ConfigManager) GlobalEntries.getGlobalEntries().get(ProxyConstants.CONFIG_MANAGER),context);
		} catch (ProvisioningException e) {
			throw new JobExecutionException(e);
		}
		
	}
	
	
	
}
