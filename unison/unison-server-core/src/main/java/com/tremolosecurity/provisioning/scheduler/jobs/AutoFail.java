/*******************************************************************************
 * Copyright 2015, 2018 Tremolo Security, Inc.
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
package com.tremolosecurity.provisioning.scheduler.jobs;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;

import jakarta.jms.*;

import com.tremolosecurity.provisioning.scheduler.jobs.util.DisposeConnection;
import org.apache.logging.log4j.Logger;
import org.quartz.JobExecutionContext;

import com.google.gson.Gson;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.jms.JMSSessionHolder;
import com.tremolosecurity.provisioning.scheduler.UnisonJob;
import com.tremolosecurity.provisioning.scheduler.jobs.util.FailApproval;
import com.tremolosecurity.provisioning.service.util.ApprovalSummaries;
import com.tremolosecurity.provisioning.service.util.ApprovalSummary;
import com.tremolosecurity.provisioning.service.util.ServiceActions;
import com.tremolosecurity.provisioning.util.EncryptedMessage;

public class AutoFail extends UnisonJob {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(AutoFail.class.getName());

	static JMSSessionHolder sessionHolder;

	private synchronized void createConnections(ConfigManager configManager,String queueName) throws JMSException, ProvisioningException {
		if (sessionHolder == null) {
			sessionHolder = com.tremolosecurity.provisioning.jms.JMSConnectionFactory.getConnectionFactory().getSession(queueName);
		}
	}

	@Override
	public void execute(ConfigManager configManager, JobExecutionContext context)
			throws ProvisioningException {
		if (configManager == null
				|| configManager.getProvisioningEngine() == null) {
			logger.warn("System not fully initialized");
			return;
		}

		String queueName = context.getJobDetail().getJobDataMap()
				.getString("queueName");
		String approver = context.getJobDetail().getJobDataMap()
				.getString("approver");
		String msg = context.getJobDetail().getJobDataMap()
				.getString("message");

		ApprovalSummaries summaries = ServiceActions
				.listOpenApprovals(approver,"",configManager);

		try {

			this.createConnections(configManager,queueName);

			Gson gson = new Gson();
			for (ApprovalSummary sum : summaries.getApprovals()) {
				FailApproval fa = new FailApproval();
				fa.setApprovalID(sum.getApproval());
				fa.setApprover(approver);
				fa.setMsg(msg);
				EncryptedMessage em = configManager.getProvisioningEngine()
						.encryptObject(fa);
				
				synchronized (sessionHolder) {
					TextMessage tmsg = sessionHolder.getSession().createTextMessage(gson.toJson(em));
					tmsg.setStringProperty("JMSXGroupID", "unison-autofail");
					sessionHolder.getMessageProduceer().send(tmsg);
				}
			}



		} catch (Throwable t) {

			throw new ProvisioningException("Could not process open approvals",
					t);
		}

	}

}
