/*
Copyright 2015 Tremolo Security, Inc.

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


package com.tremolosecurity.provisioning.scheduler.jobs;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

import org.apache.log4j.Logger;
import org.hibernate.Query;
import org.hibernate.Session;
import org.joda.time.DateTime;
import org.joda.time.Days;
import org.quartz.JobExecutionContext;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.objects.AllowedApprovers;
import com.tremolosecurity.provisioning.objects.Approvals;
import com.tremolosecurity.provisioning.objects.ApproverAttributes;
import com.tremolosecurity.provisioning.scheduler.UnisonJob;



public class RemindApprovers extends UnisonJob {

	static Logger logger = Logger.getLogger(RemindApprovers.class.getName());
	
	@Override
	public void execute(ConfigManager configManager, JobExecutionContext context)
			throws ProvisioningException {
		
		if (configManager == null || configManager.getProvisioningEngine() == null) {
			logger.warn("System not fully initialized");
			return;
		}
		
		
		String msg = context.getJobDetail().getJobDataMap().getString("message");
		int days = Integer.parseInt(context.getJobDetail().getJobDataMap().getString("days"));
		String mailAttribute = context.getJobDetail().getJobDataMap().getString("mailAttributeName");
		
		Session session = null;
		
		try {
			session = configManager.getProvisioningEngine().getHibernateSessionFactory().openSession();
			
			DateTime approvalsAfterDate = new DateTime().minusDays(days + 1);
			
			Query query = session.createQuery("FROM Approvals WHERE approved IS NULL AND createTS > :check_date");
			query.setParameter("check_date", new java.sql.Date(approvalsAfterDate.getMillis()));
			List<com.tremolosecurity.provisioning.objects.Approvals> approvals = query.list();
			
			
			
			DateTime now = new DateTime();
			
			for (Approvals apr : approvals) {
				int daysOpen = Days.daysBetween(new DateTime(apr.getCreateTs().getTime()), now).getDays();
				String label = apr.getLabel();
				String mail = null;
				
				for (AllowedApprovers allowed : apr.getAllowedApproverses()) {
					mail = null;
					for (ApproverAttributes attr : allowed.getApprovers().getApproverAttributeses()) {
						if (attr.getName().equalsIgnoreCase(mailAttribute)) {
							mail = attr.getValue();
						}
					}
					
					if (mail == null ) {
						logger.warn("No attribute called '" + mailAttribute + "' for user '" + allowed.getApprovers().getUserKey() + "'");
					} else {
						if (logger.isDebugEnabled()) {
							logger.debug("Notifying " + mail + " for " + label + " after " + daysOpen + " days");
						}
						
						String toSend = msg.replaceAll("[%]L", label).replaceAll("[%]D", Integer.toString(daysOpen));
						
						configManager.getProvisioningEngine().sendNotification(mail, toSend, "Open Approval for " + daysOpen + " days", new User(mail));
					}
				}
				
				
				
			}
		} catch (Exception e) {
			throw new ProvisioningException("Error reminding open approvers",e);
		} finally {
			if (session != null) {
				session.close();
			}
		}

	}

}
