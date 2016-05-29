/*******************************************************************************
 * Copyright 2015 Tremolo Security, Inc.
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
package com.tremolosecurity.provisioning.service;

import java.io.IOException;
import java.sql.Connection;
import java.sql.Date;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.logging.log4j.Logger;
import org.hibernate.Session;
import org.hibernate.jdbc.Work;
import org.joda.time.DateTime;

import com.google.gson.Gson;
import com.tremolosecurity.config.xml.ReportType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.service.util.ProvisioningError;
import com.tremolosecurity.provisioning.service.util.ProvisioningResult;
import com.tremolosecurity.provisioning.service.util.ReportGrouping;
import com.tremolosecurity.provisioning.service.util.ReportResults;
import com.tremolosecurity.server.GlobalEntries;

public class GenerateReport extends HttpServlet {
	/**
	 * 
	 */
	private static final long serialVersionUID = -6278339738573617694L;
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(GenerateReport.class.getName());
	@Override
	protected void doGet(final HttpServletRequest req, final HttpServletResponse resp)
			throws ServletException, IOException {
		
		final Gson gson = new Gson();
		
		try {
		
			String name = req.getParameter("name");
			ReportType reportToRunTmp = null ;
			boolean foundReport = false;
			for (ReportType report : GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getReports().getReport()) {
				if (report.getName().equalsIgnoreCase(name)) {
					reportToRunTmp = report;
					foundReport = true;
					break;
				}
			}
			
			if (! foundReport) {
				reportToRunTmp = null;
			}
			
			final ReportType reportToRun = reportToRunTmp;
			
			if (reportToRun == null) {
				throw new ProvisioningException("Could not find report");
			} else {
				Connection db = null;
				PreparedStatement ps = null;
				ResultSet rs = null;
				try {
					Session session = GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getHibernateSessionFactory().openSession();
					session.doWork(
							new Work() {
						        public void execute(Connection connection) throws SQLException 
						        { 
						        	try {
										generateReportData(req, resp, gson, reportToRun, connection);
									} catch (IOException e) {
										throw new SQLException("Could not run reports",e);
									}
						        }
						    }
							);
					
				} finally {
					
				}
			}
		} catch (Exception e) {
			logger.error("Could not run report",e);
			resp.setStatus(500);
			ProvisioningError pe = new ProvisioningError();
			pe.setError("Could not run report;" + e.getMessage());
			ProvisioningResult resObj = new ProvisioningResult();
			resObj.setSuccess(false);
			resObj.setError(pe);
			
			resp.getOutputStream().print(gson.toJson(resObj));
		}
	}
	private void generateReportData(HttpServletRequest req, HttpServletResponse resp, Gson gson, ReportType reportToRun,
			Connection db) throws SQLException, IOException {
		PreparedStatement ps;
		ResultSet rs;
		if (logger.isDebugEnabled()) {
			logger.debug("Report SQL : '" + reportToRun.getSql() + "'");
		}
		ps = db.prepareStatement(reportToRun.getSql());
		int i = 1;
		for (String paramType : reportToRun.getParamater()) {
			switch (paramType) {
				case "currentUser" :
					if (logger.isDebugEnabled()) {
						logger.debug("Current User : '" + req.getParameter("currentUser") + "'");
					}
					ps.setString(i, req.getParameter("currentUser")); 
					break;
				case "userKey" : 
					if (logger.isDebugEnabled()) {
						logger.debug("User Key : '" + req.getParameter("userKey") + "'");
					}
					ps.setString(i, req.getParameter("userKey")); 
					break;
				case "beginDate" :
					String beginDate = req.getParameter("beginDate");
					if (logger.isDebugEnabled()) {
						logger.debug("Begin Date : '" + beginDate + "'");
					}
					Date d = new Date(DateTime.parse(beginDate).getMillis());
					ps.setDate(i, d);
					break;
					
				case "endDate" :
					
					String endDate = req.getParameter("endDate");
					if (logger.isDebugEnabled()) {
						logger.debug("End Date : '" + endDate + "'");
					}
					Date de = new Date(DateTime.parse(endDate).getMillis());
					ps.setDate(i, de);
					break;
			}
			
			i++;
		}
		
		rs = ps.executeQuery();
		
		
		String groupingVal = null;
		ReportResults res = new ReportResults();
		res.setName(reportToRun.getName());
		res.setDescription(reportToRun.getDescription());
		res.setDataFields(reportToRun.getDataFields());
		res.setHeaderFields(reportToRun.getHeaderFields());
		res.setGrouping(new ArrayList<ReportGrouping>());
		
		ReportGrouping grouping = null;
		
		if (! reportToRun.isGroupings()) {
			grouping = new ReportGrouping();
			grouping.setData(new ArrayList<Map<String,String>>());
			grouping.setHeader(new HashMap<String,String>());
			res.getGrouping().add(grouping);
		}
		
		logger.debug("Running report");
		
		while (rs.next()) {
			if (logger.isDebugEnabled()) {
				logger.debug("New row");
			}
			
			HashMap<String,String> row = new HashMap<String,String>();
			
			for (String dataField : reportToRun.getDataFields()) {
				if (logger.isDebugEnabled()) {
					logger.debug("Field - " + dataField + "='" + rs.getString(dataField) + "'");
				}
				row.put(dataField, rs.getString(dataField));
			}
			
			
			if (reportToRun.isGroupings()) {
				String rowID = rs.getString(reportToRun.getGroupBy()); 
				if (logger.isDebugEnabled()) {
					logger.debug("Grouping Val : '" + groupingVal + "'");
					logger.debug("Group By : '" + reportToRun.getGroupBy() + "'");
					logger.debug("Value of Group By in row : '" + rowID + "'");
					
				}
				
				if (groupingVal == null || ! groupingVal.equals(rowID)) {
					grouping = new ReportGrouping();
					grouping.setData(new ArrayList<Map<String,String>>());
					grouping.setHeader(new HashMap<String,String>());
					res.getGrouping().add(grouping);
					
					for (String headerField : reportToRun.getHeaderFields()) {
						grouping.getHeader().put(headerField, rs.getString(headerField));
					}
					
					groupingVal = rowID;
				}
			}
			
			grouping.getData().add(row);
		}
		
		
		ProvisioningResult pres = new ProvisioningResult();
		pres.setSuccess(true);
		pres.setReportResults(res);
		
		String json = gson.toJson(pres);
		
		if (logger.isDebugEnabled()) {
			logger.debug("JSON : " + json);
		}
		
		resp.getOutputStream().print(json);
	}

}
