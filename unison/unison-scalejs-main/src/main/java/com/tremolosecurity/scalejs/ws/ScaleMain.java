/*******************************************************************************
 * Copyright 2016 Tremolo Security, Inc.
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
package com.tremolosecurity.scalejs.ws;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Type;
import java.net.MalformedURLException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.sql.Connection;
import java.sql.Date;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;

import javax.servlet.http.HttpSession;

import org.apache.logging.log4j.Logger;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Font;
import org.apache.poi.ss.usermodel.RichTextString;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.ss.util.CellRangeAddress;
import org.apache.poi.ss.util.WorkbookUtil;
import org.apache.poi.xssf.usermodel.XSSFRichTextString;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.hibernate.Session;
import org.hibernate.jdbc.Work;
import org.joda.time.DateTime;
import org.stringtemplate.v4.ST;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.ApplicationType;
import com.tremolosecurity.config.xml.AzRuleType;
import com.tremolosecurity.config.xml.OrgType;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.config.xml.PortalUrlType;
import com.tremolosecurity.config.xml.PortalUrlsType;
import com.tremolosecurity.config.xml.ReportType;
import com.tremolosecurity.config.xml.ReportsType;
import com.tremolosecurity.config.xml.WorkflowType;
import com.tremolosecurity.lastmile.LastMile;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.service.util.ApprovalDetails;
import com.tremolosecurity.provisioning.service.util.ApprovalSummaries;
import com.tremolosecurity.provisioning.service.util.ApprovalSummary;
import com.tremolosecurity.provisioning.service.util.Organization;
import com.tremolosecurity.provisioning.service.util.PortalURL;
import com.tremolosecurity.provisioning.service.util.PortalURLs;
import com.tremolosecurity.provisioning.service.util.ProvisioningResult;
import com.tremolosecurity.provisioning.service.util.ReportGrouping;
import com.tremolosecurity.provisioning.service.util.ReportInformation;
import com.tremolosecurity.provisioning.service.util.ReportResults;
import com.tremolosecurity.provisioning.service.util.ReportsList;
import com.tremolosecurity.provisioning.service.util.ServiceActions;
import com.tremolosecurity.provisioning.service.util.TremoloUser;
import com.tremolosecurity.provisioning.service.util.WFCall;
import com.tremolosecurity.provisioning.service.util.WFDescription;
import com.tremolosecurity.provisioning.tasks.Approval;
import com.tremolosecurity.provisioning.util.DynamicWorkflow;
import com.tremolosecurity.provisioning.workflow.ApprovalData;
import com.tremolosecurity.proxy.ProxySys;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.AzSys;
import com.tremolosecurity.proxy.az.AzRule;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;

import com.tremolosecurity.scalejs.cfg.ScaleAttribute;
import com.tremolosecurity.scalejs.cfg.ScaleConfig;
import com.tremolosecurity.scalejs.cfg.ScaleConfig.PreCheckAllowed;
import com.tremolosecurity.scalejs.data.PreCheckResponse;
import com.tremolosecurity.scalejs.data.ScaleApprovalData;
import com.tremolosecurity.scalejs.data.ScaleError;
import com.tremolosecurity.scalejs.data.UserData;
import com.tremolosecurity.scalejs.data.WorkflowRequest;
import com.tremolosecurity.scalejs.sdk.UiDecisions;
import com.tremolosecurity.scalejs.util.ScaleJSUtils;
import com.tremolosecurity.server.GlobalEntries;

public class ScaleMain implements HttpFilter {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(ScaleMain.class.getName());
	
	ScaleConfig scaleConfig;
	ApplicationType appType;
	
	
	@Override
	public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		Gson gson = new Gson();
		
		
		
		try {
		
		if (request.getRequestURI().endsWith("/main/config")) {
			
			if (scaleConfig.getUiDecisions() != null) {
				AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
				Set<String> allowedAttrs = this.scaleConfig.getUiDecisions().availableAttributes(userData, request.getServletRequest());
				ScaleConfig local = new ScaleConfig(this.scaleConfig);
				if (allowedAttrs != null) {
					
					for (String attrName : this.scaleConfig.getAttributes().keySet()) {
						if (! allowedAttrs.contains(attrName)) {
							local.getAttributes().remove(attrName);
						}
					}
				}
				
				local.setCanEditUser(this.scaleConfig.getUiDecisions().canEditUser(userData, request.getServletRequest()));
				
				ScaleJSUtils.addCacheHeaders(response);
				response.setContentType("application/json");
				
				response.getWriter().println(gson.toJson(local).trim());
				
			} else {
				ScaleJSUtils.addCacheHeaders(response);
				response.setContentType("application/json");
				response.getWriter().println(gson.toJson(scaleConfig).trim());
			}
		} else if (request.getMethod().equalsIgnoreCase("GET") && request.getRequestURI().endsWith("/main/user")) {
			lookupUser(request, response, gson);
		} else if (request.getMethod().equalsIgnoreCase("PUT") && request.getRequestURI().endsWith("/main/user")) {
			saveUser(request, response, gson);
		}  else if (request.getMethod().equalsIgnoreCase("GET") && request.getRequestURI().endsWith("/main/orgs")) {
			AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();			
			AzSys az = new AzSys();			
			OrgType ot = GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getOrg();
			Organization org = new Organization();
			copyOrg(org,ot,az,userData);
			ScaleJSUtils.addCacheHeaders(response);
			response.setContentType("application/json");
			response.getWriter().println(gson.toJson(org).trim());
			
		} else if (request.getMethod().equalsIgnoreCase("GET") && request.getRequestURI().contains("/main/workflows/org/")) {
			loadWorkflows(request, response, gson);
			
		} else if (request.getMethod().equalsIgnoreCase("GET") && request.getRequestURI().contains("/main/workflows/candelegate")) {
			try {
				AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
				OrgType ot = GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getOrg();
				AzSys az = new AzSys();			
				HashSet<String> allowedOrgs = new HashSet<String>();
				this.checkOrg(allowedOrgs , ot, az, userData, request.getSession());
				String workflowName = request.getParameter("workflowName").getValues().get(0);
				//need to check org
				String orgid = null;
				for (WorkflowType wf : GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getWorkflows().getWorkflow()) {
					if (wf.getName().equals(workflowName)) {
						orgid = wf.getOrgid();
						break;
					}
				}
				
				PreCheckResponse preCheckResp = new PreCheckResponse();
				if (request.getParameter("uuid") != null) {
					preCheckResp.setUuid(request.getParameter("uuid").getValues().get(0));
				}
				checkPreCheck(request, userData, allowedOrgs, workflowName, orgid, preCheckResp);
				ScaleJSUtils.addCacheHeaders(response);
				response.getWriter().print(gson.toJson(preCheckResp).trim());
				response.getWriter().flush();
			} catch (Throwable t) {
				logger.error("Could not check for preapproval status",t);
				response.setStatus(500);
				response.setContentType("application/json");
				ScaleJSUtils.addCacheHeaders(response);
				ScaleError error = new ScaleError();
				error.getErrors().add("Unable to check");
				response.getWriter().print(gson.toJson(error).trim());
				response.getWriter().flush();
			}
			
		} else if (request.getMethod().equalsIgnoreCase("PUT") && request.getRequestURI().endsWith("/main/workflows")) {
			executeWorkflows(request, response, gson);
		} else if (request.getMethod().equalsIgnoreCase("GET") && request.getRequestURI().endsWith("/main/approvals")) {
			AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
			String uid = userData.getAttribs().get(this.scaleConfig.getUidAttributeName()).getValues().get(0); 			
			response.setContentType("application/json");
			ScaleJSUtils.addCacheHeaders(response);
			response.getWriter().println(gson.toJson(ServiceActions.listOpenApprovals(uid,this.scaleConfig.getDisplayNameAttribute(),GlobalEntries.getGlobalEntries().getConfigManager())).trim());			
		} else if (request.getMethod().equalsIgnoreCase("GET") && request.getRequestURI().contains("/main/approvals/")) {
			loadApproval(request, response, gson);
			
						
		} else if (request.getMethod().equalsIgnoreCase("PUT") && request.getRequestURI().contains("/main/approvals/")) {
			int approvalID = Integer.parseInt(request.getRequestURI().substring(request.getRequestURI().lastIndexOf('/') + 1));
			AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
			String uid = userData.getAttribs().get(this.scaleConfig.getUidAttributeName()).getValues().get(0);
			boolean ok = false;
			ApprovalSummaries summaries = ServiceActions.listOpenApprovals(uid,this.scaleConfig.getDisplayNameAttribute(),GlobalEntries.getGlobalEntries().getConfigManager());
			for (ApprovalSummary as : summaries.getApprovals()) {
				if (as.getApproval() == approvalID) {
					ok = true;
				}
			}
			
			if (! ok) {
				response.setStatus(401);
				response.setContentType("application/json");
				ScaleJSUtils.addCacheHeaders(response);
				ScaleError error = new ScaleError();
				error.getErrors().add("Unauthorized");
				response.getWriter().print(gson.toJson(error).trim());
				response.getWriter().flush();
			} else {
				ScaleApprovalData approvalData = gson.fromJson(new String((byte[]) request.getAttribute(ProxySys.MSG_BODY)), ScaleApprovalData.class);
				try {
					GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().doApproval(approvalID, uid, approvalData.isApproved(),approvalData.getReason());
				} catch (Exception e) {
					logger.error("Could not execute approval",e);
					response.setStatus(500);
					ScaleError error = new ScaleError();
					error.getErrors().add("There was a problem completeding your request, please contact your system administrator");
					ScaleJSUtils.addCacheHeaders(response);
					response.getWriter().print(gson.toJson(error).trim());
					response.getWriter().flush();
				}
			}
			
						
		} else if (request.getMethod().equalsIgnoreCase("GET") && request.getRequestURI().contains("/main/reports/org/")) {
			loadReports(request, response, gson);
			
		} else if (request.getMethod().equalsIgnoreCase("GET") && request.getRequestURI().contains("/main/reports/excel/")) {
			
			exportToExcel(request, response, gson);
		} else if (request.getMethod().equalsIgnoreCase("GET") && request.getRequestURI().contains("/main/reports/")) {
			runReport(request, response, gson);
		} else if (request.getMethod().equalsIgnoreCase("GET") && request.getRequestURI().endsWith("/main/urls")) {
			AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
			AzSys az = new AzSys();
			
			PortalUrlsType pt = GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getPortal();
			
			PortalURLs urls = new PortalURLs();
			
			if (pt != null && pt.getUrls() != null) {
				for (PortalUrlType url : pt.getUrls()) {
					if (url.getAzRules() != null && url.getAzRules().getRule().size() > 0) {
						ArrayList<AzRule> rules = new ArrayList<AzRule>();
						
						for (AzRuleType art : url.getAzRules().getRule()) {
							rules.add(new AzRule(art.getScope(),art.getConstraint(),art.getClassName(),GlobalEntries.getGlobalEntries().getConfigManager(),null));
						}
						
						
						if (! az.checkRules(userData, GlobalEntries.getGlobalEntries().getConfigManager(), rules,request.getSession(),this.appType,new HashMap<String,Object>())) {
							continue;
						}
					}
					
					PortalURL purl = new PortalURL();
					purl.setName(url.getName());
					purl.setLabel(url.getLabel());
					purl.setOrg(url.getOrg());
					purl.setUrl(url.getUrl());
					purl.setIcon(url.getIcon());
					
					urls.getUrls().add(purl);
					
					
				}
			}
			
			
			
			ScaleJSUtils.addCacheHeaders(response);
			response.getWriter().print(gson.toJson(urls.getUrls()).trim());
			response.getWriter().flush();
		} else if (request.getMethod().equalsIgnoreCase("GET") && request.getRequestURI().contains("/main/urls/org")) {
			String id = URLDecoder.decode(request.getRequestURI().substring(request.getRequestURI().lastIndexOf('/') + 1), "UTF-8");
			AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
			AzSys az = new AzSys();
			
			PortalUrlsType pt = GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getPortal();
			
			PortalURLs urls = new PortalURLs();
			
			for (PortalUrlType url : pt.getUrls()) {
				
				if (url.getOrg().equalsIgnoreCase(id)) {
				
					if (url.getAzRules() != null && url.getAzRules().getRule().size() > 0) {
						ArrayList<AzRule> rules = new ArrayList<AzRule>();
						
						for (AzRuleType art : url.getAzRules().getRule()) {
							rules.add(new AzRule(art.getScope(),art.getConstraint(),art.getClassName(),GlobalEntries.getGlobalEntries().getConfigManager(),null));
						}
						
						
						if (! az.checkRules(userData, GlobalEntries.getGlobalEntries().getConfigManager(), rules,request.getSession(),this.appType,new HashMap<String,Object>())) {
							continue;
						}
					}
					
					PortalURL purl = new PortalURL();
					purl.setName(url.getName());
					purl.setLabel(url.getLabel());
					purl.setOrg(url.getOrg());
					purl.setUrl(url.getUrl());
					purl.setIcon(url.getIcon());
					
					urls.getUrls().add(purl);
				
				}
			}
			
			
			
			ScaleJSUtils.addCacheHeaders(response);
			response.getWriter().print(gson.toJson(urls.getUrls()).trim());
			response.getWriter().flush();
		}
		
		
		else {
			response.setStatus(500);
			ScaleError error = new ScaleError();
			error.getErrors().add("Operation not supported");
			ScaleJSUtils.addCacheHeaders(response);
			response.getWriter().print(gson.toJson(error).trim());
			response.getWriter().flush();
		}

		} catch (Throwable t) {
			logger.error("Could not execute request",t);
			
			response.setStatus(500);
			ScaleError error = new ScaleError();
			error.getErrors().add("Operation not supported");
			ScaleJSUtils.addCacheHeaders(response);
			response.getWriter().print(gson.toJson(error).trim());
			response.getWriter().flush();
			
		}
	}


	private void checkPreCheck(HttpFilterRequest request, AuthInfo userData, HashSet<String> allowedOrgs,
			String workflowName, String orgid, PreCheckResponse preCheckResp) {
		if (orgid != null && allowedOrgs.contains(orgid)) {
		
			switch (this.scaleConfig.getCanDelegate()) {
				case YES : preCheckResp.setCanDelegate(true); break;
				case NO : preCheckResp.setCanDelegate(false); break;
				case CUSTOM : preCheckResp.setCanDelegate(this.scaleConfig.getUiDecisions().canRequestForOthers(workflowName, userData, request.getServletRequest())); break;
			}
			
			switch (this.scaleConfig.getCanPreApprove()) {
				case YES : preCheckResp.setCanPreApprove(true); break;
				case NO : preCheckResp.setCanPreApprove(false); break;
				case CUSTOM : preCheckResp.setCanPreApprove(this.scaleConfig.getUiDecisions().canPreApprove(workflowName, userData, request.getServletRequest())); break;
			}
			
			if (preCheckResp.isCanPreApprove()) {
				//if you can pre-approve then you can delegate
				preCheckResp.setCanDelegate(true);
			}
		}
	}


	private void exportToExcel(HttpFilterRequest request, HttpFilterResponse response, Gson gson) throws IOException {
		int lastslash = request.getRequestURI().lastIndexOf('/');
		int secondlastslash = request.getRequestURI().lastIndexOf('/', lastslash - 1);
		
		String id = request.getRequestURI().substring(secondlastslash + 1,lastslash);
		
		ReportResults res = (ReportResults) request.getSession().getAttribute(id);
		
		if (res == null) {
			response.setStatus(404);
			ScaleError error = new ScaleError();
			error.getErrors().add("Report no longer available");
			ScaleJSUtils.addCacheHeaders(response);
			response.getWriter().print(gson.toJson(error).trim());
			response.getWriter().flush();
		} else {
			
		
			
			
			response.setHeader("Cache-Control", "private, no-store, no-cache, must-revalidate");
			response.setHeader("Pragma", "no-cache");
			
			
			
			
			Workbook wb = new XSSFWorkbook();
			
			Font font = wb.createFont();
			font.setBold(true);
			
			Font titleFont = wb.createFont();
			titleFont.setBold(true);
			titleFont.setFontHeightInPoints((short) 16);
			
			Sheet sheet = wb.createSheet(WorkbookUtil.createSafeSheetName(res.getName()));
			
			//Create a header
			Row row = sheet.createRow(0);
			Cell cell = row.createCell(0);
			
			RichTextString title = new XSSFRichTextString(res.getName());
			title.applyFont(titleFont);
			
			sheet.addMergedRegion(new CellRangeAddress(0,0,0,3));
			
			
			cell.setCellValue(title);
			
			row = sheet.createRow(1);
			cell = row.createCell(0);
			cell.setCellValue(res.getDescription());
			
			sheet.addMergedRegion(new CellRangeAddress(1,1,0,3));
			
			row = sheet.createRow(2);
			cell = row.createCell(0);
			//cell.setCellValue(new DateTime().toString("MMMM Do, YYYY h:mm:ss a"));
			
			sheet.addMergedRegion(new CellRangeAddress(2,2,0,3));
			
			row = sheet.createRow(3);
			
			int rowNum = 4;
			
			if (res.getGrouping().isEmpty()) {
				row = sheet.createRow(rowNum);
				cell = row.createCell(0);
				cell.setCellValue("There is no data for this report");
			} else {
				
				for (ReportGrouping group : res.getGrouping()) {
					for (String colHeader : res.getHeaderFields()) {
						row = sheet.createRow(rowNum);
						cell = row.createCell(0);
						
						RichTextString rcolHeader = new XSSFRichTextString(colHeader);
						rcolHeader.applyFont(font);
						
						cell.setCellValue(rcolHeader);
						cell = row.createCell(1);
						cell.setCellValue(group.getHeader().get(colHeader));
						
						rowNum++;
					}
					
					row = sheet.createRow(rowNum);
					
					int cellNum = 0;
					for (String colHeader : res.getDataFields()) {
						cell = row.createCell(cellNum);
						
						RichTextString rcolHeader = new XSSFRichTextString(colHeader);
						rcolHeader.applyFont(font);
						cell.setCellValue(rcolHeader);
						cellNum++;
					}
					
					rowNum++;
					
					for (Map<String,String> dataRow : group.getData()) {
						cellNum = 0;
						row = sheet.createRow(rowNum);
						for (String colHeader : res.getDataFields()) {
							cell = row.createCell(cellNum);
							cell.setCellValue(dataRow.get(colHeader));
							cellNum++;
						}
						rowNum++;
					}
					
					row = sheet.createRow(rowNum);
					rowNum++;
				}
				
			}
			
			response.setContentType("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
			wb.write(response.getOutputStream());
		}
	}


	private void runReport(final HttpFilterRequest request, final HttpFilterResponse response, final Gson gson)
			throws UnsupportedEncodingException, IOException, MalformedURLException, ProvisioningException,
			SQLException {
		String name = URLDecoder.decode(request.getRequestURI().substring(request.getRequestURI().lastIndexOf('/') + 1), "UTF-8");
		ReportType reportToRun = null;
		
		for (ReportType report : GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getReports().getReport()) {
			if (report.getName().equalsIgnoreCase(name)) {
				reportToRun = report;
				break;
			}
		}
		
		
		
		if (reportToRun == null) {
			response.setStatus(404);
			ScaleError error = new ScaleError();
			error.getErrors().add("Report not found");
			ScaleJSUtils.addCacheHeaders(response);
			response.getWriter().print(gson.toJson(error).trim());
			response.getWriter().flush();
		} else {
			HashSet<String> allowedOrgs = new HashSet<String>();
			final AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
			OrgType ot = GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getOrg();
			AzSys az = new AzSys();			
			this.checkOrg(allowedOrgs, ot, az, userData, request.getSession());
			
			if (allowedOrgs.contains(reportToRun.getOrgID())) {
				Connection db = null;
				
				final ReportType reportToRunUse = reportToRun;
				
				try {
					Session session = GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getHibernateSessionFactory().openSession();
					session.doWork(
							new Work() {
						        public void execute(Connection connection) throws SQLException 
						        { 
						        	try {
						        		generateReport(request, response, gson, reportToRunUse, userData, connection);
									} catch (IOException e) {
										throw new SQLException("Could not run reports",e);
									}
						        }
						    }
							);
					
				} finally {
					
				}
				
				
			} else {
				response.setStatus(401);
				ScaleError error = new ScaleError();
				error.getErrors().add("Unauthorized");
				ScaleJSUtils.addCacheHeaders(response);
				response.getWriter().print(gson.toJson(error).trim());
				response.getWriter().flush();
			}
		}
	}


	private void generateReport(HttpFilterRequest request, HttpFilterResponse response, Gson gson,
			ReportType reportToRun, AuthInfo userData, Connection db) throws SQLException, IOException {
		PreparedStatement ps = null;
		ResultSet rs = null;
		
		try {
			
			if (logger.isDebugEnabled()) {
				logger.debug("Report SQL : '" + reportToRun.getSql() + "'");
			}
			ps = db.prepareStatement(reportToRun.getSql());
			int i = 1;
			for (String paramType : reportToRun.getParamater()) {
				switch (paramType) {
					case "currentUser" :
						String userid = userData.getAttribs().get(this.scaleConfig.getUidAttributeName()).getValues().get(0);
						if (logger.isDebugEnabled()) {
							logger.debug("Current User : '" + userid + "'");
						}
						ps.setString(i, userid); 
						break;
					case "userKey" : 
						if (logger.isDebugEnabled()) {
							logger.debug("User Key : '" + request.getParameter("userKey") + "'");
						}
						ps.setString(i, request.getParameter("userKey").getValues().get(0)); 
						break;
					case "beginDate" :
						String beginDate = request.getParameter("beginDate").getValues().get(0);
						if (logger.isDebugEnabled()) {
							logger.debug("Begin Date : '" + beginDate + "'");
						}
						Date d = new Date(Long.parseLong(beginDate));
						ps.setDate(i, d);
						break;
						
					case "endDate" :
						
						String endDate = request.getParameter("endDate").getValues().get(0);
						if (logger.isDebugEnabled()) {
							logger.debug("End Date : '" + endDate + "'");
						}
						Date de = new Date(Long.parseLong(endDate));
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
			
			if (request.getParameter("excel") != null && request.getParameter("excel").getValues().get(0).equalsIgnoreCase("true")) {
				UUID id = UUID.randomUUID();
				String sid = id.toString();
				Map<String,String> map = new HashMap<String,String>();
				map.put("reportid", sid);
				request.getSession().setAttribute(sid, res);
				String json = gson.toJson(map);
				
				if (logger.isDebugEnabled()) {
					logger.debug("JSON : " + json);
				}
				response.setContentType("application/json");
				ScaleJSUtils.addCacheHeaders(response);
				response.getWriter().print(json);
				response.getWriter().flush();
			} else {
				ProvisioningResult pres = new ProvisioningResult();
				pres.setSuccess(true);
				pres.setReportResults(res);
				
				String json = gson.toJson(res);
				
				if (logger.isDebugEnabled()) {
					logger.debug("JSON : " + json);
				}
				response.setContentType("application/json");
				ScaleJSUtils.addCacheHeaders(response);
				response.getWriter().print(json);
				response.getWriter().flush();
			}
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch (Throwable t) {
					
				}
			}
			
			if (ps != null) {
				try {
					ps.close();
				} catch (Throwable t) {
					
				}
			}
			
			if (db != null) {
				try {
					db.close();
				} catch (Throwable t) {
					
				}
			}
		}
	}


	private void loadApproval(HttpFilterRequest request, HttpFilterResponse response, Gson gson)
			throws ProvisioningException, IOException, LDAPException {
		int approvalID = Integer.parseInt(request.getRequestURI().substring(request.getRequestURI().lastIndexOf('/') + 1));
		AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
		String uid = userData.getAttribs().get(this.scaleConfig.getUidAttributeName()).getValues().get(0);
		boolean ok = false;
		ApprovalSummaries summaries = ServiceActions.listOpenApprovals(uid,this.scaleConfig.getDisplayNameAttribute(),GlobalEntries.getGlobalEntries().getConfigManager());
		for (ApprovalSummary as : summaries.getApprovals()) {
			if (as.getApproval() == approvalID) {
				ok = true;
			}
		}
		
		if (! ok) {
			response.setStatus(401);
			response.setContentType("application/json");
			ScaleError error = new ScaleError();
			error.getErrors().add("Unauthorized");
			ScaleJSUtils.addCacheHeaders(response);
			response.getWriter().print(gson.toJson(error).trim());
			response.getWriter().flush();
		} else {
			response.setContentType("application/json");
			
			
			ApprovalDetails details = ServiceActions.loadApprovalDetails(uid, approvalID);
			
			String filter = equal(this.scaleConfig.getUidAttributeName(),details.getUserObj().getUserID()).toString();
			ArrayList<String> attrs = new ArrayList<String>();
			/*for (String attrName : this.scaleConfig.getApprovalAttributes().keySet()) {
				attrs.add(attrName);
			}
			
			if (this.scaleConfig.getRoleAttribute() != null && ! this.scaleConfig.getRoleAttribute().isEmpty()) {
				attrs.add(this.scaleConfig.getRoleAttribute());
			}*/
			
			LDAPSearchResults res = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getLdapRoot(), 2, filter, attrs);
			
			if (res.hasMore()) {
				LDAPEntry entry = res.next();
				details.getUserObj().getAttribs().clear();
				
				for (String attrName : this.scaleConfig.getApprovalAttributes().keySet()) {
					LDAPAttribute attr = entry.getAttribute(attrName);
					if (attr != null) {
						details.getUserObj().getAttribs().put(scaleConfig.getApprovalAttributes().get(attrName).getDisplayName(), new Attribute(scaleConfig.getApprovalAttributes().get(attrName).getDisplayName(),attr.getStringValue()));
					}
				}
				
				if (this.scaleConfig.getRoleAttribute() != null && ! this.scaleConfig.getRoleAttribute().isEmpty()) {
					LDAPAttribute attr = entry.getAttribute(this.scaleConfig.getRoleAttribute());
					if (attr != null) {
						details.getUserObj().getGroups().clear();
						for (String val : attr.getStringValueArray()) {
							details.getUserObj().getGroups().add(val);
						}
					}
				} else {
					details.getUserObj().getGroups().clear();
					ArrayList<String> attrNames = new ArrayList<String>();
					attrNames.add("cn");
					LDAPSearchResults res2 = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getLdapRoot(), 2, equal(GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getGroupMemberAttribute(),entry.getDN()).toString(), attrNames);
					
					while (res2.hasMore()) {
						LDAPEntry entry2 = res2.next();
						LDAPAttribute la = entry2.getAttribute("cn");
						if (la != null) {
							details.getUserObj().getGroups().add(la.getStringValue());
						}
					}
				}
				
				
			}
			
			while (res.hasMore()) res.next();
			
			ScaleJSUtils.addCacheHeaders(response);		
			response.getWriter().println(gson.toJson(details).trim());
			response.getWriter().flush();
		}
	}


	private void executeWorkflows(HttpFilterRequest request, HttpFilterResponse response, Gson gson)
			throws Exception {
		Type listType = new TypeToken<ArrayList<WorkflowRequest>>() {}.getType();
		List<WorkflowRequest> reqs = gson.fromJson(new String((byte[])request.getAttribute(ProxySys.MSG_BODY)), listType);
		HashMap<String,String> results = new HashMap<String,String>();
		
		for (WorkflowRequest req : reqs) {
			if (req.getReason() == null || req.getReason().isEmpty()) {
				results.put(req.getUuid(), "Reason is required");
			} else {
				
				HashSet<String> allowedOrgs = new HashSet<String>();
				AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
				OrgType ot = GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getOrg();
				AzSys az = new AzSys();			
				this.checkOrg(allowedOrgs, ot, az, userData, request.getSession());
				
				String orgid = null;
				
				List<WorkflowType> wfs = GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getWorkflows().getWorkflow();
				for (WorkflowType wf : wfs) {
					if (wf.getName().equals(req.getName())) {
						orgid = wf.getOrgid();
						break;
					}
				}
				
				if (orgid == null) {
					results.put(req.getUuid(), "Not Found");
				} else if (! allowedOrgs.contains(orgid)) {
					results.put(req.getUuid(), "Unauthorized");
				} else {
					WFCall wfCall = new WFCall();
					wfCall.setName(req.getName());
					wfCall.setReason(req.getReason());
					wfCall.setUidAttributeName(this.scaleConfig.getUidAttributeName());
					wfCall.setEncryptedParams(req.getEncryptedParams());	
					
					TremoloUser tu = new TremoloUser();
					
					if (req.getSubjects() == null || req.getSubjects().isEmpty()) {
						tu.setUid(userData.getAttribs().get(this.scaleConfig.getUidAttributeName()).getValues().get(0));
						tu.getAttributes().add(new Attribute(this.scaleConfig.getUidAttributeName(),userData.getAttribs().get(this.scaleConfig.getUidAttributeName()).getValues().get(0)));
						
						wfCall.setUser(tu);
						
						try {
							com.tremolosecurity.provisioning.workflow.ExecuteWorkflow exec = new com.tremolosecurity.provisioning.workflow.ExecuteWorkflow();
							exec.execute(wfCall, GlobalEntries.getGlobalEntries().getConfigManager());
							results.put(req.getUuid(), "success");
						} catch (Exception e) {
							logger.error("Could not update user",e);
							results.put(req.getUuid(), "Error, please contact your system administrator");
						}
					} else {
						
						PreCheckResponse preCheckResp = new PreCheckResponse();
						
						checkPreCheck(request, userData, allowedOrgs, req.getName(), orgid, preCheckResp);
						
						StringBuffer errors = new StringBuffer();
						
						if (preCheckResp.isCanDelegate()) {
						
							for (String subject : req.getSubjects()) {
								//execute for each subject
								wfCall = new WFCall();
								wfCall.setName(req.getName());
								wfCall.setReason(req.getReason());
								wfCall.setUidAttributeName(this.scaleConfig.getUidAttributeName());
								wfCall.setEncryptedParams(req.getEncryptedParams());	
								
							
								wfCall.setRequestor(userData.getAttribs().get(this.scaleConfig.getUidAttributeName()).getValues().get(0));
								tu = new TremoloUser();
								wfCall.setUser(tu);
								
								LDAPSearchResults searchRes = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getLdapRoot(), 2, equal(this.scaleConfig.getUidAttributeName(),subject).toString(), new ArrayList<String>());
								
								if (searchRes.hasMore()) {
									LDAPEntry entry = searchRes.next();
									if (entry == null ) {
										errors.append("Error, user " + subject + " does not exist;");
										
									} else {
										startSubjectWorkflow(errors, req, wfCall, tu, subject, entry,preCheckResp);
									}
								} else {
									
										errors.append("Error, user " + subject + " does not exist;");
									
								}
							
							}
							
							if (errors.length() == 0) {
								results.put(req.getUuid(), "success");
							} else {
								results.put(req.getUuid(), errors.toString().substring(0,errors.toString().length()-1));
							}
							
							
					} else {
						results.put(req.getUuid(), "Unable to submit");
						logger.warn("User '" + userData.getUserDN() + "' not allowed to request for others for '" + req.getName() + "'");
					}		
				}
			}
			}
		}
		ScaleJSUtils.addCacheHeaders(response);
		response.setContentType("application/json");
		response.getWriter().println(gson.toJson(results).trim());
	}


	private void startSubjectWorkflow(StringBuffer errors, WorkflowRequest req, WFCall wfCall,
			TremoloUser tu, String subject, LDAPEntry entry, PreCheckResponse preCheckResp) {
		if (entry == null) {
			tu.setUid(subject);
			tu.getAttributes().add(new Attribute(this.scaleConfig.getUidAttributeName(),subject));
		} else {
			tu.setUid(entry.getAttribute(this.scaleConfig.getUidAttributeName()).getStringValue());
			tu.getAttributes().add(new Attribute(this.scaleConfig.getUidAttributeName(),entry.getAttribute(this.scaleConfig.getUidAttributeName()).getStringValue()));
		}
		
		
		if (req.isDoPreApproval() && preCheckResp.isCanPreApprove()) {
			wfCall.getRequestParams().put(Approval.IMMEDIATE_ACTION, req.isApproved());
			wfCall.getRequestParams().put(Approval.REASON, req.getApprovalReason());
		}
		
		try {
			com.tremolosecurity.provisioning.workflow.ExecuteWorkflow exec = new com.tremolosecurity.provisioning.workflow.ExecuteWorkflow();
			exec.execute(wfCall, GlobalEntries.getGlobalEntries().getConfigManager());
			
		} catch (Exception e) {
			logger.error("Could not update user",e);
			errors.append("user " + subject + " did not get submitted, please contact your system administrator;");
			
			
		}
	}


	private void loadWorkflows(HttpFilterRequest request, HttpFilterResponse response, Gson gson)
			throws Exception {
		String orgid = request.getRequestURI().substring(request.getRequestURI().lastIndexOf('/') + 1);
		ConfigManager cfgMgr = GlobalEntries.getGlobalEntries().getConfigManager();
		HashSet<String> allowedOrgs = new HashSet<String>();
		AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
		OrgType ot = GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getOrg();
		AzSys az = new AzSys();			
		this.checkOrg(allowedOrgs, ot, az, userData, request.getSession());
		
		if (! allowedOrgs.contains(orgid)) {
			response.setStatus(401);
			response.setContentType("application/json");
			ScaleError error = new ScaleError();
			error.getErrors().add("Unauthorized");
			ScaleJSUtils.addCacheHeaders(response);
			response.getWriter().print(gson.toJson(error).trim());
			response.getWriter().flush();
		} else {
			List<WorkflowType> wfs = GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getWorkflows().getWorkflow();
			
			ArrayList<WFDescription> workflows = new ArrayList<WFDescription>();
			
			for (WorkflowType wf : wfs) {
				
				if (wf.isInList() != null && wf.isInList().booleanValue()) {
					
					if ( wf.getOrgid() == null || wf.getOrgid().equalsIgnoreCase(orgid)) { 
					
						if (wf.getDynamicConfiguration() != null && wf.getDynamicConfiguration().isDynamic()) {
							HashMap<String,Attribute> params = new HashMap<String,Attribute>();
							if (wf.getDynamicConfiguration().getParam() != null) {
								for (ParamType p : wf.getDynamicConfiguration().getParam()) {
									Attribute attr = params.get(p.getName());
									if (attr == null) {
										attr = new Attribute(p.getName());
										params.put(p.getName(), attr);
									}
									attr.getValues().add(p.getValue());
								}
							}
							
							
							DynamicWorkflow dwf = (DynamicWorkflow) Class.forName(wf.getDynamicConfiguration().getClassName()).newInstance();
							
							List<Map<String,String>> wfParams = dwf.generateWorkflows(wf, cfgMgr, params);
							
							StringBuffer b = new StringBuffer();
							b.append('/').append(URLEncoder.encode(wf.getName(),"UTF-8"));
							String uri = b.toString();
							for (Map<String,String> wfParamSet : wfParams) {
								DateTime now = new DateTime();
								DateTime expires = now.plusHours(1);
								
								LastMile lm = new LastMile(uri,now,expires,0,"");
								for (String key : wfParamSet.keySet()) {
									String val = wfParamSet.get(key);
									Attribute attr = new Attribute(key,val);	
									lm.getAttributes().add(attr);
								}
								
								WFDescription desc = new WFDescription();
								desc.setUuid(UUID.randomUUID().toString());
								desc.setName(wf.getName());
								
								ST st = new ST(wf.getLabel(),'$','$');
								for (String key : wfParamSet.keySet()) {
									st.add(key.replaceAll("[.]", "_"), wfParamSet.get(key));
								}
								
								desc.setLabel(st.render());
								
								
								st = new ST(wf.getDescription(),'$','$');
								for (String key : wfParamSet.keySet()) {
									st.add(key.replaceAll("[.]", "_"), wfParamSet.get(key));
								}
								desc.setDescription(st.render());
								
								desc.setEncryptedParams(lm.generateLastMileToken(cfgMgr.getSecretKey(cfgMgr.getCfg().getProvisioning().getApprovalDB().getEncryptionKey())));
								
								workflows.add(desc);
								
							}
							
							
						} else {
							WFDescription desc = new WFDescription();
							
							desc.setUuid(UUID.randomUUID().toString());
							desc.setName(wf.getName());
							desc.setLabel(wf.getLabel());
							desc.setDescription(wf.getDescription());
							
							
							workflows.add(desc);
						}
						
						
					}
				}
				
			}
			ScaleJSUtils.addCacheHeaders(response);
			response.setContentType("application/json");
			response.getWriter().println(gson.toJson(workflows).trim());
			response.getWriter().flush();
		}
	}
	
	private void loadReports(HttpFilterRequest request, HttpFilterResponse response, Gson gson)
			throws MalformedURLException, ProvisioningException, IOException {
		String orgid = request.getRequestURI().substring(request.getRequestURI().lastIndexOf('/') + 1);
		ConfigManager cfgMgr = GlobalEntries.getGlobalEntries().getConfigManager();
		HashSet<String> allowedOrgs = new HashSet<String>();
		AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
		OrgType ot = GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getOrg();
		AzSys az = new AzSys();			
		this.checkOrg(allowedOrgs, ot, az, userData, request.getSession());
		
		if (! allowedOrgs.contains(orgid)) {
			response.setStatus(401);
			response.setContentType("application/json");
			ScaleError error = new ScaleError();
			error.getErrors().add("Unauthorized");
			ScaleJSUtils.addCacheHeaders(response);
			response.getWriter().print(gson.toJson(error).trim());
			response.getWriter().flush();
		} else {
			
			ReportsType reports = GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getReports();
			
			ReportsList reportsList = new ReportsList();
			reportsList.setReports(new ArrayList<ReportInformation>());
			
			if (reports != null && reports.getReport() != null) {
				for (ReportType report : reports.getReport()) {
					if (report.getOrgID().equals(orgid)) {
						ReportInformation ri = new ReportInformation();
						ri.setName(report.getName());
						ri.setDescription(report.getDescription());
						ri.setOrgID(report.getOrgID());
						ri.setParameters(new ArrayList<String>());
						ri.getParameters().addAll(report.getParamater());
						ri.getParameters().remove("currentUser");
						reportsList.getReports().add(ri);
					}
				}
			}
			
			response.setContentType("application/json");
			ScaleJSUtils.addCacheHeaders(response);
			response.getWriter().println(gson.toJson(reportsList).trim());
			response.getWriter().flush();
		}
	}
	
	
	private boolean copyOrg(Organization org,OrgType ot, AzSys az, AuthInfo auinfo) throws MalformedURLException, ProvisioningException {
		
		ConfigManager cfgMgr = GlobalEntries.getGlobalEntries().getConfigManager();
		
		if (ot.getAzRules() != null && ot.getAzRules().getRule().size() > 0) {
			ArrayList<AzRule> rules = new ArrayList<AzRule>();
			
			for (AzRuleType art : ot.getAzRules().getRule()) {
				rules.add(new AzRule(art.getScope(),art.getConstraint(),art.getClassName(),cfgMgr,null));
			}
			
			
			if (! az.checkRules(auinfo,cfgMgr , rules, new HashMap<String,Object>())) {
				return false;
			}
		}
		
		org.setId(ot.getUuid());
		org.setName(ot.getName());
		org.setDescription(ot.getDescription());
		
		for (OrgType child : ot.getOrgs()) {
			Organization sub = new Organization();
			
			if (copyOrg(sub,child, az, auinfo)) {
				org.getSubOrgs().add(sub);
			}
		}
		
		return true;
	}

	private void saveUser(HttpFilterRequest request, HttpFilterResponse response, Gson gson) throws IOException {
		ScaleError errors = new ScaleError();
		String json = new String( (byte[]) request.getAttribute(ProxySys.MSG_BODY));
		
		AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
		Set<String> allowedAttrs = null;

		if (this.scaleConfig.getUiDecisions() != null) {
			allowedAttrs = this.scaleConfig.getUiDecisions().availableAttributes(userData, request.getServletRequest());
		}
		
		JsonElement root = new JsonParser().parse(json);
		JsonObject jo = root.getAsJsonObject();
		
		HashMap<String,String> values = new HashMap<String,String>();
		boolean ok = true;
		
		
		
		for (Entry<String,JsonElement> entry : jo.entrySet()) {
			String attributeName = entry.getKey();
			
			if (allowedAttrs == null || allowedAttrs.contains(attributeName)) {
			
				String value = entry.getValue().getAsJsonObject().get("value").getAsString();
				
				
				
				if (this.scaleConfig.getAttributes().get(attributeName) == null) {
					errors.getErrors().add("Invalid attribute : '" + attributeName + "'");
					ok = false;
				} else if (this.scaleConfig.getAttributes().get(attributeName).isReadOnly()) {
					errors.getErrors().add("Attribute is read only : '" + this.scaleConfig.getAttributes().get(attributeName).getDisplayName() + "'");
					ok = false;
				} else if (this.scaleConfig.getAttributes().get(attributeName).isRequired() && value.length() == 0) {
					errors.getErrors().add("Attribute is required : '" + this.scaleConfig.getAttributes().get(attributeName).getDisplayName() + "'");
					ok = false;
				} else if (this.scaleConfig.getAttributes().get(attributeName).getMinChars() > 0 && this.scaleConfig.getAttributes().get(attributeName).getMinChars() > value.length()) {
					errors.getErrors().add(this.scaleConfig.getAttributes().get(attributeName).getDisplayName() + " must have at least " + this.scaleConfig.getAttributes().get(attributeName).getMinChars() + " characters");
					ok = false;
				} else if (this.scaleConfig.getAttributes().get(attributeName).getMaxChars() > 0 && this.scaleConfig.getAttributes().get(attributeName).getMaxChars() < value.length()) {
					errors.getErrors().add(this.scaleConfig.getAttributes().get(attributeName).getDisplayName() + " must have at most " + this.scaleConfig.getAttributes().get(attributeName).getMaxChars() + " characters");
					ok = false;
				} else if (this.scaleConfig.getAttributes().get(attributeName).getPattern() != null) {
					try {
						Matcher m = this.scaleConfig.getAttributes().get(attributeName).getPattern().matcher(value);
						if (m == null || ! m.matches()) {
							ok = false;
						}
					} catch (Exception e) {
						ok = false;
					}
					
					if (!ok) {
						errors.getErrors().add("Attribute value not valid : '" + this.scaleConfig.getAttributes().get(attributeName).getDisplayName() + "' - " + this.scaleConfig.getAttributes().get(attributeName).getRegExFailedMsg());
					}
				}
				
				values.put(attributeName, value);
			}
		}

		for (String attrName : this.scaleConfig.getAttributes().keySet()) {
			if (this.scaleConfig.getAttributes().get(attrName).isRequired() && ! values.containsKey(attrName) && (allowedAttrs == null || allowedAttrs.contains(attrName) )) {
				errors.getErrors().add("Attribute is required : '" + this.scaleConfig.getAttributes().get(attrName).getDisplayName() + "'");
				ok = false;
			}
		}
		
		if (ok) {
			
			ConfigManager cfgMgr = GlobalEntries.getGlobalEntries().getConfigManager();
			WFCall wfCall = new WFCall();
			wfCall.setName(this.scaleConfig.getWorkflowName());
			wfCall.setReason("User update");
			wfCall.setUidAttributeName(this.scaleConfig.getUidAttributeName());
			
			TremoloUser tu = new TremoloUser();
			tu.setUid(userData.getAttribs().get(this.scaleConfig.getUidAttributeName()).getValues().get(0));
			for (String name : values.keySet()) {
				tu.getAttributes().add(new Attribute(name,values.get(name)));
			}
			
			tu.getAttributes().add(new Attribute(this.scaleConfig.getUidAttributeName(),userData.getAttribs().get(this.scaleConfig.getUidAttributeName()).getValues().get(0)));
			
			wfCall.setUser(tu);
			
			try {
				com.tremolosecurity.provisioning.workflow.ExecuteWorkflow exec = new com.tremolosecurity.provisioning.workflow.ExecuteWorkflow();
				exec.execute(wfCall, GlobalEntries.getGlobalEntries().getConfigManager());
				lookupUser(request, response, gson);
			} catch (Exception e) {
				logger.error("Could not update user",e);
				response.setStatus(500);
				ScaleError error = new ScaleError();
				error.getErrors().add("Please contact your system administrator");
				ScaleJSUtils.addCacheHeaders(response);
				response.getWriter().print(gson.toJson(error).trim());
				response.getWriter().flush();
			}
			
			
		} else {
			response.setStatus(500);
			ScaleJSUtils.addCacheHeaders(response);
			response.getWriter().print(gson.toJson(errors).trim());
			response.getWriter().flush();
		}
	}

	private void lookupUser(HttpFilterRequest request, HttpFilterResponse response, Gson gson)
			throws LDAPException, IOException {
		
		
		
		
		response.setContentType("application/json");
		
		AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
		
		
		
		Set<String> allowedAttrs = null;
		
		if (scaleConfig.getUiDecisions() != null) {
			allowedAttrs = this.scaleConfig.getUiDecisions().availableAttributes(userData, request.getServletRequest());
		}
		
		
		
		UserData userToSend = new UserData();
		userToSend.setDn(userData.getUserDN());
		
		
		
		for (String attrName : this.scaleConfig.getAttributes().keySet()) {
			
			if (allowedAttrs == null || allowedAttrs.contains(attrName)) {
				Attribute attr = new Attribute(attrName);
				Attribute fromUser = userData.getAttribs().get(attrName);
				if (fromUser != null) {
					attr.getValues().addAll(fromUser.getValues());
					
					if (attrName.equalsIgnoreCase(this.scaleConfig.getUidAttributeName())) {
						userToSend.setUid(fromUser.getValues().get(0));
					}
				}
				userToSend.getAttributes().add(attr);
			}
		}
		
		
		if (this.scaleConfig.getRoleAttribute() != null && ! this.scaleConfig.getRoleAttribute().isEmpty()) {
			Attribute fromUser = userData.getAttribs().get(this.scaleConfig.getRoleAttribute());
			Attribute attr = new Attribute(this.scaleConfig.getRoleAttribute());
			if (fromUser != null) {
				attr.getValues().addAll(fromUser.getValues());
			}
			
			userToSend.getAttributes().add(attr);
		}
		
		
		ArrayList<String> attrNames = new ArrayList<String>();
		attrNames.add("cn");
		LDAPSearchResults res = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getLdapRoot(), 2, equal(GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getGroupMemberAttribute(),userData.getUserDN()).toString(), attrNames);
		
		while (res.hasMore()) {
			LDAPEntry entry = res.next();
			LDAPAttribute la = entry.getAttribute("cn");
			if (la != null) {
				userToSend.getGroups().add(la.getStringValue());
			}
		}
		
		ScaleJSUtils.addCacheHeaders(response);
		response.getWriter().println(gson.toJson(userToSend).trim());
		
		
	}

	@Override
	public void filterResponseText(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			StringBuffer data) throws Exception {
		

	}

	@Override
	public void filterResponseBinary(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			byte[] data, int length) throws Exception {
		

	}

	
	private String loadAttributeValue(String name,String label,HttpFilterConfig config) throws Exception {
		Attribute attr = config.getAttribute(name);
		if (attr == null) {
			throw new Exception(label + " not found");
		}
		
		String val = attr.getValues().get(0);
		logger.info(label + ": '" + val + "'");
		
		return val;
	}
	
	private String loadOptionalAttributeValue(String name,String label,HttpFilterConfig config) throws Exception {
		Attribute attr = config.getAttribute(name);
		if (attr == null) {
			logger.warn(label + " not found");
			return null;
		}
		
		String val = attr.getValues().get(0);
		logger.info(label + ": '" + val + "'");
		
		return val;
	}
	
	@Override
	public void initFilter(HttpFilterConfig config) throws Exception {
		this.scaleConfig = new ScaleConfig();
		scaleConfig.setDisplayNameAttribute(this.loadAttributeValue("displayNameAttribute", "Display Name Attribute Name", config));
		scaleConfig.getFrontPage().setTitle(this.loadAttributeValue("frontPage.title", "Front Page Title", config));
		scaleConfig.getFrontPage().setText(this.loadAttributeValue("frontPage.text", "Front Page Text", config));
		scaleConfig.setCanEditUser(this.loadAttributeValue("canEditUser", "User Fields Editable", config).equalsIgnoreCase("true"));
		scaleConfig.setWorkflowName(this.loadAttributeValue("workflowName", "Save User Workflow", config));
		scaleConfig.setUidAttributeName(this.loadAttributeValue("uidAttributeName", "User ID Attribute Name", config));
		scaleConfig.setShowPortalOrgs(this.loadAttributeValue("showPortalOrgs", "Show Portal Orgs", config).equalsIgnoreCase("true"));
		scaleConfig.setLogoutURL(this.loadAttributeValue("logoutURL", "Logout URL", config));
		scaleConfig.setWarnMinutesLeft(Integer.parseInt(this.loadAttributeValue("warnMinutesLeft", "Warn when number of minutes left in the user's session", config)));
		
		String val = this.loadOptionalAttributeValue("canDelegate", "canDelegate", config);
		if (val == null) {
			val = "NO";
		}
		
		scaleConfig.setCanDelegate(PreCheckAllowed.valueOf(val.toUpperCase()));
		
		val = this.loadOptionalAttributeValue("canPreApprove", "canPreApprove", config);
		if (val == null) {
			val = "NO";
		}
		
		scaleConfig.setCanPreApprove(PreCheckAllowed.valueOf(val.toUpperCase()));
		
		
		val = this.loadOptionalAttributeValue("roleAttribute", "Role Attribute Name", config);
				
		
		this.appType = new ApplicationType();
		this.appType.setAzTimeoutMillis((long) 3000);
		
		if (val != null) {
			scaleConfig.setRoleAttribute(val);
		}
		
		Attribute attr = config.getAttribute("attributeNames");
		if (attr == null) {
			throw new Exception("Attribute names not found");
		}
		
		for (String attributeName : attr.getValues()) {
			ScaleAttribute scaleAttr = new ScaleAttribute();
			scaleAttr.setName(attributeName);
			scaleAttr.setDisplayName(this.loadAttributeValue(attributeName + ".displayName", attributeName + " Display Name", config));
			scaleAttr.setReadOnly(this.loadAttributeValue(attributeName + ".readOnly", attributeName + " Read Only", config).equalsIgnoreCase("true"));
			
			val = this.loadOptionalAttributeValue(attributeName + ".required", attributeName + " Required", config);
			scaleAttr.setRequired(val != null && val.equalsIgnoreCase("true"));
			
			val = this.loadOptionalAttributeValue(attributeName + ".regEx", attributeName + " Reg Ex", config);
			if (val != null) {
				scaleAttr.setRegEx(val);
			}
			
			val = this.loadOptionalAttributeValue(attributeName + ".regExFailedMsg", attributeName + " Reg Ex Failed Message", config);
			if (val != null) {
				scaleAttr.setRegExFailedMsg(val);
			}
			
			val = this.loadOptionalAttributeValue(attributeName + ".minChars", attributeName + " Minimum Characters", config);
			if (val != null) {
				scaleAttr.setMinChars(Integer.parseInt(val));
			}
			
			val = this.loadOptionalAttributeValue(attributeName + ".mxnChars", attributeName + " Maximum Characters", config);
			if (val != null) {
				scaleAttr.setMaxChars(Integer.parseInt(val));
			}
			
			
			scaleConfig.getAttributes().put(attributeName, scaleAttr);
		}
		
		
		attr = config.getAttribute("approvalAttributeNames");
		if (attr == null) {
			throw new Exception("Approval attribute names not found");
		}
		
		for (String attributeName : attr.getValues()) {
			ScaleAttribute scaleAttr = new ScaleAttribute();
			scaleAttr.setName(attributeName);
			scaleAttr.setDisplayName(this.loadAttributeValue("approvals." + attributeName, "Approvals attribute " + attributeName + " Display Name", config));
			scaleConfig.getApprovalAttributes().put(attributeName, scaleAttr);
		}
		
		val = this.loadOptionalAttributeValue("uiHelperClassName", "UI Helper Class Name", config);
		if (val != null && ! val.isEmpty()) {
			UiDecisions dec = (UiDecisions) Class.forName(val).newInstance();
			attr  = config.getAttribute("uihelper.params");
			HashMap<String,Attribute> decCfg = new HashMap<String,Attribute>();
			if (attr != null) {
				for (String v : attr.getValues()) {
					String name = v.substring(0,v.indexOf('='));
					String value = v.substring(v.indexOf('=') + 1);
					Attribute param = decCfg.get(name);
					if (param == null) {
						param = new Attribute(name);
						decCfg.put(name, param);
					}
					param.getValues().add(value);
					
				}
			}
			
			dec.init(decCfg);
			scaleConfig.setUiDecisions(dec);
			
		}
		
	}
	
	private void checkOrg(HashSet<String> allowedOrgs,OrgType ot, AzSys az, AuthInfo auinfo,HttpSession session) throws MalformedURLException, ProvisioningException {
		ConfigManager cfgMgr = GlobalEntries.getGlobalEntries().getConfigManager();
		
		if (ot.getAzRules() != null && ot.getAzRules().getRule().size() > 0) {
			ArrayList<AzRule> rules = new ArrayList<AzRule>();
			
			for (AzRuleType art : ot.getAzRules().getRule()) {
				rules.add(new AzRule(art.getScope(),art.getConstraint(),art.getClassName(),cfgMgr,null));
			}
			
			
			if (! az.checkRules(auinfo, cfgMgr, rules,session, this.appType,new HashMap<String,Object>())) {
				return;
			}
		}
		
		allowedOrgs.add(ot.getUuid());
		
		for (OrgType child : ot.getOrgs()) {
			checkOrg(allowedOrgs,child, az, auinfo,session);
		}
	}

}
