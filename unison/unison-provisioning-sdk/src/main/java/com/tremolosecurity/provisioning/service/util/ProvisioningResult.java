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


package com.tremolosecurity.provisioning.service.util;

import java.util.List;

/**
 * @author mlb
 *
 */
public class ProvisioningResult {
	private boolean success;
	
	private ProvisioningError error;
	private ApprovalSummaries summaries;
	private List<String> workflowIds;
	private WFDescriptions wfDescriptions;
	private TremoloUser user;
	private ApprovalDetails approvalDetail;
	private Organization org;
	private PortalURLs portalURLs;
	private ReportResults reportResults;
	private ReportsList reportsList;
	
	
	public PortalURLs getPortalURLs() {
		return portalURLs;
	}

	public void setPortalURLs(PortalURLs portalURLs) {
		this.portalURLs = portalURLs;
	}

	public ApprovalDetails getApprovalDetail() {
		return approvalDetail;
	}

	public void setApprovalDetail(ApprovalDetails approvalDetail) {
		this.approvalDetail = approvalDetail;
	}

	public ProvisioningResult() {
		
	}

	public boolean isSuccess() {
		return success;
	}

	public void setSuccess(boolean success) {
		this.success = success;
	}

	public ProvisioningError getError() {
		return error;
	}

	public void setError(ProvisioningError error) {
		this.error = error;
	}

	public ApprovalSummaries getSummaries() {
		return summaries;
	}

	public void setSummaries(ApprovalSummaries summaries) {
		this.summaries = summaries;
	}

	public List<String> getWorkflowIds() {
		return workflowIds;
	}

	public void setWorkflowIds(List<String> workflowIds) {
		this.workflowIds = workflowIds;
	}

	public WFDescriptions getWfDescriptions() {
		return wfDescriptions;
	}

	public void setWfDescriptions(WFDescriptions wfDescriptions) {
		this.wfDescriptions = wfDescriptions;
	}

	public TremoloUser getUser() {
		return user;
	}

	public void setUser(TremoloUser user) {
		this.user = user;
	}

	public Organization getOrg() {
		return org;
	}

	public void setOrg(Organization org) {
		this.org = org;
	}

	public ReportResults getReportResults() {
		return reportResults;
	}

	public void setReportResults(ReportResults reportResults) {
		this.reportResults = reportResults;
	}

	public ReportsList getReportsList() {
		return reportsList;
	}

	public void setReportsList(ReportsList reportsList) {
		this.reportsList = reportsList;
	}
	
	
	
	
}
