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


package com.tremolosecurity.provisioning.workflow;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningEngine;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.service.util.WFCall;


public class ExecuteWorkflow {

	public void execute(WFCall wfcall,ConfigManager cfgMgr,List<ApprovalData> approvals) throws ProvisioningException,SQLException {
		Workflow wf = cfgMgr.getProvisioningEngine().getWorkFlow(wfcall.getName());
		wf.executeWorkflow(wfcall);
		
		if (approvals != null && approvals.size() > 0) {
			ProvisioningEngine prov =  cfgMgr.getProvisioningEngine(); //TremoloContext.getContext().getConfigManager("proxy").getProvisioningEngine();
			String approver = approvals.get(0).getApprover();
			String approvalReason = approvals.get(0).getReason(); 
			
			try {
				Thread.sleep(5000);
			} catch (InterruptedException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			
			Connection con = prov.getApprovalDBConn();
			try {
				
				int i = 0;
				while (executeApprovals(wfcall, wf, prov, approvalReason, con,approver)) {
					i++;
					if (i >= approvals.size()) {
						i = 0;
					}
					
					approver = approvals.get(i).getApprover();
					approvalReason = approvals.get(i).getReason();
				}
			} catch (Exception e) {
				throw new ProvisioningException("Could not complete approvals",e);
			} finally {
				if (con != null) {
					try {
						con.close();
					} catch (Exception e) {}
				}
			}
		}
		
		
	}
	
	private boolean executeApprovals(WFCall wfcall,
			Workflow wf, ProvisioningEngine prov, String approvalReason,
			Connection con,String approver) throws SQLException, ProvisioningException {
		if (con != null) {
			PreparedStatement ps = con.prepareStatement("SELECT id FROM approvals WHERE approvedTS IS NULL AND workflow=?");
			ps.setInt(1, wf.getId());
			ResultSet rs = ps.executeQuery();
			if (rs.next()) {
				int approval = rs.getInt("id");
				/*AuthController ac = (AuthController) req.getSession().getAttribute(AuthSys.AUTH_CTL);
				Attribute attr = ac.getAuthInfo().getAttribs().get(wfcall.getUidAttributeName());
				if (attr == null) {
					throw new ProvisioningException("Administrator does not have attribute '" + wfcall.getUidAttributeName() + "'");
				}*/
				
				ps.close();
				rs.close();
				
				prov.doApproval(approval, approver, true, approvalReason);
				
				return true;
			} else {
				ps.close();
				rs.close();
				
				return false;
			}
			
			
		} else {
			return false;
		}
	}

}
