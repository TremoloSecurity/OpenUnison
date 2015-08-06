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


package com.tremolosecurity.provisioning.core;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;

import java.io.Serializable;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Stack;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.WorkflowTaskType;
import com.tremolosecurity.config.xml.WorkflowType;
import com.tremolosecurity.provisioning.service.util.TremoloUser;
import com.tremolosecurity.provisioning.service.util.WFCall;
import com.tremolosecurity.provisioning.tasks.Approval;
import com.tremolosecurity.provisioning.util.TaskHolder;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.AuthSys;
import com.tremolosecurity.saml.Attribute;

public class WorkflowImpl implements  Workflow {
	static Logger logger = Logger.getLogger(WorkflowImpl.class.getName());
	String name;
	ArrayList<WorkflowTask> tasks;
	

	transient ConfigManager cfgMgr;
	private int id;
	private User user;
	
	private HashMap<String,Object> request;
	private int userNum;
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.Workflow#getUserNum()
	 */
	@Override
	public int getUserNum() {
		return userNum;
	}

	public WorkflowImpl() {
		this.id = 0;
		this.userNum = 0;
		this.user = new User("test");
	}
	
	public WorkflowImpl(ConfigManager cfgMgr,WorkflowType wf) throws ProvisioningException {
		this.cfgMgr = cfgMgr;
		this.name = wf.getName();
		this.tasks = new ArrayList<WorkflowTask>();
		
		Iterator<WorkflowTaskType> it = wf.getWorkflowTasksGroup().iterator();
		while (it.hasNext()) {
			WorkflowTaskType taskCfg = it.next();
			tasks.add(WorkflowTaskImpl.loadTask(taskCfg,cfgMgr,this));
			
			
			
		}
		
		
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.Workflow#reInit(com.tremolosecurity.config.util.ConfigManager)
	 */
	@Override
	public final void reInit(ConfigManager cfgMgr) throws ProvisioningException {
		this.cfgMgr = cfgMgr;
		for (WorkflowTask wft : this.tasks) {
			
			this.reInitTask(wft);
		}
		
	}
	
	
	
	private void reInitTask(WorkflowTask task) throws ProvisioningException {
		
		task.reInit(cfgMgr,this);
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.Workflow#executeWorkflow(com.tremolosecurity.provisioning.core.User, java.util.Map)
	 */
	@Override
	public void executeWorkflow(User user,Map<String,Object> params) throws ProvisioningException {
		
		request = new HashMap<String,Object>();
		
		if (params != null) {
			request.putAll(params);
		}
		
		this.user = user;
		
		Connection con = null;
		try {
			con = this.cfgMgr.getProvisioningEngine().getApprovalDBConn();
			if (con != null) {
				
				this.userNum = this.getUserNum(user,con,this.cfgMgr);
				
				PreparedStatement ps = con.prepareStatement("UPDATE workflows SET userid = ?, requestReason=? WHERE id = ?");
				ps.setInt(1, userNum);
				ps.setString(2, user.getRequestReason());
				ps.setLong(3, this.getId());
				ps.executeUpdate();
				ps.close();
				
			}
		} catch (SQLException e) {
			throw new ProvisioningException("Could not set workflow user key",e);
		} catch (LDAPException e) {
			throw new ProvisioningException("Could not set workflow user key",e);
		} finally {
			if (con != null) {
				
				try {
					con.rollback();
				} catch (SQLException e1) {
					
				}
				
				try {
					con.close();
				} catch (SQLException e) {
					// TODO Auto-generated catch block
					
				}
			}
		}
		
		
		if (request.get(ProvisioningParams.UNISON_EXEC_TYPE) != null && request.get(ProvisioningParams.UNISON_EXEC_TYPE).equals(ProvisioningParams.UNISON_EXEC_SYNC)) {
			Iterator<WorkflowTask> it = this.tasks.iterator();
			while (it.hasNext()) {
				
				boolean doContinue = it.next().doTask(user,request);
				if (! doContinue) {
					return;
				}
			}
			
			this.completeWorkflow();
		} else {
			WorkflowHolder wfHolder = new WorkflowHolder(this,user,request);
			TaskHolder root = new TaskHolder();
			root.setParent(this.tasks);
			root.setPosition(0);
			wfHolder.getWfStack().push(root);
			
			((ProvisioningEngineImpl) this.cfgMgr.getProvisioningEngine()).enqueue(wfHolder);
		}
		
		
	}

	
	public static int getUserNum(User user, Connection con,ConfigManager cfgMgr) throws LDAPException, SQLException {
		StringBuffer filter = new StringBuffer();
		
		
		
		
		LDAPSearchResults res = cfgMgr.getMyVD().search("o=Tremolo", 2, equal(cfgMgr.getProvisioningEngine().getUserIDAttribute(),user.getAttribs().get(cfgMgr.getProvisioningEngine().getUserIDAttribute()).getValues().get(0)).toString(), new ArrayList<String>());
		LDAPEntry fromLDAP = null;
		if (res.hasMore()) {
			fromLDAP = res.next();
		}
		
		while (res.hasMore()) res.next();
		
		con.setAutoCommit(false);
		
		PreparedStatement ps = con.prepareStatement("SELECT id FROM users WHERE userKey=?");
		ps.setString(1, user.getUserID());
		ResultSet rs = ps.executeQuery();
		
		int id = 0;
		
		if (rs.next()) {
			id = rs.getInt("id");
			user.setJitAddToAuditDB(false);
			rs.close();
		} else {
			rs.close();
			PreparedStatement psi = con.prepareStatement("INSERT INTO users (userKey) VALUES (?)",Statement.RETURN_GENERATED_KEYS);
			psi.setString(1, user.getUserID());
			psi.executeUpdate();
			rs = psi.getGeneratedKeys();
			rs.next();
			id = rs.getInt(1);
			rs.close();
			psi.close();
			user.setJitAddToAuditDB(true);
		}
		
		ps.close();
		
		
		StringBuffer sb = new StringBuffer();
		
		
		if (! user.isJitAddToAuditDB()) {
			StringBuffer select = new StringBuffer("SELECT id FROM users WHERE userKey=? AND ");
			ArrayList<String> vals = new ArrayList<String>(); 
			for (String attr : cfgMgr.getProvisioningEngine().getUserAttrbiutes()) {
				if (user.getAttribs().get(attr) != null) {
					select.append(attr).append("=? AND ");
					vals.add(user.getAttribs().get(attr).getValues().get(0));
				}
			}
			
			String sql = select.toString();
			sql = sql.substring(0,sql.lastIndexOf("AND"));
			
			
			
			ps = con.prepareStatement(sql);
			
			ps.setString(1, user.getUserID());
			
			int pNum = 2;
			for (String val : vals) {
				ps.setString(pNum, val);
				pNum++;
			}
			
			rs = ps.executeQuery();
			if (rs.next()) {
				user.setJitAddToAuditDB(false);
			} else {
				user.setJitAddToAuditDB(true);
			}
			
			rs.close();
			ps.close();
		}
		
		if (user.isJitAddToAuditDB()) {
			for (String attr : cfgMgr.getProvisioningEngine().getUserAttrbiutes()) {
				if (user.getAttribs().get(attr) != null) {
					sb.setLength(0);
					sb.append("UPDATE users SET ").append(attr).append("=? WHERE id=?");
					PreparedStatement psu = con.prepareStatement(sb.toString());
					psu.setString(1, user.getAttribs().get(attr).getValues().get(0));
					psu.setInt(2, id);
					psu.executeUpdate();
					psu.close();
				} else if (fromLDAP != null && fromLDAP.getAttribute(attr) != null) {
					sb.setLength(0);
					sb.append("UPDATE users SET ").append(attr).append("=? WHERE id=?");
					PreparedStatement psu = con.prepareStatement(sb.toString());
					psu.setString(1, fromLDAP.getAttribute(attr).getStringValue());
					psu.setInt(2, id);
					psu.executeUpdate();
					psu.close();
				} else {
					logger.warn("Could not store attribute '" + attr + "' in audit database");
				}
			}
		}
		
		con.commit();
		con.setAutoCommit(true);
		
		return id;
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.Workflow#executeWorkflow(com.tremolosecurity.proxy.auth.AuthInfo, java.lang.String)
	 */
	@Override
	public void executeWorkflow(AuthInfo authInfo,String uidAttr) throws ProvisioningException {
		Attribute uid = authInfo.getAttribs().get(uidAttr);
		if (uid == null) {
			throw new ProvisioningException("No uid attribute " + uidAttr);
		}
		
		User user = new User(uid.getValues().get(0));
		user.getAttribs().putAll(authInfo.getAttribs());
		
		HashMap<String,Object> params = new HashMap<String,Object>();
		params.put(ProvisioningParams.UNISON_EXEC_TYPE, ProvisioningParams.UNISON_EXEC_SYNC);
		
		this.executeWorkflow(user,params);
		
		try {
			if (user.isResync()) {
				
				
				StringBuffer b = new StringBuffer();
				b.append("(").append(uidAttr).append("=").append(user.getUserID()).append(")");
				
				String root = null;
				AuthChainType act = this.cfgMgr.getAuthChains().get(authInfo.getAuthChain()); 
				
				if (act != null) {
					root = act.getRoot();
				}
				if (root == null) {
					root = "o=Tremolo";
				}
				
				LDAPSearchResults res = this.cfgMgr.getMyVD().search(root, 2, equal(uidAttr,user.getUserID()).toString(), new ArrayList<String>());
				
				if (res.hasMore()) {
					
					
					if (! user.keepExternalAttrs) {
						authInfo.getAttribs().clear();
					}
					
					LDAPEntry entry = res.next();
					authInfo.setUserDN(entry.getDN());
					
					Iterator<LDAPAttribute> it = entry.getAttributeSet().iterator();
					
					while (it.hasNext()) {
						LDAPAttribute attrib = it.next();
						Attribute attr = new Attribute(attrib.getName());
						String[] vals = attrib.getStringValueArray();
						for (int i=0;i<vals.length;i++) {
							attr.getValues().add(vals[i]);
						}
						authInfo.getAttribs().put(attr.getName(), attr);
					}
					
					
					
					
					
					
				} else {
					throw new ProvisioningException("User " + authInfo.getUserDN() + " does not exist" ); 
				}
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not reload user",e);
		}
		
	} 
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.Workflow#executeWorkflow(com.tremolosecurity.provisioning.service.util.WFCall)
	 */
	@Override
	public void executeWorkflow(WFCall call) throws ProvisioningException {
		TremoloUser userFromCall = call.getUser();
		String uidAttr = call.getUidAttributeName();
		
		HashMap<String,Attribute> attrs = new HashMap<String,Attribute>();
		for (Attribute attr : userFromCall.getAttributes()) {
			attrs.put(attr.getName(),attr);
		}
		
		Attribute uid = attrs.get(uidAttr);
		if (uid == null) {
			throw new ProvisioningException("No uid attribute " + uidAttr);
		}
		
		User user = new User(uid.getValues().get(0));
		user.getGroups().addAll(userFromCall.getGroups());
		user.getAttribs().putAll(attrs);
		
		if (userFromCall.getUserPassword() != null) {
			user.setPassword(userFromCall.getUserPassword());
		}
		
		if (call.getReason() != null) {
			user.setRequestReason(call.getReason());
		}
		
		
		
		this.executeWorkflow(user,call.getRequestParams());
		
	} 
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.Workflow#init()
	 */
	@Override
	public void init() throws ProvisioningException {
		Iterator<WorkflowTask> it = this.tasks.iterator();
		while (it.hasNext()) {
			it.next().initWorkFlow();
		}
		
	}

	

	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.Workflow#getId()
	 */
	@Override
	public int getId() {
		return id;
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.Workflow#setId(int)
	 */
	@Override
	public void setId(int id) {
		this.id = id;
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.Workflow#restart()
	 */
	@Override
	public void restart() throws ProvisioningException {
		for (WorkflowTask wft : this.tasks) {
			
			if (wft.isOnHold()) {
				
				boolean doContinue = wft.doTask(user,request);
				if (! doContinue) {
					
					return;
				}
			} else {
				wft.restartChildren();
			}
		}
		
		this.completeWorkflow();
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.Workflow#getUser()
	 */
	@Override
	public User getUser() {
		return this.user;
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.Workflow#completeWorkflow()
	 */
	@Override
	public void completeWorkflow() throws ProvisioningException {
		Connection con = null;
		try {
			con = this.cfgMgr.getProvisioningEngine().getApprovalDBConn();
			if (con != null) {
				DateTime now = new DateTime();
				PreparedStatement ps = con.prepareStatement("UPDATE workflows SET completeTS=? WHERE id=?");
				ps.setTimestamp(1, new Timestamp(now.getMillis()));
				ps.setLong(2, this.id);
				ps.executeUpdate();
				ps.close();
			}
		} catch (SQLException e) {
			throw new ProvisioningException("Could not complete workflow",e);
		} finally {
			if (con != null) {
				
				try {
					con.rollback();
				} catch (SQLException e1) {
					
				}
				
				try {
					con.close();
				} catch (SQLException e) {
					
				}
			}
		}
		
		
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.Workflow#findCurrentApprovalTask()
	 */
	@Override
	public Approval findCurrentApprovalTask() {
		for (WorkflowTask wft : this.tasks) {
			if (wft.isOnHold()) {
				return (Approval) wft;
			} else {
				Approval appr = (Approval) wft.findApprovalTask();
				if (appr != null) {
					return appr;
				}
			}
		}
		
		return null;
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.Workflow#getTasks()
	 */
	@Override
	public ArrayList<WorkflowTask> getTasks() {
		return tasks;
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.Workflow#getRequest()
	 */
	@Override
	public HashMap<String, Object> getRequest() {
		return this.request;
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.Workflow#getName()
	 */
	@Override
	public String getName() {
		return this.name;
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.Workflow#toString()
	 */
	@Override
	public String toString() {
		StringBuffer b = new StringBuffer();
		b.append(this.getName()).append("-----\n");
		for (WorkflowTask task : this.tasks) {
			this.printWF(b, "   ", task);
		}
		
		return b.toString();
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.Workflow#printWF(java.lang.StringBuffer, java.lang.String, com.tremolosecurity.provisioning.core.WorkflowTaskImpl)
	 */
	@Override
	public void printWF(StringBuffer b,String prefix,WorkflowTask task) {
		b.append(prefix).append(task.toString()).append('\n');
		if (task.getChildren() != null) {
			for (WorkflowTask c : task.getChildren()) {
				this.printWF(b, prefix + "   ", c);
			}
		}
	}
}
