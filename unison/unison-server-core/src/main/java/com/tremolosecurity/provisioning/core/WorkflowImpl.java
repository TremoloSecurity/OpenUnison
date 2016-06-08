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

import static org.apache.directory.ldap.client.api.search.FilterBuilder.*;

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
import java.util.List;
import java.util.Map;
import java.util.Stack;

import org.apache.logging.log4j.Logger;
import org.hibernate.HibernateException;
import org.hibernate.Query;
import org.hibernate.Session;
import org.hibernate.resource.transaction.spi.TransactionStatus;
import org.joda.time.DateTime;
import org.stringtemplate.v4.ST;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.WorkflowTaskType;
import com.tremolosecurity.config.xml.WorkflowType;
import com.tremolosecurity.provisioning.objects.ApproverAttributes;
import com.tremolosecurity.provisioning.objects.Approvers;
import com.tremolosecurity.provisioning.objects.UserAttributes;
import com.tremolosecurity.provisioning.objects.Users;
import com.tremolosecurity.provisioning.objects.WorkflowParameters;
import com.tremolosecurity.provisioning.objects.Workflows;
import com.tremolosecurity.provisioning.service.util.TremoloUser;
import com.tremolosecurity.provisioning.service.util.WFCall;
import com.tremolosecurity.provisioning.tasks.Approval;
import com.tremolosecurity.provisioning.util.TaskHolder;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.AuthSys;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

public class WorkflowImpl implements  Workflow {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(WorkflowImpl.class.getName());
	String name;
	ArrayList<WorkflowTask> tasks;
	

	transient ConfigManager cfgMgr;
	private int id;
	private User user;
	private User requester;
	
	private HashMap<String,Object> request;
	private int userNum;
	private int requesterNum;
	
	private transient Workflows fromDB;
	private String description;
	private String label;
	
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
		this.description = wf.getDescription();
		this.label = wf.getLabel();
		
		if (this.description == null) {
			this.description = "";
		}
		
		Iterator<WorkflowTaskType> it = wf.getTasks().getWorkflowTasksGroup().iterator();
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
		this.executeWorkflow(user, params, null);
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.Workflow#executeWorkflow(com.tremolosecurity.provisioning.core.User, java.util.Map)
	 */
	@Override
	public void executeWorkflow(User user,Map<String,Object> params, String requesterUID) throws ProvisioningException {
		
		request = new HashMap<String,Object>();
		
		if (params != null) {
			request = (HashMap<String, Object>) params;
		}
		
		this.user = user;
		
		Session session = null;
		
		try {
			
			if (this.cfgMgr.getProvisioningEngine().getHibernateSessionFactory() != null) {
				session = this.cfgMgr.getProvisioningEngine().getHibernateSessionFactory().openSession();
				this.userNum = getUserNum(user,session,this.cfgMgr);
				
				if (requesterUID == null) {
					this.requester = this.user;
					this.requesterNum = this.userNum;
				} else {
					this.requester = getRequester(requesterUID,session,cfgMgr);
					this.requesterNum = getUserNum(requester,session,this.cfgMgr);
				}
				
				
				
				
				Workflows workflow = session.load(Workflows.class, this.getId());
				workflow.setUsers(session.load(Users.class, this.userNum));
				workflow.setRequester(session.load(Users.class, this.requesterNum));
				workflow.setRequestReason(user.getRequestReason());
				
				
				ST st = new ST(this.description,'$','$');
				for (String key : request.keySet()) {
					st.add(key.replaceAll("[.]", "_"), request.get(key));
				}
				
				workflow.setDescription(st.render());
				
				if (this.label != null) {
					st = new ST(this.label,'$','$');
					for (String key : request.keySet()) {
						st.add(key.replaceAll("[.]", "_"), request.get(key));
					}
					
					workflow.setLabel(st.render());
					
				} else {
					workflow.setLabel("");
				}
				
				
				session.beginTransaction();
				
				session.save(workflow);
				
				for (String paramName : params.keySet()) {
					WorkflowParameters param = new WorkflowParameters();
					param.setName(paramName);
					Object  o = params.get(paramName);
					if (o != null) {
						param.setValue(o.toString());
					} else {
						param.setValue("");
					}
					param.setWorkflows(workflow);
					session.save(param);
				}
				
				
				session.getTransaction().commit();
				
				
				
			}
		} catch (SQLException e) {
			throw new ProvisioningException("Could not set workflow user key",e);
		} catch (LDAPException e) {
			throw new ProvisioningException("Could not set workflow user key",e);
		} finally {
			if (session != null) {
				
				if (session.getTransaction() != null && session.getTransaction().getStatus() == TransactionStatus.ACTIVE) {
					session.getTransaction().rollback();
				}
				
				session.close();
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

	
	public static User getRequester(String requestorID, Session session,ConfigManager cfgMgr) throws LDAPException, SQLException {
		StringBuffer filter = new StringBuffer();
		
		
		
		
		LDAPSearchResults res = cfgMgr.getMyVD().search(cfgMgr.getCfg().getLdapRoot(), 2, equal(cfgMgr.getProvisioningEngine().getUserIDAttribute(),requestorID).toString(), new ArrayList<String>());
		LDAPEntry fromLDAP = null;
		if (res.hasMore()) {
			fromLDAP = res.next();
		}
		
		while (res.hasMore()) res.next();
		
		
		
		
		Query query = session.createQuery("FROM Users WHERE userKey = :user_key");
		query.setParameter("user_key", requestorID);
		List<Users> users = query.list();
		Users userObj = null;
		
		
		
		session.beginTransaction();
		
		int id = 0;
		
		User requestor = new User(requestorID);
		
		if (users.size() > 0) {
			userObj = users.get(0);
			id = userObj.getId();
			requestor.setJitAddToAuditDB(false);
			
		} else {
			
			userObj = new Users();
			userObj.setUserKey(requestor.getUserID());
			session.save(userObj);
			id = userObj.getId();
			
			if (fromLDAP != null) {
				for (String attr : cfgMgr.getProvisioningEngine().getUserAttrbiutes()) {
					UserAttributes nattr = new UserAttributes();
					
					nattr.setName(attr);
					LDAPAttribute userAttrFromLDAP = fromLDAP.getAttribute(attr);
					if (userAttrFromLDAP != null) {
						nattr.setValue(userAttrFromLDAP.getStringValue());
						
					}
					nattr.setUsers(userObj);
					userObj.getUserAttributeses().add(nattr);
					
					session.save(nattr);
					
				}
			}
			
		}
		
		for (UserAttributes attr : userObj.getUserAttributeses()) {
			Attribute nattr = requestor.getAttribs().get(attr.getName());
			if (nattr == null) {
				nattr = new Attribute(attr.getName());
				requestor.getAttribs().put(nattr.getName(), nattr);
			}
			nattr.getValues().add(attr.getValue());
		}
		
		if (! requestor.getAttribs().containsKey(cfgMgr.getProvisioningEngine().getUserIDAttribute())) {
			requestor.getAttribs().put(cfgMgr.getProvisioningEngine().getUserIDAttribute(), new Attribute(cfgMgr.getProvisioningEngine().getUserIDAttribute(),requestor.getUserID()));
		}
		
		requestor.setJitAddToAuditDB(true);
		session.getTransaction().commit();
		
		return requestor;
	}
	
	public static int getUserNum(User user, Session session,ConfigManager cfgMgr) throws LDAPException, SQLException {
		StringBuffer filter = new StringBuffer();
		
		
		
		
		LDAPSearchResults res = cfgMgr.getMyVD().search(cfgMgr.getCfg().getLdapRoot(), 2, and(equal(cfgMgr.getProvisioningEngine().getUserIDAttribute(),user.getAttribs().get(cfgMgr.getProvisioningEngine().getUserIDAttribute()).getValues().get(0)),equal("objectClass",cfgMgr.getCfg().getUserObjectClass())).toString(), new ArrayList<String>());
		LDAPEntry fromLDAP = null;
		if (res.hasMore()) {
			fromLDAP = res.next();
		}
		
		while (res.hasMore()) res.next();
		
		
		
		
		Query query = session.createQuery("FROM Users WHERE userKey = :user_key");
		query.setParameter("user_key", user.getUserID());
		List<Users> users = query.list();
		Users userObj = null;
		
		
		
		session.beginTransaction();
		
		int id = 0;
		
		if (users.size() > 0) {
			userObj = users.get(0);
			id = userObj.getId();
			user.setJitAddToAuditDB(false);
			
		} else {
			
			userObj = new Users();
			userObj.setUserKey(user.getUserID());
			
			
			
			session.save(userObj);
			
			id = userObj.getId();
			if (fromLDAP != null) {
				for (String attr : cfgMgr.getProvisioningEngine().getUserAttrbiutes()) {
					UserAttributes nattr = new UserAttributes();
					nattr.setName(attr);
					LDAPAttribute userAttrFromLDAP = fromLDAP.getAttribute(attr);
					if (userAttrFromLDAP != null) {
						nattr.setValue(userAttrFromLDAP.getStringValue());
						nattr.setUsers(userObj);
						session.save(nattr);
					} else {
						logger.warn("No value for attribute '" + attr + "'");
					}
					
					
					
					
				}
			} else {
				for (String attr : cfgMgr.getProvisioningEngine().getUserAttrbiutes()) {
					UserAttributes nattr = new UserAttributes();
					nattr.setName(attr);
					Attribute fromObj = user.getAttribs().get(attr);
					if (fromObj != null) {
						nattr.setValue(fromObj.getValues().get(0));
					} else {
						nattr.setValue("");
					}
					nattr.setUsers(userObj);
					
					session.save(nattr);
					
				}
			}
			
			user.setJitAddToAuditDB(true);
		}
		
	
		
		
		StringBuffer sb = new StringBuffer();
		
		
		if (! user.isJitAddToAuditDB()) {
			
			
			
			boolean changed = false;
			
			boolean found = false;
			
			for (String attr : cfgMgr.getProvisioningEngine().getUserAttrbiutes()) {
				for (UserAttributes userAttr : userObj.getUserAttributeses()) {
					if (attr.equalsIgnoreCase(userAttr.getName())) {
						found = true;
						if (fromLDAP != null) {
							LDAPAttribute userAttrFromLDAP = fromLDAP.getAttribute(attr);
							if (userAttrFromLDAP != null) {
								if (! userAttrFromLDAP.getStringValue().equals(userAttr.getValue())) {
									changed = true;
									userAttr.setValue(userAttrFromLDAP.getStringValue());
									
									session.save(userAttr);
								}
							}
						} 
						
					}
				}
			
				
				if (! found) {
					UserAttributes nattr = new UserAttributes();
					nattr.setName(attr);
					if (fromLDAP != null) {
						LDAPAttribute userAttrFromLDAP = fromLDAP.getAttribute(attr);
						if (userAttrFromLDAP != null) {
							nattr.setValue(userAttrFromLDAP.getStringValue());
						} 
					} else  {
						Attribute userAttr = user.getAttribs().get(attr);
						if (userAttr != null) {
							nattr.setValue(userAttr.getValues().get(0));
						}
					}
					
					if (nattr.getValue() == null) {
						nattr.setValue("");
					}
					
					nattr.setUsers(userObj);
					userObj.getUserAttributeses().add(nattr);
					session.save(nattr);
					changed = true;
				}
			
			}
			
			
			
			
			
			
			
			
			
			
			
			
			
			if (! changed) {
				user.setJitAddToAuditDB(false);
			} else {
				user.setJitAddToAuditDB(true);
			}
			
			
		}
		
		session.getTransaction().commit();
		
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
				
				root = (String) params.get(ProvisioningParams.UNISON_RESYNC_ROOT);
				
				if (root == null) {
					if (act != null) {
						root = act.getRoot();
					}
					if (root == null) {
						root = this.cfgMgr.getCfg().getLdapRoot();
					}
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
		
		
		
		this.executeWorkflow(user,call.getRequestParams(),call.getRequestor());
		
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
		Session session = null;
		try {
			
			if (this.cfgMgr.getProvisioningEngine().getHibernateSessionFactory() != null) {
				session = this.cfgMgr.getProvisioningEngine().getHibernateSessionFactory().openSession();
				session.beginTransaction();
				DateTime now = new DateTime();
				Workflows wf = session.load(Workflows.class, this.id);
				wf.setCompleteTs(new Timestamp(now.getMillis()));
				session.save(wf);
				session.getTransaction().commit();
				
			}
		} finally {
			if (session != null) {
				
				if (session.getTransaction() != null && session.getTransaction().getStatus() == TransactionStatus.ACTIVE) {
					session.getTransaction().rollback();
				}
				
				session.close();
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
		if (task.getOnSuccess() != null) {
			for (WorkflowTask c : task.getOnSuccess()) {
				this.printWF(b, prefix + " on success  ", c);
			}
		}
		
		if (task.getOnFailure() != null) {
			for (WorkflowTask c : task.getOnFailure()) {
				this.printWF(b, prefix + " on failure  ", c);
			}
		}
	}

	@Override
	public Workflows getFromDB(Session session) throws HibernateException, ProvisioningException {
		if (fromDB == null) {
			
			this.fromDB = session.load(Workflows.class,this.id);
		}
		
		return this.fromDB;
	}
	
	public void setFromDB(Workflows fromDB) {
		this.fromDB = fromDB;
	}

	@Override
	public User getRequester() {
		return this.requester;
	}

	@Override
	public int getRequesterNum() {
		return this.requesterNum;
	}
}
