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

import java.io.Serializable;
import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.apache.log4j.Logger;
import org.stringtemplate.v4.ST;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UnisonConfigManagerImpl;
import com.tremolosecurity.config.xml.WorkflowTaskType;
import com.tremolosecurity.provisioning.tasks.Approval;
import com.tremolosecurity.provisioning.util.TaskHolder;

public abstract class WorkflowTaskImpl implements Serializable, WorkflowTask {
	
	transient static Logger logger = Logger.getLogger(WorkflowTaskImpl.class.getName());

	private ArrayList<WorkflowTask> children;


	transient private WorkflowTaskType taskConfig;
	transient private ConfigManager cfgMgr;
	private Workflow workflow;
	private boolean isOnHold;
	
	public WorkflowTaskImpl() {
		
	}
	
	public WorkflowTaskImpl(WorkflowTaskType taskConfig,ConfigManager cfg,Workflow wf) throws ProvisioningException {
		this.taskConfig = taskConfig;
		this.cfgMgr = cfg;
		this.children = new ArrayList<WorkflowTask>();
		Iterator<WorkflowTaskType> it = taskConfig.getWorkflowTasksGroup().iterator();
		this.workflow = wf;
		while (it.hasNext()) {
			WorkflowTaskType childCfg = it.next();
			this.children.add(loadTask(childCfg,cfg,wf));
		}
		
		this.setOnHold(false);
		
		//this.init(taskConfig);
	}
	
	@Override
	public abstract String getLabel();
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.WorkflowTask#init(com.tremolosecurity.config.xml.WorkflowTaskType)
	 */
	@Override
	public abstract void init(WorkflowTaskType taskConfig)throws ProvisioningException ;
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.WorkflowTask#doTask(com.tremolosecurity.provisioning.core.User, java.util.HashMap)
	 */
	@Override
	public abstract boolean doTask(User user,Map<String,Object> request) throws ProvisioningException;
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.WorkflowTask#reInit()
	 */
	@Override
	public void reInit() throws ProvisioningException  {	
		
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.WorkflowTask#reInit(com.tremolosecurity.config.util.ConfigManager, com.tremolosecurity.provisioning.core.Workflow)
	 */
	@Override
	public final void reInit(ConfigManager cfgMgr,Workflow wf) throws ProvisioningException {
		this.cfgMgr = cfgMgr;
		this.workflow = wf;
		this.reInit();
		for (WorkflowTask wft : this.children) {
			wft.reInit(cfgMgr,wf);
		}
	}
	
	public static WorkflowTaskImpl loadTask(WorkflowTaskType cfg,ConfigManager cfgMgr,Workflow wf) throws ProvisioningException  {
		String className = cfg.getClass().getName().substring(cfg.getClass().getName().lastIndexOf('.') + 1,cfg.getClass().getName().length() - 4);
		StringBuffer b = new StringBuffer();
		b.append("com.tremolosecurity.provisioning.tasks.").append(className.substring(0,1).toUpperCase()).append(className.substring(1));
		className = b.toString();
		
		if (logger.isDebugEnabled()) {
			logger.debug("Task Class : " + className);
		}
		try {
			Class cls = Class.forName(className);
			Constructor constructor = cls.getConstructor(WorkflowTaskType.class,ConfigManager.class,Workflow.class);
			WorkflowTaskImpl wft = (WorkflowTaskImpl) constructor.newInstance(cfg,cfgMgr,wf);
			return wft;
		} catch (Exception e) {
			throw new ProvisioningException("Could not load workflow task",e);
		}
		
	}
	
	protected final boolean runChildren(User user,Map<String,Object> request) throws ProvisioningException {
		
		if (request.get(ProvisioningParams.UNISON_EXEC_TYPE) != null && request.get(ProvisioningParams.UNISON_EXEC_TYPE).equals(ProvisioningParams.UNISON_EXEC_SYNC)) {
			Iterator<WorkflowTask> it = this.children.iterator();
			
			while (it.hasNext()) {
				boolean doContinue = it.next().doTask(user,request);
				if (! doContinue) {
					return false;
				}
			}
			
			return true;
		} else {
			WorkflowHolder holder = (WorkflowHolder) request.get(WorkflowHolder.WF_HOLDER_REQUEST);
			TaskHolder th = new TaskHolder();
			th.setPosition(0);
			th.setParent(children);
			th.setCurrentUser(user);
			holder.getWfStack().push(th);
			((ProvisioningEngineImpl) this.cfgMgr.getProvisioningEngine()).enqueue(holder);
			return false;
		}
	}
	
	protected final boolean restartChildren(User user,Map<String,Object> request) throws ProvisioningException {
		Iterator<WorkflowTask> it = this.children.iterator();
		
		
		while (it.hasNext()) {
			WorkflowTask wft = it.next();
			if (wft.isOnHold()) {
				
				boolean doContinue = wft.doTask(user,request);
				if (! doContinue) {
					return false;
				}
			} else {
				return wft.restartChildren();
			}
			
		}
		
		return true;
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.WorkflowTask#initWorkFlow()
	 */
	@Override
	public void initWorkFlow() throws ProvisioningException {
		this.init(this.taskConfig);
		
		Iterator<WorkflowTask> it = this.children.iterator();
		while (it.hasNext()) {
			it.next().initWorkFlow();
		}
		
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.WorkflowTask#getConfig()
	 */
	@Override
	public final WorkflowTaskType getConfig() {
		return this.taskConfig;
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.WorkflowTask#getConfigManager()
	 */
	@Override
	public final ConfigManager getConfigManager() {
		return this.cfgMgr;
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.WorkflowTask#setConfigManager(com.tremolosecurity.config.util.ConfigManager)
	 */
	@Override
	public final void setConfigManager(ConfigManager mgr) {
		this.cfgMgr = cfgMgr;
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.WorkflowTask#getWorkflow()
	 */
	@Override
	public Workflow getWorkflow() {
		return workflow;
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.WorkflowTask#setWorkflow(com.tremolosecurity.provisioning.core.Workflow)
	 */
	@Override
	public void setWorkflow(Workflow workflow) {
		this.workflow = workflow;
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.WorkflowTask#isOnHold()
	 */
	@Override
	public boolean isOnHold() {
		return isOnHold;
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.WorkflowTask#setOnHold(boolean)
	 */
	@Override
	public void setOnHold(boolean isOnHold) {
		this.isOnHold = isOnHold;
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.WorkflowTask#restartChildren()
	 */
	@Override
	public boolean restartChildren() throws ProvisioningException {
		return true;
		
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.WorkflowTask#findApprovalTask()
	 */
	@Override
	public Approval findApprovalTask() {
		if (this.children == null || this.children.size() == 0) {
			return null;
		}
		
		for (WorkflowTask wft : this.children) {
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
	 * @see com.tremolosecurity.provisioning.core.WorkflowTask#getChildren()
	 */
	@Override
	public ArrayList<WorkflowTask> getChildren() {
		return children;
	}
	
	@Override
	public String renderTemplate(String val,Map<String,Object> request) {
		ST st = new ST(val,'$','$');
		for (String key : request.keySet()) {
			st.add(key.replaceAll("[.]", "_"), request.get(key));
		}
		
		return st.render();
	}
	
}
