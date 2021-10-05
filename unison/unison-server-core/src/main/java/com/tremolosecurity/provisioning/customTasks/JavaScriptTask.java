/*******************************************************************************
 * Copyright 2021 Tremolo Security, Inc.
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
package com.tremolosecurity.provisioning.customTasks;

import java.util.HashMap;
import java.util.Map;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;

import org.apache.log4j.Logger;
import org.graalvm.polyglot.*;
import org.graalvm.polyglot.proxy.*;

public class JavaScriptTask implements CustomTask {
	static Logger logger = Logger.getLogger(JavaScriptTask.class);
	
	String javaScript;
	Map<String,Object> state;
	boolean initCompleted;
	transient WorkflowTask task;

	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
		initCompleted = false;
		
		Context context = Context.newBuilder("js").allowAllAccess(true).build();
		context.getBindings("js").putMember("state", state);
		
		
		
		try {
			this.javaScript = params.get("javaScript").getValues().get(0);
			params.remove("javaScript");
			state = new HashMap<String,Object>();
			context.getBindings("js").putMember("state", state);
			Value val = context.eval("js",this.javaScript);
			
			Value init = context.getBindings("js").getMember("init");
			if (init == null || ! init.canExecute()) {
				throw new ProvisioningException("init function must be defined with two paramters");
			}
			
			Value reInit = context.getBindings("js").getMember("reInit");
			
			if (reInit == null || ! reInit.canExecute()) {
				throw new ProvisioningException("reInit function must be defined with one parameter");
			}
			
			Value doTask = context.getBindings("js").getMember("doTask");
			
			if (doTask == null || ! doTask.canExecute()) {
				throw new ProvisioningException("doTask function must be defined with two parameters and must return a boolean");
			}
			
			init.executeVoid(task,params);
			context.close();
			initCompleted = true;
			this.task = task;
		
		} catch (Throwable t) {
			logger.error("Could not initialize javascript task",t);
			return;
		}
		
	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		if (initCompleted) {
			Context context = Context.newBuilder("js").allowAllAccess(true).build();
			context.getBindings("js").putMember("state", state);
			Value val = context.eval("js",this.javaScript);
			
			Value init = context.getBindings("js").getMember("reInit");
			init.executeVoid(task);
			this.task = task;
		} else {
			throw new ProvisioningException("Javascript initialization did not complete, not attempting to reinit");
		}

	}

	@Override
	public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
		if (initCompleted) {
			Context context = Context.newBuilder("js").allowAllAccess(true).build();
			context.getBindings("js").putMember("state", state);
			context.getBindings("js").putMember("task", task);
			Value val = context.eval("js",this.javaScript);
			
			Value doTask = context.getBindings("js").getMember("doTask");
			Value result = doTask.execute(user,request);
			
			context.close();
			
			
			
			return result.asBoolean();
		} else {
			throw new ProvisioningException("Javascript initialization did not complete, not attempting to run task");
		}
	}

}
