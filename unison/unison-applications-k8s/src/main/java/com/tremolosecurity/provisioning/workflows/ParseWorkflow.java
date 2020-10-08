/*******************************************************************************
 * Copyright 2020 Tremolo Security, Inc.
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
package com.tremolosecurity.provisioning.workflows;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import org.apache.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.tremolosecurity.config.xml.AddAttributeType;
import com.tremolosecurity.config.xml.AddGroupType;
import com.tremolosecurity.config.xml.CallWorkflowType;
import com.tremolosecurity.config.xml.CustomTaskType;
import com.tremolosecurity.config.xml.DeleteType;
import com.tremolosecurity.config.xml.NotifyUserType;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.config.xml.ParamWithValueType;
import com.tremolosecurity.config.xml.ResyncType;
import com.tremolosecurity.config.xml.WorkflowTaskType;
import com.tremolosecurity.config.xml.WorkflowTasksType;

public class ParseWorkflow {
	
	static Logger logger = Logger.getLogger(ParseWorkflow.class.getName());
	
	public ParsedWorkflow parseWorkflow(String json ) {
		ParsedWorkflow pw = new ParsedWorkflow();
		
		JSONParser parser = new JSONParser();
		Object o;
		try {
			o = parser.parse(json);
		} catch (ParseException e) {
			logger.error("Unable to parse JSON",e);
			pw.setError(e.toString());
			pw.setErrorPath("$");
			return pw;
		}
		
		if (! (o instanceof JSONArray)) {
			pw.setError("Top level must be an array");
			pw.setErrorPath("$");
			return pw;
		}
		
		JSONArray tasks = (JSONArray) o;
		int i = 0;
		for (Object ox : tasks) {
			JSONObject node = (JSONObject) ox;
			parseNode(node,"$[" + i + "]",pw.getWft().getTasks(),pw);
			if (pw.getError() != null) {
				return pw;
			}
			i++;
		}
		
		return pw;
	}
	
	private void parseNode(JSONObject node,String path,WorkflowTasksType parent,ParsedWorkflow pw)  {
		if (node.get("taskType") == null) {
			pw.setError("No taskType specified");
			pw.setErrorPath(path);
			return;
		} 
		
		String taskType = (String) node.get("taskType");
		String value;
		
		if (taskType.equals("notifyUser")) {
			createNotify(node, path, parent, pw);
		} else if (taskType.equals("addAttribute")) {
			createAddAttribute(node, path, parent, pw);
		} else if (taskType.equals("addGroup")) {
			createAddGroup(node, path, parent, pw);
		} else if (taskType.equals("callWorkflow")) {
			createCallWorkflow(node, path, parent, pw);
		} else if (taskType.equals("callWorkflow")) {
			createCallWorkflow(node, path, parent, pw);
		} else if (taskType.equals("delete")) {
			createDelete(node, path, parent, pw);
		} else if (taskType.equals("resync")) {
			createResync(node, path, parent, pw);
		} else if (taskType.equals("customTask")) {
			createCustomTask(node, path, parent, pw);
		} else {
			pw.setError("Invalid taskType " + taskType);
			pw.setErrorPath(path);
		}
		
		
	}

	private void createCustomTask(JSONObject node, String path, WorkflowTasksType parent, ParsedWorkflow pw) {
		CustomTaskType task = new CustomTaskType();
		
		OptionType[] options = new OptionType[] {
			new OptionType("className",true,OptionType.OptionValueType.STRING)
			
		};
		
		for (OptionType ot : options) {
			setAttribute(node,ot,task,CustomTaskType.class,pw,path);
			if (pw.getError() != null) {
				return;
			}
		}
		
		Object op = node.get("params");
		if (op != null) {
			if (! (op instanceof JSONArray)) {
				pw.setError("params must be an array");
				pw.setErrorPath(path + ".params");
				return;
			}
			
			int ii = 0;
			JSONArray params = (JSONArray) op;
			
			options = new OptionType[] {
					new OptionType("name",true,OptionType.OptionValueType.STRING),
					new OptionType("value",true,OptionType.OptionValueType.STRING)
					
				};
			
			for (Object o : params) {
				if (! (o instanceof JSONObject)) {
					pw.setError("each param must be an object");
					pw.setErrorPath(path + ".params[" + ii + "]");
					return;
				}
				
				JSONObject param = (JSONObject) o;
				
				ParamWithValueType pt = new ParamWithValueType();
				
				for (OptionType ot : options) {
					setAttribute(param,ot,pt,ParamWithValueType.class,pw,path + ".params[" + ii + "]");
					if (pw.getError() != null) {
						return;
					}
				}
				
				task.getParam().add(pt);
				
				
				ii++;
			}
		}
		
		parent.getWorkflowTasksGroup().add(task);
	}

	private void createResync(JSONObject node, String path, WorkflowTasksType parent, ParsedWorkflow pw) {
		ResyncType task = new ResyncType();
		
		OptionType[] options = new OptionType[] {
			new OptionType("newRoot",false,OptionType.OptionValueType.STRING),
			new OptionType("changeRoot",false,OptionType.OptionValueType.BOOLEAN),
			new OptionType("keepExternalAttrs",false,OptionType.OptionValueType.BOOLEAN)
			
		};
		
		for (OptionType ot : options) {
			setAttribute(node,ot,task,ResyncType.class,pw,path);
			if (pw.getError() != null) {
				return;
			}
		}
		
		parent.getWorkflowTasksGroup().add(task);
	}

	private void createDelete(JSONObject node, String path, WorkflowTasksType parent, ParsedWorkflow pw) {
		DeleteType task = new DeleteType();
		
		OptionType[] options = new OptionType[] {
			new OptionType("target",true,OptionType.OptionValueType.STRING)
			
		};
		
		for (OptionType ot : options) {
			setAttribute(node,ot,task,DeleteType.class,pw,path);
			if (pw.getError() != null) {
				return;
			}
		}
		
		parent.getWorkflowTasksGroup().add(task);
	}

	private void createCallWorkflow(JSONObject node, String path, WorkflowTasksType parent, ParsedWorkflow pw) {
		CallWorkflowType task = new CallWorkflowType();
		
		OptionType[] options = new OptionType[] {
			new OptionType("name",true,OptionType.OptionValueType.STRING)
			
		};
		
		for (OptionType ot : options) {
			setAttribute(node,ot,task,CallWorkflowType.class,pw,path);
			if (pw.getError() != null) {
				return;
			}
		}
		
		parent.getWorkflowTasksGroup().add(task);
	}

	private void createAddGroup(JSONObject node, String path, WorkflowTasksType parent, ParsedWorkflow pw) {
		AddGroupType task = new AddGroupType();
		
		OptionType[] options = new OptionType[] {
			new OptionType("name",true,OptionType.OptionValueType.STRING),
			new OptionType("remove",false,OptionType.OptionValueType.BOOLEAN)
		};
		
		for (OptionType ot : options) {
			setAttribute(node,ot,task,AddGroupType.class,pw,path);
			if (pw.getError() != null) {
				return;
			}
		}
		
		parent.getWorkflowTasksGroup().add(task);
	}

	private void createAddAttribute(JSONObject node, String path, WorkflowTasksType parent, ParsedWorkflow pw) {
		AddAttributeType task = new AddAttributeType();
		
		OptionType[] options = new OptionType[] {
			new OptionType("name",true,OptionType.OptionValueType.STRING),
			new OptionType("value",true,OptionType.OptionValueType.STRING),
			new OptionType("remove",false,OptionType.OptionValueType.BOOLEAN),
			new OptionType("addToRequest",false,OptionType.OptionValueType.BOOLEAN)
		};
		
		for (OptionType ot : options) {
			setAttribute(node,ot,task,AddAttributeType.class,pw,path);
			if (pw.getError() != null) {
				return;
			}
		}
		
		parent.getWorkflowTasksGroup().add(task);
	}

	private void createNotify(JSONObject node, String path, WorkflowTasksType parent, ParsedWorkflow pw) {
		NotifyUserType notifyUser = new NotifyUserType();
		
		OptionType[] options = new OptionType[] {
			new OptionType("subject",true,OptionType.OptionValueType.STRING),
			new OptionType("msg",true,OptionType.OptionValueType.STRING),
			new OptionType("mailAttrib",true,OptionType.OptionValueType.STRING),
			new OptionType("contentType",false,OptionType.OptionValueType.STRING)
		};
		
		for (OptionType ot : options) {
			setAttribute(node,ot,notifyUser,NotifyUserType.class,pw,path);
			if (pw.getError() != null) {
				return;
			}
		}
		
		parent.getWorkflowTasksGroup().add(notifyUser);
	}
	
	private void setAttribute(JSONObject node,OptionType ot,Object wfTask,Class destType,ParsedWorkflow pw,String path) {
		if (node.containsKey(ot.name)) {
			Object val = node.get(ot.getName());
			switch (ot.getType()) {
				case STRING : {
					setAttributeLocal(node,ot,wfTask,destType,pw,path,val,String.class);
					break;
				}
				
				case BOOLEAN : {
					setAttributeLocal(node,ot,wfTask,destType,pw,path,val,Boolean.class);		
					break;
				}
			}
		} else {
			if (ot.isRequired()) {
				pw.setErrorPath(path);
				pw.setError("Attribute " + ot.getName() + " not found");
			}
		}
	}
	
	private void setAttributeLocal(JSONObject node,OptionType ot,Object wfTask,Class destType,ParsedWorkflow pw,String path,Object val,Class paramType) {
		if (! (val.getClass() ==  paramType)) {
			pw.setError("Attribute " + ot.getName() + " must be a " + paramType.getSimpleName().toLowerCase());
			pw.setErrorPath(path);
			return;
		}
		
		Method setter = findMethod(ot.getName(),destType,paramType);
		if (setter == null) {
			pw.setError("Invalid attribute " + ot.getName());
			pw.setErrorPath(path);
			return;
		} 
		
		try {
			setter.invoke(wfTask, val);
		} catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
			logger.warn("Could not set " + ot.getName(),e);
			pw.setError("Error setting " + ot.getName());
			pw.setErrorPath(path);
		}
	}
	
	private Method findMethod(String attributeName,Class<WorkflowTaskType> destType,Class paramType) {
		String methodName = "set" + attributeName.substring(0,1).toUpperCase() + attributeName.substring(1);
		try {
			return destType.getDeclaredMethod(methodName, paramType);
		} catch (NoSuchMethodException | SecurityException e) {
			logger.warn("Could not set " + attributeName,e);
			return null;
		}
	}
}
