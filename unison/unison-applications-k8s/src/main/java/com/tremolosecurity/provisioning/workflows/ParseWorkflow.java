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
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.tremolosecurity.config.xml.AddAttributeType;
import com.tremolosecurity.config.xml.AddGroupType;
import com.tremolosecurity.config.xml.ApprovalType;
import com.tremolosecurity.config.xml.AzRuleType;
import com.tremolosecurity.config.xml.AzRulesType;
import com.tremolosecurity.config.xml.CallWorkflowType;
import com.tremolosecurity.config.xml.CustomTaskType;
import com.tremolosecurity.config.xml.DeleteType;
import com.tremolosecurity.config.xml.EscalationFailureType;
import com.tremolosecurity.config.xml.EscalationPolicyType;
import com.tremolosecurity.config.xml.EscalationType;
import com.tremolosecurity.config.xml.IfAttrExistsType;
import com.tremolosecurity.config.xml.IfAttrHasValueType;
import com.tremolosecurity.config.xml.IfNotUserExistsType;
import com.tremolosecurity.config.xml.MappingType;
import com.tremolosecurity.config.xml.NotifyUserType;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.config.xml.ParamWithValueType;
import com.tremolosecurity.config.xml.ProvisionMappingType;
import com.tremolosecurity.config.xml.ProvisionMappingsType;
import com.tremolosecurity.config.xml.ResyncType;
import com.tremolosecurity.config.xml.WorkflowChoiceTaskType;
import com.tremolosecurity.config.xml.WorkflowTaskListType;
import com.tremolosecurity.config.xml.WorkflowTaskType;
import com.tremolosecurity.config.xml.WorkflowTasksType;

import edu.emory.mathcs.backport.java.util.Arrays;

public class ParseWorkflow {
	
	static Logger logger = Logger.getLogger(ParseWorkflow.class.getName());
	
	static HashSet<String> approversAllowedScopes = new HashSet<String>(Arrays.asList(new String[]{"filter","group","dn","dynamicGroup","custom"}));
	static HashSet<String> approversEscUnits = new HashSet<String>(Arrays.asList(new String[]{"sec","min","hr","wk","day"}));
	static HashSet<String> escalationFailureActions = new HashSet<String>(Arrays.asList(new String[]{"assign","leave"}));
	
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
			parseNode(node,"$[" + i + "]",pw.getWft().getTasks().getWorkflowTasksGroup(),pw);
			if (pw.getError() != null) {
				return pw;
			}
			i++;
		}
		
		return pw;
	}
	
	private void parseNode(JSONObject node,String path,List<WorkflowTaskType> parent,ParsedWorkflow pw)  {
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
		} else if (taskType.equals("delete")) {
			createDelete(node, path, parent, pw);
		} else if (taskType.equals("resync")) {
			createResync(node, path, parent, pw);
		} else if (taskType.equals("customTask")) {
			createCustomTask(node, path, parent, pw);
		} else if (taskType.equals("ifAttrExists")) {
			createIfAttrExistsTask(node, path, parent, pw);
		} else if (taskType.equals("ifAttrHasValue")) {
			createIfAttrHasValueTask(node, path, parent, pw);
		} else if (taskType.equals("ifNotUserExists")) {
			createIfNotUserExistsTask(node, path, parent, pw);
		} else if (taskType.equals("mapping")) {
			createMappingTask(node, path, parent, pw);
		} else if (taskType.equals("approval")) {
			createApprovalTask(node, path, parent, pw);
		}
		
		else {
			pw.setError("Invalid taskType " + taskType);
			pw.setErrorPath(path);
		}
		
		
	}
	
	
	
	private void createApprovalTask(JSONObject node, String path, List<WorkflowTaskType> parent, ParsedWorkflow pw) {
		ApprovalType task = new ApprovalType();
		task.setApprovers(new AzRulesType());
		
		
		OptionType[] options = new OptionType[] {
				new OptionType("emailTemplate",true,OptionType.OptionValueType.STRING),
				new OptionType("mailAttr",true,OptionType.OptionValueType.STRING),
				new OptionType("failureEmailSubject",true,OptionType.OptionValueType.STRING),
				new OptionType("failureEmailMsg",true,OptionType.OptionValueType.STRING),
				new OptionType("label",true,OptionType.OptionValueType.STRING)
				
			};
			
			for (OptionType ot : options) {
				setAttribute(node,ot,task,ApprovalType.class,pw,path);
				if (pw.getError() != null) {
					return;
				}
			}
			
			Object o = node.get("approvers");
			
			parseApprovers(path, pw, task.getApprovers(), o,"approvers");
			if (pw.getError() != null) {
				return;
			}
			
			
			o = node.get("escalationPolicy");
			if (o != null) {
				task.setEscalationPolicy(new EscalationPolicyType());
				
				if (! (o instanceof JSONObject)) {
					pw.setErrorPath(path + ".escalationPolicy");
					pw.setError("escalationPolicy must be an object");
					return;
					
				}
				
				JSONObject escPolicy = (JSONObject) o;
				
				o = escPolicy.get("escalations");
				if (o == null) {
					pw.setErrorPath(path + ".escalationPolicy.escalations");
					pw.setError("At least one escalation must be specified");
					return;
				}
				
				if (! (o instanceof JSONArray)) {
					pw.setErrorPath(path + ".escalationPolicy.escalations");
					pw.setError("escalations must be an array");
					return;
				}
				
				JSONArray escs = (JSONArray) o;
				int ii = 0;
				
				OptionType[] escOpts = new OptionType[] {
						new OptionType("executeAfterTime",true,OptionType.OptionValueType.INT),
						new OptionType("validateEscalationClass",false,OptionType.OptionValueType.STRING),
						new OptionType("executeAfterUnits",true,OptionType.OptionValueType.STRING,ParseWorkflow.approversEscUnits)
						
					};
				
				
				
				for (Object ox : escs) {
					EscalationType esc = new EscalationType();
					esc.setAzRules(new AzRulesType());
					
					if (! (ox instanceof JSONObject)) {
						pw.setErrorPath(path + ".escalationPolicy.escalations[" + ii + "]");
						pw.setError("escalation must be an object");
						return;
					}
					
					JSONObject jesc = (JSONObject)ox;
					
					
					for (OptionType ot : escOpts) {
						setAttribute(jesc,ot,esc,EscalationType.class,pw ,path + ".escalationPolicy.escalations[" + ii + "]");
						if (pw.getError() != null) {
							return;
						}
					}
					
					o = jesc.get("azRules");
					
					parseApprovers(path + ".escalationPolicy.escalations[" + ii + "]", pw, esc.getAzRules(), o,"azRules");
					if (pw.getError() != null) {
						return;
					}
					
					task.getEscalationPolicy().getEscalation().add(esc);
					ii++;
				}
				
				
				o = escPolicy.get("failure");
				if (o != null) {
					if (! (o instanceof JSONObject)) {
						pw.setErrorPath(path + ".escalationPolicy.failure");
						pw.setError("filure must be an object");
						return;
					}
					
					JSONObject escFailure = (JSONObject) o;
					EscalationFailureType eft = new EscalationFailureType();
					eft.setAzRules(new AzRulesType());
					
					task.getEscalationPolicy().setEscalationFailure(eft);
					
					OptionType[] escfOpts = new OptionType[] {
							new OptionType("action",true,OptionType.OptionValueType.STRING,ParseWorkflow.escalationFailureActions)
							
						};
					
					for (OptionType ot : escfOpts) {
						setAttribute(escFailure,ot,eft,EscalationFailureType.class,pw,path + ".escalationPolicy.failure");
						if (pw.getError() != null) {
							return;
						}
					}
					
					o = escFailure.get("azRules");
					
					parseApprovers(path + ".escalationPolicy.failure", pw, eft.getAzRules(), o,"azRules");
					if (pw.getError() != null) {
						return;
					}	
				
				}
			}
			
			
			
			loadSubTasks(node, path, pw, task);
			if (pw.getError() != null) {
				return;
			}
			
			parent.add(task);
		
		
	}

	private void loadSubTasks(JSONObject node, String path, ParsedWorkflow pw, WorkflowChoiceTaskType task) {
		
		Object o = node.get("onSuccess");
		
		
		if (o != null) {
			if (! (o instanceof JSONArray)) {
				pw.setError("onSuccess must be an array");
				pw.setErrorPath(path + ".onSuccess");
				return;
			}
			
			JSONArray subTasks = (JSONArray) o; 
		
			task.setOnSuccess(new WorkflowTaskListType());
			
			int i = 0;
			for (Object ox : subTasks) {
				if (! (ox instanceof JSONObject)) {
					pw.setError("onSuccess members must be an object");
					pw.setErrorPath(path + ".onSuccess[" + i + "]");
					return;
				}
				JSONObject subNode = (JSONObject) ox;
				parseNode(subNode,path + ".onSuccess[" + i + "]",task.getOnSuccess().getWorkflowTasksGroup(),pw);
				if (pw.getError() != null) {
					return;
				}
				i++;
			}
		}
		
		
		o = node.get("onFailure");
		
		if (o != null) {
		
			if (! (o instanceof JSONArray)) {
				pw.setError("onFailure must be an array");
				pw.setErrorPath(path + ".onFailure");
				return;
			}
			
			JSONArray subTasks = (JSONArray) o;
		
			task.setOnFailure(new WorkflowTaskListType());
			
			int i = 0;
			for (Object ox : subTasks) {
				
				if (! (ox instanceof JSONObject)) {
					pw.setError("onFailure members must be an object");
					pw.setErrorPath(path + ".onFailure[" + i + "]");
					return;
				}
				
				JSONObject subNode = (JSONObject) ox;
				parseNode(subNode,path + ".onFailure[" + i + "]",task.getOnFailure().getWorkflowTasksGroup(),pw);
				if (pw.getError() != null) {
					return;
				}
				i++;
			}
		}
	}

	private void parseApprovers(String path, ParsedWorkflow pw, AzRulesType azt, Object o,String keyName) {
		if (o == null) {
			pw.setErrorPath(pw + "." + keyName);
			pw.setError(keyName + " required");
			return;
		}
		
		if (! (o instanceof JSONArray)) {
			pw.setErrorPath(pw + "." + keyName);
			pw.setError(keyName + " must be an array");
			return;
		}
		
		JSONArray approvers = (JSONArray) o;
		int ii = 0;
		for (Object ox : approvers) {
			if (! (ox instanceof JSONObject)) {
				pw.setErrorPath(pw + "." + keyName + "[" + ii + "]");
				pw.setError(keyName.substring(0,keyName.length()-1) + " must be an object");
				return;
			}
			
			JSONObject approver = (JSONObject) ox;
			
			
			OptionType[] approverOptions = new OptionType[] {
					new OptionType("scope",true,OptionType.OptionValueType.STRING,ParseWorkflow.approversAllowedScopes),
					new OptionType("constraint",true,OptionType.OptionValueType.STRING)
			};
			
			
			AzRuleType at = new AzRuleType();
			
			for (OptionType ot : approverOptions) {
				setAttribute(approver,ot,at,AzRuleType.class,pw,path);
				
				if (pw.getError() != null) {
					return;
				}
				
				
				
			}
			
			azt.getRule().add(at);
			
			
			ii++;
			
		}
	}

	
	private void createMappingTask(JSONObject node, String path, List<WorkflowTaskType> parent, ParsedWorkflow pw) {
		MappingType task = new MappingType();
		
		OptionType[] options = new OptionType[] {
				new OptionType("strict",false,OptionType.OptionValueType.BOOLEAN)
				
			};
			
			for (OptionType ot : options) {
				setAttribute(node,ot,task,MappingType.class,pw,path);
				if (pw.getError() != null) {
					return;
				}
			}
			
			task.setMap(new ProvisionMappingsType());
			
			Object o = node.get("map");
			if (o == null) {
				pw.setError("map required and must be an array");
				pw.setErrorPath(path);
				return;
				
			} 
			
			if (! (o instanceof JSONArray)) {
				pw.setError("map must be an array");
				pw.setErrorPath(path);
				return;
			}
			
			int ii = 0;
			JSONArray map = (JSONArray) o;
			for (Object oo : map) {
				if (! (oo instanceof JSONObject)) {
					pw.setError("All map entries must be objects");
					pw.setErrorPath(path + ".map[" + ii + "]");
					ii++;
					return;
				}
				
				JSONObject mapNode = (JSONObject) oo;
				
				options = new OptionType[] {
						new OptionType("targetAttributeName",true,OptionType.OptionValueType.STRING),
						new OptionType("sourceType",true,OptionType.OptionValueType.STRING),
						new OptionType("targetAttributeSource",true,OptionType.OptionValueType.STRING)
						
				};
				
				ProvisionMappingType pmt = new ProvisionMappingType();
				for (OptionType ot : options) {
					setAttribute(mapNode,ot,pmt,ProvisionMappingType.class,pw,path);
					if (pw.getError() != null) {
						return;
					}
				}
				task.getMap().getMapping().add(pmt);
				
				
				
			}
			
			
			loadSubTasks(node, path, pw, task);
			if (pw.getError() != null) {
				return;
			}
			
			
			
			parent.add(task);
		
		
	}
	
	private void createIfAttrExistsTask(JSONObject node, String path, List<WorkflowTaskType> parent, ParsedWorkflow pw) {
		IfAttrExistsType task = new IfAttrExistsType();
		
		OptionType[] options = new OptionType[] {
				new OptionType("name",true,OptionType.OptionValueType.STRING)
				
			};
			
			for (OptionType ot : options) {
				setAttribute(node,ot,task,IfAttrExistsType.class,pw,path);
				if (pw.getError() != null) {
					return;
				}
			}
			
			loadSubTasks(node, path, pw, task);
			if (pw.getError() != null) {
				return;
			}
			
			parent.add(task);
		
		
	}
	
	private void createIfAttrHasValueTask(JSONObject node, String path, List<WorkflowTaskType> parent, ParsedWorkflow pw) {
		IfAttrHasValueType task = new IfAttrHasValueType();
		
		OptionType[] options = new OptionType[] {
				new OptionType("name",true,OptionType.OptionValueType.STRING),
				new OptionType("value",true,OptionType.OptionValueType.STRING)
				
			};
			
			for (OptionType ot : options) {
				setAttribute(node,ot,task,IfAttrHasValueType.class,pw,path);
				if (pw.getError() != null) {
					return;
				}
			}
			
			loadSubTasks(node, path, pw, task);
			if (pw.getError() != null) {
				return;
			}
			
			parent.add(task);
		
		
	}
	
	private void createIfNotUserExistsTask(JSONObject node, String path, List<WorkflowTaskType> parent, ParsedWorkflow pw) {
		IfNotUserExistsType task = new IfNotUserExistsType();
		
		OptionType[] options = new OptionType[] {
				new OptionType("target",true,OptionType.OptionValueType.STRING),
				new OptionType("uidAttribute",true,OptionType.OptionValueType.STRING)
				
			};
			
			for (OptionType ot : options) {
				setAttribute(node,ot,task,IfNotUserExistsType.class,pw,path);
				if (pw.getError() != null) {
					return;
				}
			}
			
			loadSubTasks(node, path, pw, task);
			if (pw.getError() != null) {
				return;
			}
			
			parent.add(task);
		
		
	}

	private void createCustomTask(JSONObject node, String path, List<WorkflowTaskType> parent, ParsedWorkflow pw) {
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
		
		parent.add(task);
	}

	private void createResync(JSONObject node, String path, List<WorkflowTaskType> parent, ParsedWorkflow pw) {
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
		
		parent.add(task);
	}

	private void createDelete(JSONObject node, String path, List<WorkflowTaskType> parent, ParsedWorkflow pw) {
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
		
		parent.add(task);
	}

	private void createCallWorkflow(JSONObject node, String path, List<WorkflowTaskType> parent, ParsedWorkflow pw) {
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
		
		parent.add(task);
	}

	private void createAddGroup(JSONObject node, String path, List<WorkflowTaskType> parent, ParsedWorkflow pw) {
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
		
		parent.add(task);
	}

	private void createAddAttribute(JSONObject node, String path, List<WorkflowTaskType> parent, ParsedWorkflow pw) {
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
		
		parent.add(task);
	}

	private void createNotify(JSONObject node, String path, List<WorkflowTaskType> parent, ParsedWorkflow pw) {
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
		
		parent.add(notifyUser);
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
				
				case INT : {
					setAttributeLocal(node,ot,wfTask,destType,pw,path,val,Long.class);		
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
		
		if (ot.getAllowedValues() != null) {
			if (! ot.getAllowedValues().contains(val)) {
				pw.setError("Attribute " + ot.getName() + " must be one of " + ot.getAllowedValues().toString());
				pw.setErrorPath(path);
				return;
			}
		}
		
		Method setter = findMethod(ot.getName(),destType,paramType);
		if (setter == null) {
			pw.setError("Invalid attribute " + ot.getName());
			pw.setErrorPath(path);
			return;
		} 
		
		try {
			if (paramType == Long.class) {
				val = new Integer(((Long) val).intValue());
			}
			setter.invoke(wfTask, val);
		} catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
			logger.warn("Could not set " + ot.getName(),e);
			pw.setError("Error setting " + ot.getName());
			pw.setErrorPath(path);
		}
	}
	
	private Method findMethod(String attributeName,Class<WorkflowTaskType> destType,Class paramType) {
		if (paramType == Long.class) {
			paramType = Integer.class;
		}
		String methodName = "set" + attributeName.substring(0,1).toUpperCase() + attributeName.substring(1);
		try {
			return destType.getDeclaredMethod(methodName, paramType);
		} catch (NoSuchMethodException | SecurityException e) {
			logger.warn("Could not set " + attributeName,e);
			return null;
		}
	}
}
