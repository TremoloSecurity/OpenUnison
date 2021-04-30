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
package com.tremolosecurity.proxy.dynamicconfiguration.webhooks;

import org.apache.log4j.Logger;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.tremolosecurity.proxy.ProxySys;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class ValidateAuthChainsWebhook implements HttpFilter {
	
	static Logger logger = Logger.getLogger(ValidateAuthChainsWebhook.class);

	@Override
	public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		
		
		
		request.getServletRequest().setAttribute("com.tremolosecurity.unison.proxy.noRedirectOnError", "com.tremolosecurity.unison.proxy.noRedirectOnError");
		
		
		JSONObject resp = new JSONObject();
		resp.put("apiVersion", "admission.k8s.io/v1");
		resp.put("kind", "AdmissionReview");
		JSONObject admResp = new JSONObject();
		resp.put("response", admResp);
		
		String json = new String( (byte[]) request.getAttribute(ProxySys.MSG_BODY));
		String reviewId = null;
		try {
			JSONObject admissionReview = (JSONObject) new JSONParser().parse(json);
			JSONObject admReq = (JSONObject) admissionReview.get("request");
			reviewId = (String) admReq.get("uid");
			String op = (String) admReq.get("operation");
			admResp.put("uid", reviewId);
			
			
			if (op.equals("CREATE") || op.equals("UPDATE")) {
				
				
				
				JSONObject root = (JSONObject) admReq.get("object");
				JSONObject spec = (JSONObject) root.get("spec");
				
				JSONArray authMechs = (JSONArray) spec.get("authMechs");
				
				int i = 0;
				
				for (Object oo : authMechs) {
					JSONObject authMech = (JSONObject) oo;
					
					Object params = authMech.get("params");
					
					if (! (params instanceof JSONObject)) {
						JSONObject status = new JSONObject();
						status.put("code", 400);
						status.put("message", "spec.authMechs[" + i + "].params must be an object keys that must be a string or list of strings");
						
						admResp.put("status", status);
						
						
						response.getWriter().println(resp.toString());
						return;
					}
					
					JSONObject jparams = (JSONObject) params;
					
					
					for (Object o : jparams.keySet()) {
						String paramName = (String) o;
						
						Object ov = jparams.get(paramName);
						
						if (ov instanceof String) {
							//we're ok, do nothing
						} else if (ov instanceof JSONArray) {
							int l = 0;
							JSONArray vals = (JSONArray) ov;
							for (Object ol : vals) {
								if (! (ol instanceof String)) {
									JSONObject status = new JSONObject();
									status.put("code", 400);
									status.put("message", "spec.authMechs[" + i + "].params." + paramName + "[" + l + "] must be a string");
									
									admResp.put("status", status);
									
									
									response.getWriter().println(resp.toString());
									return;
								}
								l++;
							}
						} else {
							JSONObject status = new JSONObject();
							status.put("code", 400);
							status.put("message", "spec.authMechs[" + i + "].params." + paramName + " must be a string or array of strings");
							
							admResp.put("status", status);
							
							
							response.getWriter().println(resp.toString());
							return;
						}
					}
					
					i++;
				}
				
				
				admResp.put("allowed", true);
				response.setStatus(200);
				response.setContentType("application/json");
				response.getWriter().println(resp.toString());
				
				
			}
			
			
		} catch (Throwable t) {
			logger.error("Could not process review",t);
			
			JSONObject status = new JSONObject();
			status.put("code", 500);
			status.put("message", "There was an error processing your request, see the logs for a stack trace");
			
			admResp.put("status", status);
			
			
			
			response.setStatus(500);
			response.setContentType("application/json");
			response.getWriter().println(resp.toString());
			
		}

	}
	
	String convertYamlToJson(String yaml) throws JsonMappingException, JsonProcessingException {
	    ObjectMapper yamlReader = new ObjectMapper(new YAMLFactory());
	    Object obj = yamlReader.readValue(yaml, Object.class);

	    ObjectMapper jsonWriter = new ObjectMapper();
	    return jsonWriter.writeValueAsString(obj);
	}

	@Override
	public void filterResponseText(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			StringBuffer data) throws Exception {
		

	}

	@Override
	public void filterResponseBinary(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			byte[] data, int length) throws Exception {
		

	}

	@Override
	public void initFilter(HttpFilterConfig config) throws Exception {
		

	}

}
