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

import java.io.IOException;

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

public class ValidateApplicationsWebhook implements HttpFilter {
	
	static Logger logger = Logger.getLogger(ValidateApplicationsWebhook.class);

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
				
				
				JSONArray urls = (JSONArray) spec.get("urls");
				
				if (urls != null) {
					int urli = 0;
					for (Object o : urls) {
						JSONObject url = (JSONObject) o;
						
						if (! checkUrlFilterChain(response, resp, admResp, urli, url)) {
							return;
						}
						
						if (! checkUrlIdp(response, resp, admResp, urli, url)) {
							return;
						}
						
						
						
						urli++;
					}
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

	private boolean checkUrlFilterChain(HttpFilterResponse response, JSONObject resp, JSONObject admResp, int urli,
			JSONObject url) throws IOException {
		JSONArray filterChain = (JSONArray) url.get("filterChain");
		
		if (filterChain != null) {
			int chaini = 0;
			for (Object x : filterChain) {
				JSONObject filter = (JSONObject) x;
				
				Object params = filter.get("params");
				
				if (params != null) {
				
					if (! (params instanceof JSONObject)) {
						JSONObject status = new JSONObject();
						status.put("code", 400);
						status.put("message", "spec.urls[" + urli + "].filterChain[" + chaini + "].params must be an object keys that must be a string or list of strings");
						
						admResp.put("status", status);
						
						
						response.getWriter().println(resp.toString());
						return false;
					}
					
					JSONObject jparams = (JSONObject) params;
					
					
					for (Object ox : jparams.keySet()) {
						String paramName = (String) ox;
						
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
									status.put("message", "spec.urls[" + urli + "].filterChain[" + chaini + "].params." + paramName + "[" + l + "] must be a string");
									
									admResp.put("status", status);
									
									
									response.getWriter().println(resp.toString());
									return false;
								}
								l++;
							}
						} else {
							JSONObject status = new JSONObject();
							status.put("code", 400);
							status.put("message", "spec.urls[" + urli + "].filterChain[" + chaini + "].params." + paramName + " must be a string or array of strings");
							
							admResp.put("status", status);
							
							
							response.getWriter().println(resp.toString());
							return false;
						}
					}
				}
				
				chaini++;
				
			}
			
			
		}
		
		return true;
	}
	
	private boolean checkUrlIdp(HttpFilterResponse response, JSONObject resp, JSONObject admResp, int urli,
			JSONObject url) throws IOException {
		JSONObject idp = (JSONObject) url.get("idp");
		
		if (idp != null) {
			
				
				
				Object params = idp.get("params");
				
				if (! (params instanceof JSONObject)) {
					JSONObject status = new JSONObject();
					status.put("code", 400);
					status.put("message", "spec.urls[" + urli + "].idp.params must be an object keys that must be a string or list of strings");
					
					admResp.put("status", status);
					
					
					response.getWriter().println(resp.toString());
					return false;
				}
				
				JSONObject jparams = (JSONObject) params;
				
				
				for (Object ox : jparams.keySet()) {
					String paramName = (String) ox;
					
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
								status.put("message", "spec.urls[" + urli + "].idp.params." + paramName + "[" + l + "] must be a string");
								
								admResp.put("status", status);
								
								
								response.getWriter().println(resp.toString());
								return false;
							}
							l++;
						}
					} else {
						JSONObject status = new JSONObject();
						status.put("code", 400);
						status.put("message", "spec.urls[" + urli + "].idp.params." + paramName + " must be a string or array of strings");
						
						admResp.put("status", status);
						
						
						response.getWriter().println(resp.toString());
						return false;
					}
				}
				
				if (! this.checkUrlIdpTrusts(response, resp, admResp, urli, idp)) {
					return false;
				}
				
				
			
			
		}
		
		return true;
	}
	
	private boolean checkUrlIdpTrusts(HttpFilterResponse response, JSONObject resp, JSONObject admResp, int urli,
			JSONObject idp) throws IOException {
		JSONArray trusts = (JSONArray) idp.get("trusts");
		
		if (trusts != null) {
			int trusti = 0;
			for (Object x : trusts) {
				JSONObject trust = (JSONObject) x;
				
				Object params = trust.get("params");
				
				if (! (params instanceof JSONObject)) {
					JSONObject status = new JSONObject();
					status.put("code", 400);
					status.put("message", "spec.urls[" + urli + "].idp.trusts[" + trusti + "].params must be an object keys that must be a string or list of strings");
					
					admResp.put("status", status);
					
					
					response.getWriter().println(resp.toString());
					return false;
				}
				
				JSONObject jparams = (JSONObject) params;
				
				
				for (Object ox : jparams.keySet()) {
					String paramName = (String) ox;
					
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
								status.put("message", "spec.urls[" + urli + "].idp.trusts[" + trusti + "].params." + paramName + "[" + l + "] must be a string");
								
								admResp.put("status", status);
								
								
								response.getWriter().println(resp.toString());
								return false;
							}
							l++;
						}
					} else {
						JSONObject status = new JSONObject();
						status.put("code", 400);
						status.put("message", "spec.urls[" + urli + "].idp.trusts[" + trusti + "].params." + paramName + " must be a string or array of strings");
						
						admResp.put("status", status);
						
						
						response.getWriter().println(resp.toString());
						return false;
					}
				}
				
				trusti++;
				
			}
			
			
		}
		
		return true;
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
