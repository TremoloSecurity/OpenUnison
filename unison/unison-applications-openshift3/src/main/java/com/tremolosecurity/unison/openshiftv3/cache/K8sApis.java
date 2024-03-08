/*******************************************************************************
 * Copyright (c) 2024 Tremolo Security, Inc.
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
package com.tremolosecurity.unison.openshiftv3.cache;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpClient.Version;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

public class K8sApis {
	
	static Logger logger = Logger.getLogger(K8sApis.class);
	
    Map<String,K8sApiGroup> apiGroups;
    private K8sApiGroupVersion v1;
	private OpenShiftTarget target;
	private boolean initialized = false;
    public K8sApis(OpenShiftTarget target) {
        this.target = target;
        this.initialized = false;
    }

    private void loadApis() throws Exception {
        // first get all the APIs
       
        
        
        HttpCon con = null;
        try {
        
	        con = this.target.createClient();
	        this.apiGroups = new HashMap<String,K8sApiGroup>();
	
	
	        
	
	        String json = target.callWS(target.getAuthToken(), con, "/apis");
	
	        if (logger.isDebugEnabled()) {
	        	logger.debug("APIs: " + json);
	        }
	
	        JSONObject root = (JSONObject) new JSONParser().parse(json);
	
	        JSONArray groups = (JSONArray) root.get("groups");
	
	        for (Object o : groups) {
	            JSONObject group = (JSONObject) o;
	            String name = (String) group.get("name");
	            
	            JSONArray versions = (JSONArray) group.get("versions");
	
	            K8sApiGroup apiGroup = new K8sApiGroup(name);
	            this.apiGroups.put(name,apiGroup);
	
	
	            for (Object oo : versions) {
	                JSONObject version = (JSONObject) oo;
	
	                K8sApiGroupVersion apiGroupVersion = new K8sApiGroupVersion((String)version.get("groupVersion"));
	
	                apiGroup.getVersions().put(apiGroupVersion.getVersion(),apiGroupVersion);
	
	                if (logger.isDebugEnabled()) {
	                	logger.debug(version.get("groupVersion"));
	                }
	
	                String uri = String.format("/apis/%s",version.get("groupVersion"));
	                
	                
	                
	
	                
	
	                String groupJson = target.callWS(target.getAuthToken(), con, uri);
	                
	                if (logger.isDebugEnabled()) {
	                	logger.debug(groupJson);
	                }
	                
	                JSONObject groupRoot = (JSONObject) new JSONParser().parse(groupJson);
	
	                JSONArray resources = (JSONArray) groupRoot.get("resources");
	
	                for (Object r : resources) {
	                    JSONObject resource = (JSONObject) r;
	                    if (resource.get("singularName") != null && ! resource.get("name").toString().contains("/")) {
	                        K8sApi api = new K8sApi((String)resource.get("name"),(String)resource.get("singularName"),(String)resource.get("kind"),(Boolean)resource.get("namespaced"),apiGroupVersion);
	                        apiGroupVersion.getApis().put(api.getKind(), api);
	                    }
	                    
	                }
	
	                
	            }
	
	        }
	
	        
	
	        
	
	        json = target.callWS(target.getAuthToken(), con, "/api/v1");
	
	        if (logger.isDebugEnabled()) {
	        	logger.debug(json);
	        }
	
	        this.v1 = new K8sApiGroupVersion();
	
	        JSONObject groupRoot = (JSONObject) new JSONParser().parse(json);
	
	        JSONArray resources = (JSONArray) groupRoot.get("resources");
	
	        for (Object r : resources) {
	            JSONObject resource = (JSONObject) r;
	            if (resource.get("singularName") != null && ! resource.get("name").toString().contains("/")) {
	                K8sApi api = new K8sApi((String)resource.get("name"),(String)resource.get("singularName"),(String)resource.get("kind"),(Boolean)resource.get("namespaced"),this.v1);
	                this.v1.getApis().put(api.getKind(), api);
	            }
	            
	        }
	        
	        this.initialized = true;
        } finally {
        	if (con != null) {
        		try {
        		con.getHttp().close();
        		} catch (Exception e) {}
        		
        		con.getBcm().close();
        	}
        }

    }

    public String getUri(String apiVersion,String kind) throws Exception {
    	String uri = this.getUriInternal(apiVersion, kind);
    	if (uri == null) {
    		synchronized(this) {
    			this.loadApis();
    		}
    		uri = this.getUriInternal(apiVersion, kind);
    	}
    	
    	return uri;
    }
    
    private String getUriInternal(String apiVersion,String kind) throws Exception {
    	
    	synchronized (this) {
    		if (! initialized) {
    			this.loadApis();
    		}
    	}
    	
    	if (apiVersion.indexOf('/') > 0) {
    	
	    	String api = apiVersion.substring(0,apiVersion.indexOf('/'));
	    	String version = apiVersion.substring(apiVersion.indexOf('/') + 1);
	    	
	    	K8sApiGroup apiGroup = this.apiGroups.get(api);
	    	if (apiGroup == null) {
	    		return null;
	    	}
	    	
	    	K8sApiGroupVersion apiGroupVersion =  apiGroup.getVersions().get(apiVersion);
	    	if (apiGroupVersion == null) {
	    		return null;
	    	}
	    	
	    	K8sApi apiCfg = apiGroupVersion.getApis().get(kind);
	    	if (apiCfg == null) {
	    		return null;
	    	}
	    	
	    	String uri = String.format("/apis/%s/%s/%s", api,version,apiCfg.getName());
	    	return uri;
    	} else {
    		K8sApi apiCfg = this.v1.getApis().get(kind);
    		if (apiCfg == null) {
	    		return null;
	    	}
	    	
	    	String uri = String.format("/api/v1/%s", apiCfg.getName());
	    	return uri;
    	}
    }
    
    
    public String getUri(String apiVersion,String kind,String namespace) throws Exception {
    	String url = this.getUriInternal(apiVersion, kind, namespace);
    	if (url == null) {
    		synchronized (this) {
    			this.loadApis();
    		}
    		url = this.getUriInternal(apiVersion, kind, namespace);
    	}
    	return url;
    }
    
    
    private String getUriInternal(String apiVersion,String kind,String namespace) throws Exception {
    	
    	synchronized (this) {
    		if (! initialized) {
    			this.loadApis();
    		}
    	}
    	
    	
    	if (apiVersion.indexOf('/') > 0) {
    	
	    	String api = apiVersion.substring(0,apiVersion.indexOf('/'));
	    	String version = apiVersion.substring(apiVersion.indexOf('/') + 1);
	    	
	    	K8sApiGroup apiGroup = this.apiGroups.get(api);
	    	if (apiGroup == null) {
	    		return null;
	    	}
	    	
	    	K8sApiGroupVersion apiGroupVersion =  apiGroup.getVersions().get(apiVersion);
	    	if (apiGroupVersion == null) {
	    		return null;
	    	}
	    	
	    	K8sApi apiCfg = apiGroupVersion.getApis().get(kind);
	    	if (apiCfg == null) {
	    		return null;
	    	}
	    	
	    	String uri = String.format("/apis/%s/%s/namespaces/%s/%s", api,version,namespace,apiCfg.getName());
	    	return uri;
    	} else {
    		K8sApi apiCfg = this.v1.getApis().get(kind);
    		if (apiCfg == null) {
	    		return null;
	    	}
	    	
	    	String uri = String.format("/api/v1/namespaces/%s/%s", namespace,apiCfg.getName());
	    	return uri;
    	}
    }


}
