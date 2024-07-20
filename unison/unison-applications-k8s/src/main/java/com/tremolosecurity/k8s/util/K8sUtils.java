//    Copyright 2021 Tremolo Security, Inc.
// 
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
// 
//        http://www.apache.org/licenses/LICENSE-2.0
// 
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.


package com.tremolosecurity.k8s.util;

import java.util.HashMap;
import java.util.Map;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

public class K8sUtils {

	public static Map<String,String> loadConfigMap(String targetName,String namespace,String configMapName) throws Exception {
		HashMap<String,String> map = new HashMap<String,String>();
		
		OpenShiftTarget k8s = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(targetName).getProvider();
		HttpCon con = k8s.createClient();
		
		try {
			StringBuilder sb = new StringBuilder();
			sb.append("/api/v1/namespaces/").append(namespace).append("/configmaps/").append(configMapName);
			String uri = sb.toString();
			
			String jsonData = k8s.callWS(k8s.getAuthToken(), con, uri);
			JSONObject root = (JSONObject)  new JSONParser().parse(jsonData);
			
			for (Object key : ((JSONObject)root.get("data")).keySet()) {
				map.put((String) key, (String) ((JSONObject) root.get("data")).get(key));
			}
			
		} finally {
			if (con != null) {
				con.getHttp().close();
				con.getBcm().close();
			}
		}
		
		
		
		return map;
	}
	
	public static Map<String,String> loadSecret(String targetName,String namespace,String configMapName) throws Exception {
		HashMap<String,String> map = new HashMap<String,String>();
		
		OpenShiftTarget k8s = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(targetName).getProvider();
		HttpCon con = k8s.createClient();
		
		try {
			StringBuilder sb = new StringBuilder();
			sb.append("/api/v1/namespaces/").append(namespace).append("/secrets/").append(configMapName);
			String uri = sb.toString();
			
			String jsonData = k8s.callWS(k8s.getAuthToken(), con, uri);
			JSONObject root = (JSONObject)  new JSONParser().parse(jsonData);
			
			for (Object key : ((JSONObject)root.get("data")).keySet()) {
				String b64val = (String) ((JSONObject) root.get("data")).get(key);
				map.put((String) key, new String(java.util.Base64.getDecoder().decode(b64val.getBytes("UTF-8"))) );
			}
			
		} finally {
			if (con != null) {
				con.getHttp().close();
				con.getBcm().close();
			}
		}
		
		
		
		return map;
	}
}
