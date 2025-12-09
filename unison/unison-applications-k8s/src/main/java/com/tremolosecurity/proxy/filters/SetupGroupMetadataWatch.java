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
package com.tremolosecurity.proxy.filters;


import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.tremolosecurity.proxy.dynamicconfiguration.LoadNamespaceGroupMetadataFromK8s;
import org.apache.log4j.Logger;

import com.novell.ldap.util.DN;
import com.tremolosecurity.proxy.dynamicconfiguration.LoadGroupMetadataFromK8s;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;


public class SetupGroupMetadataWatch implements HttpFilter {
	
	static Logger logger = Logger.getLogger(SetupGroupMetadataWatch.class);

	static Map<String,GroupMetadata> metadatas;
	static Map<String,NamespaceGroupMetadata> groupmetadatas;
	static LoadGroupMetadataFromK8s lgm;
	static LoadNamespaceGroupMetadataFromK8s lnsgm;
	static Map<String,List<String>> ext2k8s;
	static Map<String,String> k8s2ext;
	
	
	
	boolean extIsDN;
	String target;
	String namespace;



	@Override
	public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		chain.nextFilter(request, response, chain);
		
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
	public synchronized void  initFilter(HttpFilterConfig config) throws Exception {
		this.extIsDN = config.getAttribute("extIsDN").getValues().get(0).equalsIgnoreCase("true");
		this.target = config.getAttribute("target").getValues().get(0);
		this.namespace = config.getAttribute("namespace").getValues().get(0);

		if (this.metadatas == null) {
			metadatas = new HashMap<String,GroupMetadata>();
		}
		
		if (ext2k8s == null) {
			ext2k8s = new HashMap<String, List<String>>();
		}
		
		if (k8s2ext == null) {
			k8s2ext = new HashMap<String,String>();
		}

		if (groupmetadatas == null) {
			groupmetadatas = new HashMap<String,NamespaceGroupMetadata>();
		}
		
		if (lgm == null) {
			lgm = new LoadGroupMetadataFromK8s();
			lgm.loadGroupMetadatas(config.getConfigManager(),target,namespace,this);
		}

		if (lnsgm == null) {
			lnsgm = new LoadNamespaceGroupMetadataFromK8s();
			lnsgm.loadNamespaceGroupMetadatas(config.getConfigManager(),target,namespace,this);
		}

		
	}
	
	public static List<String> getK8s(String ext) {
		return ext2k8s.get(ext.toLowerCase()); 
	}
	
	public static String getExt(String k8s) {
		return k8s2ext.get(k8s.toLowerCase());
	}
	
	
	public synchronized void addMapping(String name,String k8s,String ext) {
		synchronized (ext2k8s) {
			synchronized (k8s2ext) {
				synchronized (metadatas) {



					ext = ext.toLowerCase();
					k8s = k8s.toLowerCase();

					metadatas.put(name,new GroupMetadata(name,k8s,ext));

					if (extIsDN) {
						DN dn = new DN(ext);
						ext = dn.toString();
					}

					List<String> k8sFromExt = ext2k8s.get(ext);
					if (k8sFromExt == null) {
						k8sFromExt = new ArrayList<String>();
						ext2k8s.put(ext, k8sFromExt);
					}

					k8sFromExt.add(k8s);


					k8s2ext.put(k8s, ext);
				}
			}
		}

	}

	public synchronized void addNamespaceMapping(String name, JSONObject mapping) {
		synchronized (ext2k8s) {
			synchronized (k8s2ext) {
				synchronized (groupmetadatas) {


					String namespace = mapping.get("namespace").toString();
					String cluster = mapping.get("cluster").toString();

					JSONArray mappings = (JSONArray) mapping.get("mappings");
					ArrayList<NamespaceMapping> metadatas = new ArrayList<NamespaceMapping>();
					for (Object o : mappings) {
						JSONObject mappingObj = (JSONObject) o;

						String k8s = (String) mappingObj.get("groupName");
						String ext = (String) mappingObj.get("externalName");
						String role = (String) mappingObj.get("roleName");
						ext = ext.toLowerCase();
						k8s = k8s.toLowerCase();


						if (extIsDN) {
							DN dn = new DN(ext);
							ext = dn.toString();
						}


						metadatas.add(new NamespaceMapping(role,k8s,ext));

						List<String> k8sFromExt = ext2k8s.get(ext);
						if (k8sFromExt == null) {
							k8sFromExt = new ArrayList<String>();
							ext2k8s.put(ext, k8sFromExt);
						}

						k8sFromExt.add(k8s);


						k8s2ext.put(k8s, ext);

					}

					groupmetadatas.put(name,new NamespaceGroupMetadata(name,cluster,namespace,metadatas));

				}
			}
		}

	}
	
	
	public synchronized void deleteMapping(String name) {
		synchronized (ext2k8s) {
		synchronized (k8s2ext) {
			synchronized (metadatas) {

				GroupMetadata gm = metadatas.remove(name);
				if (gm == null) {
					return;
				}

				String ext = gm.ext;
				String k8s = gm.group;

				removeMapping(ext, k8s);
			}
		}
		}
	}

	public synchronized void deleteNamespaceMapping(String name) {
		synchronized (ext2k8s) {
			synchronized (k8s2ext) {
				synchronized (groupmetadatas) {

					NamespaceGroupMetadata gm = groupmetadatas.remove(name);
					if (gm == null) {
						return;
					}

					for (NamespaceMapping nm : gm.mappings) {
						String ext = nm.ext;
						String k8s = nm.group;

						removeMapping(ext, k8s);
					}


				}
			}
		}
	}

	private void removeMapping(String ext, String k8s) {
		if (extIsDN && ext != null) {
			DN dn = new DN(ext);
			ext = dn.toString();
		}

		String keyToDel = null;
		String valToDel = null;
		for (String key : ext2k8s.keySet()) {
			if (ext2k8s.get(key) != null) {
				for (String val : ext2k8s.get(key)) {
					if (val.equalsIgnoreCase(k8s)) {
						keyToDel = key;
						valToDel = val;
						break;
					}
				}
			}


		}


		if (ext2k8s.get(keyToDel) != null) {
			ext2k8s.get(keyToDel).remove(valToDel);
			if (ext2k8s.get(keyToDel).size() == 0) {
				ext2k8s.remove(keyToDel);
				logger.info("deleting " + keyToDel);
			}
		}

		keyToDel = null;

		for (String key : k8s2ext.keySet()) {
			if (k8s2ext.get(key) != null && k8s2ext.get(key).equalsIgnoreCase(ext)) {
				keyToDel = key;
				break;
			}
		}


		k8s2ext.remove(keyToDel);
	}


}

class GroupMetadata {
	public GroupMetadata(String name, String k8s, String ext) {
		this.name = name;
		this.ext = ext;
		this.group = k8s;
	}
	String name;
	String group;
	String ext;
	boolean enabled;
}

class NamespaceGroupMetadata {
	String name;
	String cluster;
	String namespace;
	boolean enabled;
	List<NamespaceMapping> mappings;

	public NamespaceGroupMetadata(String name,String cluster,String namespace,List<NamespaceMapping> mappings) {
		this.name = name;
		this.cluster = cluster;
		this.namespace = namespace;
		this.mappings = mappings;

	}
}

class NamespaceMapping {
	String role;
	String group;
	String ext;

	public NamespaceMapping(String role, String group, String ext) {
		this.role = role;
		this.group = group;
		this.ext = ext;
	}
}
