/*******************************************************************************
 * Copyright 2019 Tremolo Security, Inc.
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
package com.tremolosecurity.scalejs.register.dynamicSource;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.provisioning.core.providers.ADProvider;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.scalejs.cfg.ScaleAttribute;
import com.tremolosecurity.scalejs.sdk.SourceList;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.util.NVP;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.*;

public class LoadFromLDAP implements SourceList {
	
	String nameField;
	String valueField;
	String errorMessage;
	int maxEntries;
	String searchBase;
	String objectClass;
	String searchAttribute;
	
	boolean sort;
	
	boolean dynSearch;
	
	@Override
	public void init(ScaleAttribute attribute, Map<String, Attribute> config) {
		
		nameField = config.get("nameField").getValues().get(0);
		valueField = config.get("valueField").getValues().get(0);
		this.searchAttribute = valueField;
		maxEntries = Integer.parseInt(config.get("maxEntries").getValues().get(0));
		searchBase = config.get("searchBase").getValues().get(0);
		errorMessage = config.get("errorMessage").getValues().get(0);
		objectClass = config.get("objectClass").getValues().get(0);
		
		this.sort = false;
		
		if (config.get("sort") != null) {
			this.sort = config.get("sort").getValues().get(0).equalsIgnoreCase("true");
		}
		
		dynSearch = attribute.getType().equalsIgnoreCase("text-list");
		
	}

	@Override
	public List<NVP> getSourceList(HttpFilterRequest request) throws Exception {
		if (request.getParameter("search") == null ) {
			ArrayList<NVP> toReturn = new ArrayList<NVP>();
			
			LDAPSearchResults res = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(this.searchBase, 2,and(equal("objectClass",this.objectClass),present(this.searchAttribute)).toString(), new ArrayList<String>());
			int num = 0;
			while (res.hasMore()) {
				if ((this.dynSearch && num < this.maxEntries) || ! this.dynSearch) {
					LDAPEntry entry = res.next();
					String name = entry.getAttribute(this.nameField).getStringValue();
					String value = entry.getAttribute(this.valueField).getStringValue();
					toReturn.add(new NVP(name,value));
				} else {
					res.next();
				}
				
				
				
				num++;
				
				
			}
			
			if (this.sort) {
				Collections.sort(toReturn, new Comparator<NVP>() {

				@Override
				public int compare(NVP arg0, NVP arg1) {
					return arg0.getName().compareTo(arg1.getName());
				}});
			}
			
			return toReturn;
		} else {
			ArrayList<NVP> toReturn = new ArrayList<NVP>();
			
			LDAPSearchResults res = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(this.searchBase, 2,and(equal("objectClass",this.objectClass),contains(this.searchAttribute,request.getParameter("search").getValues().get(0))).toString(), new ArrayList<String>());
			int num = 0;
			while (res.hasMore() && num < this.maxEntries) {
				LDAPEntry entry = res.next();
				String name = entry.getAttribute(this.nameField).getStringValue();
				String value = entry.getAttribute(this.valueField).getStringValue();
				toReturn.add(new NVP(name,value));
				num++;
			}
			
			while (res.hasMore()) res.next();
			
			if (this.sort) {
				Collections.sort(toReturn, new Comparator<NVP>() {

				@Override
				public int compare(NVP arg0, NVP arg1) {
					return arg0.getName().compareTo(arg1.getName());
				}});
			}
			
			return toReturn;
		}
		
		
	}

	@Override
	public String validate(String value, HttpFilterRequest request) throws Exception {
		LDAPSearchResults res = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(this.searchBase, 2,and(equal("objectClass",this.objectClass),equal(this.valueField,value)).toString(), new ArrayList<String>());
		if (res.hasMore()) {
			res.next();
			while (res.hasMore()) res.next();
			return null;
		} else {
			return this.errorMessage;
		}
	}

}
