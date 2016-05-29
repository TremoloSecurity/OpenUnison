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


package com.tremolosecurity.lastmile.servlet3x.filter;

import java.security.Principal;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Vector;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.filter.AutoIDMPrincipal;
import com.tremolosecurity.saml.Attribute;

public class UnisonLastMileRequest extends HttpServletRequestWrapper {

	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(UnisonLastMileRequest.class);
	
	HttpServletRequest request;
	com.tremolosecurity.lastmile.LastMile lastmile;
	HashMap<String,Vector<String>> headers;
	String userAttribute;
	HashMap<String,com.tremolosecurity.saml.Attribute> attribs;
	HashSet<String> roles;
	
	

	
	public UnisonLastMileRequest(HttpServletRequest request,com.tremolosecurity.lastmile.LastMile lastmile,String userAttribute,String roleAttribute,boolean toHeaders) {
		
		super(request);
		
		this.request = request;
		this.lastmile = lastmile;
		this.userAttribute = userAttribute;
		this.headers = new HashMap<String,Vector<String>>();
		this.attribs = new HashMap<String,Attribute>();
		this.roles = new HashSet<String>();
		
		Enumeration headerNames = request.getHeaderNames();
		while (headerNames.hasMoreElements()) {
			String name = (String) headerNames.nextElement();
			Vector<String> vals = new Vector<String>();
			Enumeration enumvals = request.getHeaders(name);
			while (enumvals.hasMoreElements()) {
				String val = (String) enumvals.nextElement(); 
				//if (logger.isDebugEnabled()) {
					////System.out.println("Header From Assertion : " + name + "='" + val + "'");
				//}
				
				vals.add(val);
			}
			this.headers.put(name, vals);
			
		}
		
		
		Iterator<Attribute> attribs = lastmile.getAttributes().iterator();
		while (attribs.hasNext()) {
			Attribute attrib = attribs.next();
			if (toHeaders) {
				
				Vector<String> vals = this.headers.get(attrib.getName());
				if (vals == null) {
					vals = new Vector<String>();
					this.headers.put(attrib.getName(), vals);
				}
				vals.addAll(attrib.getValues());
			}
			
			this.attribs.put(attrib.getName(), attrib);
			
			if (attrib.getName().equals(roleAttribute)) {
				this.roles.addAll(attrib.getValues());
			}
		}
			
		
	}
	
	@Override
	public String getAuthType() {
		return "";
	}
	
	@Override
	public long getDateHeader(String name) {
		
		if (logger.isDebugEnabled()) {
			logger.debug("Header Requested : '" + name + "'" );
		}
		
		if (! this.headers.containsKey(name)) {
			return -1;
		} else {
			return Long.parseLong(this.headers.get(name).get(0));
		}
	}

	@Override
	public String getHeader(String name) {
		
		if (logger.isDebugEnabled()) {
			logger.debug("Header Requested : '" + name + "'" );
		}
		
		if (! this.headers.containsKey(name)) {
			return null;
		} else {
			return this.headers.get(name).get(0);
		}
	}

	@Override
	public Enumeration getHeaderNames() {
		Vector names = new Vector();
		names.addAll(this.headers.keySet());
		return names.elements();
	}

	@Override
	public Enumeration getHeaders(String name) {
		if (! this.headers.containsKey(name)) {
			return null;
		} else {
			return this.headers.get(name).elements();
		}
	}

	@Override
	public int getIntHeader(String name) {
		if (! this.headers.containsKey(name)) {
			return 0;
		} else {
			return Integer.parseInt(this.headers.get(name).get(0));
		}
	}
	
	@Override
	public String getRemoteUser() {
		return this.attribs.get(this.userAttribute).getValues().get(0);
	}
	
	@Override
	public Principal getUserPrincipal() {
		if (this.attribs.get(this.userAttribute) != null) {
			return new AutoIDMPrincipal(this.attribs.get(this.userAttribute).getValues().get(0),this.attribs);
		} else {
			return null;
		}
	}
	
	

}
