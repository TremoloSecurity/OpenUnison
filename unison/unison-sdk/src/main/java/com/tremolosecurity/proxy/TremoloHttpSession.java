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


package com.tremolosecurity.proxy;

import java.io.Serializable;
import java.util.Enumeration;
import java.util.HashMap;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionContext;

import org.apache.logging.log4j.Logger;


import com.tremolosecurity.proxy.util.ItEnumeration;

public class TremoloHttpSession implements HttpSession, Serializable {

	long creationTime;
	long lastAccessedTime;
	int maxInactiveInterval;
	String id;
	boolean isNew;
	transient ServletContext ctx;
	transient SessionManager mgr;
	boolean isOpen;
	String appName;
	
	




	/**
	 * 
	 */
	

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(TremoloHttpSession.class);
	
	/**
	 * 
	 */
	
	HashMap<String,Object> data;
	
	
	
	public TremoloHttpSession(String id) {
		
		this.data = new HashMap<String,Object>();
		this.creationTime = System.currentTimeMillis();
		this.id = id;
		this.lastAccessedTime = System.currentTimeMillis();
		this.maxInactiveInterval = 0;
		this.isNew = true;
		
	}
	
	
	
	@Override
	public Object getAttribute(String key) {
		this.lastAccessedTime = System.currentTimeMillis();
		return data.get(key);
	}

	@Override
	public Enumeration getAttributeNames() {
		this.lastAccessedTime = System.currentTimeMillis();
		return new ItEnumeration(data.keySet().iterator());
	}

	@Override
	public long getCreationTime() {
		this.lastAccessedTime = System.currentTimeMillis();
		return this.creationTime;
	}

	@Override
	public String getId() {
		this.lastAccessedTime = System.currentTimeMillis();
		return this.id;
	}

	@Override
	public long getLastAccessedTime() {
		return this.lastAccessedTime;
	}

	@Override
	public int getMaxInactiveInterval() {
		this.lastAccessedTime = System.currentTimeMillis();
		return this.maxInactiveInterval;
	}

	@Override
	public ServletContext getServletContext() {
		this.lastAccessedTime = System.currentTimeMillis();
		return this.ctx;
	}
	
	public void refresh(ServletContext ctx,SessionManager mgr) {
		this.ctx = ctx;
		this.mgr = mgr;
	}

	@Override
	public HttpSessionContext getSessionContext() {
		return null;
	}

	@Override
	public Object getValue(String key) {
		this.lastAccessedTime = System.currentTimeMillis();
		return this.data.get(key);
	}

	@Override
	public String[] getValueNames() {
		this.lastAccessedTime = System.currentTimeMillis();
		String[] names = new String[this.data.keySet().size()];
		this.data.keySet().toArray(names);
		return names;
	}

	@Override
	public void invalidate() {
		this.lastAccessedTime = System.currentTimeMillis();
		
		this.mgr.invalidateSession(this);
		this.data = new HashMap<String,Object>();
	}

	@Override
	public boolean isNew() {
		this.lastAccessedTime = System.currentTimeMillis();
		if (isNew) {
			isNew = false;
			return true;
		} else {
			return false;
		}
	}

	@Override
	public void putValue(String key, Object value) {
		this.lastAccessedTime = System.currentTimeMillis();
		this.data.put(key, value);

	}

	@Override
	public void removeAttribute(String key) {
		this.lastAccessedTime = System.currentTimeMillis();
		this.data.remove(key);

	}

	@Override
	public void removeValue(String key) {
		this.lastAccessedTime = System.currentTimeMillis();
		this.data.remove(key);

	}

	@Override
	public void setAttribute(String key, Object value) {
		this.lastAccessedTime = System.currentTimeMillis();
		this.data.put(key, value);

	}

	@Override
	public void setMaxInactiveInterval(int val) {
		this.lastAccessedTime = System.currentTimeMillis();
		this.maxInactiveInterval = val;

	}



	public boolean isOpen() {
		return isOpen;
	}



	public void setOpen(boolean isOpen) {
		this.isOpen = isOpen;
	}



	public String getAppName() {
		return appName;
	}



	public void setAppName(String appName) {
		this.appName = appName;
	}
	
	

}
