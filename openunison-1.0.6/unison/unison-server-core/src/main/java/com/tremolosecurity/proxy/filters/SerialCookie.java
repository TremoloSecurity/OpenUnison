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


package com.tremolosecurity.proxy.filters;

import java.io.Serializable;

import javax.servlet.http.Cookie;

import org.joda.time.DateTime;

class SerialCookie implements Serializable {


	
	/**
	 * 
	 */
	private static final long serialVersionUID = -2200516828006881862L;
	/**
	 * 
	 */
	
	DateTime created;
	String comment;
	String domain;
	String name;
	String value;
	String path;
	boolean secure;
	int version;
	int age;
	
	
	public Object clone() {
		return new SerialCookie(this);
	}

	
	public String getComment() {
		return this.comment;
	}

	
	public String getDomain() {
		return this.domain;
	}

	
	public int getMaxAge() {
		return this.age;
	}

	
	public String getName() {
		return this.name;
	}

	
	public String getPath() {
		return this.path;
	}

	
	public boolean getSecure() {
		return this.secure;
	}

	
	public String getValue() {
		return this.value;
	}

	
	public int getVersion() {
		return this.version;
	}

	
	public void setComment(String purpose) {
		this.comment = purpose;
	}

	
	public void setDomain(String pattern) {
		this.domain = pattern;
	}

	
	public void setMaxAge(int expiry) {
		this.age = expiry;
	}

	
	public void setPath(String uri) {
		this.path = uri;
	}

	
	public void setSecure(boolean flag) {
		this.secure = flag;
	}

	
	public void setValue(String newValue) {
		this.value = newValue;
	}

	
	public void setVersion(int v) {
		this.version = v;
	}

	public SerialCookie(String name, String value) {
		
		this.name = name;
		this.value = value;
		this.created = new DateTime();
	}
	
	public SerialCookie(SerialCookie orig) {
		
		this.age = orig.age;
		this.comment = orig.comment;
		this.domain = orig.domain;
		this.name = orig.name;
		this.path = orig.path;
		this.secure = orig.secure;
		this.value = orig.value;
		this.version = orig.version;
		this.created = new DateTime();
	}
	
	public SerialCookie(Cookie orig) {
		
		this.age = orig.getMaxAge();
		this.comment = orig.getComment();
		this.domain = orig.getDomain();
		this.name = orig.getName();
		this.path = orig.getPath();
		this.secure = orig.getSecure();
		this.value = orig.getValue();
		this.version = orig.getVersion();
		this.created = new DateTime();
	}
	

	
	public boolean isValid() {
		if (this.age < 0) {
			return true;
		} else {
			DateTime expires = this.created.plusSeconds(this.age);
			DateTime now = new DateTime();
			if (now.compareTo(expires) < 0) {
				return true;
			} else {
				return false;
			}
		}
	}
	
	public Cookie genCookie() {
		Cookie c = new Cookie(this.name,this.value);
		return c;
	}
	
	
}