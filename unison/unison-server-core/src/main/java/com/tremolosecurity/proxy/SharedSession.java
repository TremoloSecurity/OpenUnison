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

import java.io.IOException;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;

public class SharedSession {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(SharedSession.class);
	
	static SharedSession instance;
	
	
	SessionManager sessionMgr;
	
	
	
	public SharedSession(ConfigManager cfg) {
		
		this.sessionMgr = new SessionManagerImpl(cfg,cfg.getContext());
	}
	
	public HttpSession getSession(UrlHolder holder,HttpServletRequest request,HttpServletResponse response,ServletContext ctx) throws Exception {
		return this.sessionMgr.getSession(holder,request, response,ctx);
	}

	public HttpSession getSession(String sessionCookieName,UrlHolder holder,
			HttpServletRequest request, HttpServletResponse response, ServletContext ctx) throws Exception {
		return this.sessionMgr.getSession(sessionCookieName,holder, request, response, ctx);
	}

	public void clear(HttpSession sharedSession) {
		
		
	}

	public void writeSession(UrlHolder holder,
			TremoloHttpSession sharedSession, HttpServletRequest req,
			HttpServletResponse resp) throws IOException {
		this.sessionMgr.writeSession(holder, sharedSession, req, resp);
		
	}

	public void clearSession(UrlHolder holder,
			HttpSession sharedSession, HttpServletRequest req,
			HttpServletResponse resp) {
		this.sessionMgr.clearSession(holder, sharedSession, req, resp);
		
	}
	
	
	
	
}
