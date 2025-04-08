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
import java.util.concurrent.ConcurrentHashMap;

import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;

public interface SessionManager {

	public abstract void invalidateSession(TremoloHttpSession tsession);

	public abstract HttpSession getSession(UrlHolder holder,
			HttpServletRequest request, HttpServletResponse response,
			ServletContext ctx) throws Exception;

	public abstract HttpSession getSession(String sessionCookieName,
			UrlHolder holder, HttpServletRequest request,
			HttpServletResponse response, ServletContext ctx) throws Exception;

	public abstract void writeSession(UrlHolder holder,
			TremoloHttpSession session, HttpServletRequest request,
			HttpServletResponse response) throws IOException;

	public abstract void clearSession(UrlHolder holder,
			HttpSession sharedSession, HttpServletRequest request,
			HttpServletResponse response);

	public abstract void resetSessionChecker(ConfigManager cfg);

	public abstract ConcurrentHashMap<String, TremoloHttpSession> getSessions();
	
	public abstract void stopSessionChecker();

	public abstract void removeSessionFromCache(TremoloHttpSession tsession);

	public abstract void shutdownSession(TremoloHttpSession tsession);

	public abstract void addUserSession(String userDN, TremoloHttpSession session);

	public abstract void removeUserSession(String dn, TremoloHttpSession session);

	public abstract void logoutAll(String userdn);
}