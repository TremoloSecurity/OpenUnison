/*
Copyright 2015, 2016 Tremolo Security, Inc.

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


package com.tremolosecurity.proxy.logout;

import java.util.ArrayList;

import javax.servlet.http.HttpServletRequest;

public class LogoutUtil {
	public static final String LOGOUT_HANDLERS = "TREMOLO_LOGOUT_HANDLERS";
	
	public static void addLogoutHandler(HttpServletRequest request,LogoutHandler handler) {
		@SuppressWarnings("unchecked")
		ArrayList<LogoutHandler> handlers = (ArrayList<LogoutHandler>) request.getSession().getAttribute(LOGOUT_HANDLERS);
		if (handlers == null) {
			handlers = new ArrayList<LogoutHandler>();
			request.getSession().setAttribute(LOGOUT_HANDLERS, handlers);
		}
		
		handlers.add(handler);
	}
	
	public static void insertFirstLogoutHandler(HttpServletRequest request,LogoutHandler handler) {
		@SuppressWarnings("unchecked")
		ArrayList<LogoutHandler> handlers = (ArrayList<LogoutHandler>) request.getSession().getAttribute(LOGOUT_HANDLERS);
		if (handlers == null) {
			handlers = new ArrayList<LogoutHandler>();
			request.getSession().setAttribute(LOGOUT_HANDLERS, handlers);
		}
		
		handlers.add(0,handler);
	}
	
	
}
