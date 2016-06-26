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


package com.tremolosecurity.log;

import javax.servlet.http.HttpServletRequest;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.config.xml.ApplicationType;
import com.tremolosecurity.config.xml.ApplicationsType;
import com.tremolosecurity.openunison.OpenUnisonConstants;

import com.tremolosecurity.proxy.auth.AuthInfo;

public class AccessLog {
	
	public enum AccessEvent {
		AuSuccess,
		AuFail,
		AzSuccess,
		AzFail,
		NotFound
	}
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(AccessLog.class.getName());
	
	public static void log(AccessEvent event,ApplicationType app,HttpServletRequest request,AuthInfo user,String msg) {
		String strevent = "";
		String struser = "cn=none";
		
		if (user != null) {
			struser = user.getUserDN();
		}
		
		
		switch (event) {
			case AuSuccess : strevent = "AuSuccess"; break;
			case AzSuccess : strevent = "AzSuccess"; break;
			case AuFail : strevent = "AuFail"; break;
			case AzFail : strevent = "AzFail"; break;
			case NotFound : strevent = "NotFound"; break;
		}
		
		
		
		StringBuffer logLine = new StringBuffer();
		logLine.append('[').append(strevent).append("] - ");
		if (event == AccessEvent.NotFound) {
			logLine.append("UNKNOWN").append(" - ");
		} else {
			logLine.append(app.getName()).append(" - ");	
		}
		
		logLine.append(request.getRequestURL()).append(" - ");
		logLine.append(struser).append(" - ");
		logLine.append(msg);
		logLine.append(" [").append(request.getRemoteAddr()).append("] - [").append(request.getSession().getAttribute(OpenUnisonConstants.TREMOLO_SESSION_ID)).append("]");
		
		logger.info(logLine.toString());
		
		
	}
}
