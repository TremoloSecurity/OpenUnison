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


package com.tremolosecurity.proxy.auth;

import java.io.IOException;
import java.util.HashMap;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.proxy.ServletMethods;
import com.tremolosecurity.proxy.auth.util.AuthStep;

public interface AuthMechanism  {

	
	public void init(ServletContext ctx, HashMap<String,Attribute> init);
	
	public String getFinalURL(HttpServletRequest request,HttpServletResponse response);
	
	public void doGet(HttpServletRequest request,HttpServletResponse response,AuthStep as) throws IOException,ServletException;
	public void doPost(HttpServletRequest request,HttpServletResponse response,AuthStep as) throws IOException,ServletException;
	public void doPut(HttpServletRequest request,HttpServletResponse response,AuthStep as) throws IOException,ServletException;
	public void doHead(HttpServletRequest request,HttpServletResponse response,AuthStep as) throws IOException,ServletException;
	public void doOptions(HttpServletRequest request,HttpServletResponse response,AuthStep as) throws IOException,ServletException;
	public void doDelete(HttpServletRequest request,HttpServletResponse response,AuthStep as) throws IOException,ServletException;

}
