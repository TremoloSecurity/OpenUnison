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


package com.tremolosecurity.proxy.auth.sys;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.RequestHolder;
import com.tremolosecurity.proxy.util.NextSys;

public interface AuthManager {

	public static final String NEXT_SYS = "TREMOLO_AUTH_NEXT_SYS";

	public abstract boolean nextAuth(HttpServletRequest req,
			HttpServletResponse resp, HttpSession session, boolean jsRedirect)
			throws ServletException, IOException;

	public abstract boolean nextAuth(HttpServletRequest req,
			HttpServletResponse resp, HttpSession session, boolean jsRedirect,
			NextSys next) throws ServletException, IOException;

	public abstract boolean execAuth(HttpServletRequest req,
			HttpServletResponse resp, HttpSession session, boolean jsRedirect,
			UrlHolder holder, AuthChainType act, String finalURL)
			throws IOException, ServletException;

	public abstract boolean execAuth(HttpServletRequest req,
			HttpServletResponse resp, HttpSession session, boolean jsRedirect,
			UrlHolder holder, AuthChainType act, String finalURL, NextSys next)
			throws IOException, ServletException;

	public abstract boolean finishSuccessfulLogin(HttpServletRequest req,
			HttpServletResponse resp, UrlHolder holder, AuthChainType act,
			RequestHolder reqHolder, AuthController actl, NextSys next)
			throws IOException, ServletException;

	public abstract void loadAmtParams(HttpSession session, AuthMechType amt);

	public abstract StringBuffer getGetRedirectURL(RequestHolder reqHolder);

}