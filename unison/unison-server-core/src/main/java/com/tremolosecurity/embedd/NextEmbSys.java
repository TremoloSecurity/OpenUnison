/*
Copyright 2015, 2017 Tremolo Security, Inc.

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


package com.tremolosecurity.embedd;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.config.util.ConfigManager;

import com.tremolosecurity.proxy.ConfigSys;
import com.tremolosecurity.proxy.ConfigSys;
import com.tremolosecurity.proxy.ProxyRequest;
import com.tremolosecurity.proxy.ProxySys;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthFilter;
import com.tremolosecurity.proxy.auth.AuthMgrSys;
import com.tremolosecurity.proxy.auth.AuthSys;
import com.tremolosecurity.proxy.auth.AzSys;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.az.AzFilter;
import com.tremolosecurity.proxy.util.NextSys;
import com.tremolosecurity.proxy.util.ProxyConstants;

public class NextEmbSys implements NextSys {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(NextEmbSys.class);

	
	ConfigSys cfgSys;
	AuthSys auSys;
	AzSys azSys;
	AuthMgrSys authMgrSys;
	EmbForward fwd;
	ProxySys proxy;
	
	public enum SysState {
		Config,
		Auth,
		Az,
		AuthMgr,
		Fwd,
		Skip
	};
	
	SysState state;
	private FilterChain chain;
	private boolean passOn;
	private static boolean isUnison;
	
	static {
		try {
			isUnison = true;
		} catch (Exception e) {
		
		}
	}
	
	public ConfigSys getConfigSys() {
		return this.cfgSys;
	}
	
	@Override
	public void nextSys(HttpServletRequest request, HttpServletResponse response)
			throws IOException, ServletException {
		
		ConfigManager cfg = this.cfgSys.getConfigManager();
		
		switch (this.state) {
			case Config : this.state = SysState.Auth; 
						  cfgSys.doConfig(request, response, this); 
						  break;
						  
			case Auth : 
				
						if (request.getRequestURI().startsWith(cfg.getAuthFormsPath()) /*|| request.getRequestURI().startsWith(cfg.getAuthIdPPath() ) /*|| request.getRequestURI().startsWith("/auth/idp/")*/ ) {
							//processesing the authentications, skip auth and az processing
							this.state = SysState.Skip; 
							//System.out.println(request.getSession());
							chain.doFilter(request, response);
						} else {
							this.state = SysState.Az; 
							auSys.doAuth(request, response, this);
						}
						
						break;
						
			case Az : this.state = SysState.AuthMgr; 
					  azSys.doAz(request, response, this);
					  break;
			case AuthMgr:
					this.state = SysState.Fwd;
					
					
					AuthController actl = (AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL);
					
					if (actl != null) {
						AuthStep curStep = actl.getCurrentStep();
						
						if (curStep != null) {
							curStep.setExecuted(true);
							curStep.setSuccess(false);
						}
						authMgrSys.doAuthMgr(request, response, this,curStep);
					} else {
						authMgrSys.doAuthMgr(request, response, this,null);
					}
					
					break;
			case Fwd :
				if (this.passOn) {
					if (request.getRequestURI().startsWith(cfg.getAuthPath()) || proxy == null) {
						chain.doFilter(request, response); 
					} else {
						
						if (((ProxyRequest)request).isPush()) {
							proxy.doPush(request, response);
						} else {
							proxy.doURI(request, response);
						}
						/*
						if (request.getMethod().equalsIgnoreCase("get")) {
							proxy.doGet(request, response);
						} else if (request.getMethod().equalsIgnoreCase("post")) {
							proxy.doPost(request, response);
						} else if (request.getMethod().equalsIgnoreCase("options")) {
							proxy.doOptions(request, response);
						} else if (request.getMethod().equalsIgnoreCase("delete")) {
							proxy.doDelete(request, response);
						} else if (request.getMethod().equalsIgnoreCase("put")) {
							proxy.doPut(request, response);
						} else {
							throw new ServletException("Method not supported");
						}*/
					}
				} else {
					((ProxyRequest) request).copyQSParamsToFormParams();
					fwd.doEmbResults(request, response, chain, this);
				}
				
				break;
				
			default:
		}

	}

	public NextEmbSys(ServletContext ctx,FilterChain chain,boolean passOn) throws ServletException {
		
		this.state = SysState.Config;
		this.cfgSys = new ConfigSys((ConfigManager) ctx.getAttribute(ProxyConstants.TREMOLO_CONFIG),true,ctx);
		
		this.auSys = new AuthSys();
		this.azSys = new AzSys();
		this.fwd = new EmbForward();
		if (isUnison) {
			this.proxy = new ProxySys();
		}
		this.authMgrSys = new AuthMgrSys(ctx);
		this.chain = chain;
		this.passOn = passOn;
		
	}
}
