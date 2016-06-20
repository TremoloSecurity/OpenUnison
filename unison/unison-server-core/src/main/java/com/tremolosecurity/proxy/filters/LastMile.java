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


package com.tremolosecurity.proxy.filters;

import java.util.HashMap;
import java.util.Iterator;

import javax.crypto.SecretKey;

import org.apache.logging.log4j.Logger;
import org.joda.time.DateTime;

import com.tremolosecurity.config.util.ConfigManager;

import com.tremolosecurity.proxy.TremoloHttpSession;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;



public class LastMile implements HttpFilter {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(LastMile.class);
	
	ConfigManager cfgMgr;
	SecretKey sigKey;
	SecretKey encKey;
	
	int timeScew;
	
	String headerName;
	
	HashMap<String,String> headers;

	private String headerPrefix;
	
	@Override
	public void doFilter(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		
		DateTime notBefore = new DateTime();
		notBefore = notBefore.minusSeconds(timeScew);
		DateTime notAfter = new DateTime();
		notAfter = notAfter.plusSeconds(timeScew);
		
		AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
		
		com.tremolosecurity.lastmile.LastMile lastmile = new com.tremolosecurity.lastmile.LastMile(request.getRequestURI(),notBefore,notAfter,userData.getAuthLevel(),userData.getAuthChain()); 
		
		
		
		Iterator<String> it = this.headers.keySet().iterator();
		while (it.hasNext()) {
			String fromUser = it.next();
			String toApp = this.headers.get(fromUser);
			
			Attribute attrib = userData.getAttribs().get(fromUser);
			request.removeHeader(toApp);
			
			if (logger.isDebugEnabled()) {
				logger.debug("Header to add : " + fromUser);
			}
			
			if (attrib != null) {
				if (logger.isDebugEnabled()) {
					logger.debug("Attribute " + fromUser + "='" + attrib.getValues() + "' for " + userData.getUserDN());
				}
				Attribute toAppAttrib = new Attribute(toApp);
				toAppAttrib.getValues().addAll(attrib.getValues());
				lastmile.getAttributes().add(toAppAttrib);
			} else {
				if (logger.isDebugEnabled()) {
					logger.debug("Attribute " + fromUser + " is not available for " + userData.getUserDN());
				}
			}
		}
		
		String encryptedXML = lastmile.generateLastMileToken(encKey);

		if (this.headerPrefix != null && ! this.headerPrefix.isEmpty()) {
			StringBuffer b = new StringBuffer();
			b.append(this.headerPrefix).append(' ').append(encryptedXML);
			encryptedXML = b.toString();
		}
		
		request.addHeader(new Attribute(this.headerName,encryptedXML));
		
		//response.addHeader(this.headerName, requestKey.getEncrypted());
		
		chain.nextFilter(request, response, chain);
		
		

	}

	@Override
	public void filterResponseText(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain,
			StringBuffer data) throws Exception {
		chain.nextFilterResponseText(request, response, chain, data);

	}

	@Override
	public void filterResponseBinary(HttpFilterRequest request,
			HttpFilterResponse response, HttpFilterChain chain, byte[] data,
			int length) throws Exception {
		chain.nextFilterResponseBinary(request, response, chain, data, length);

	}

	@Override
	public void initFilter(HttpFilterConfig config) throws Exception {
		this.cfgMgr = config.getConfigManager();
		
		
		
		String encKeyAlias = config.getAttribute("encKeyAlias").getValues().get(0);
		
		
		
		this.encKey = cfgMgr.getSecretKey(encKeyAlias);
		
		this.timeScew = Integer.parseInt(config.getAttribute("timeScew").getValues().get(0));
		this.headerName = config.getAttribute("headerName").getValues().get(0);
		
		
		Attribute attr = config.getAttribute("headerPrefix");
		if (attr != null) {
			this.headerPrefix = attr.getValues().get(0);
		} else {
			this.headerPrefix = "";
		}
		 
		
		
		headers = new HashMap<String,String>();
		
		Attribute headerAttribs = config.getAttribute("attribs");
		
		if (headerAttribs != null) {
			Iterator<String> it = headerAttribs.getValues().iterator();
			while (it.hasNext()) {
				String val = it.next();
				String fromUser = val.substring(0,val.indexOf('='));
				String toApp = val.substring(val.indexOf('=') + 1);
				
				if (logger.isDebugEnabled()) {
					logger.debug("INIT : UserAttribute='" + fromUser + "' / ToApplication : '" + toApp + "'");
				}
				
				headers.put(fromUser, toApp);
			}
		}

	}

}
