/*
Copyright 2015, 2018 Tremolo Security, Inc.

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


package com.tremolosecurity.config.util;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.StringTokenizer;
import java.util.regex.Pattern;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.config.xml.ApplicationType;
import com.tremolosecurity.config.xml.AzRuleType;
import com.tremolosecurity.config.xml.FilterConfigType;
import com.tremolosecurity.config.xml.UrlType;
import com.tremolosecurity.proxy.az.AzRule;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;

/**
 * Represents a single URL in Unison
 *
 */
public class UrlHolder {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(UrlHolder.class);
	ConfigManager cfg;
	ApplicationType app;
	UrlType url;
	int weight;
	Pattern pattern;
	boolean overrideHost;
	boolean overrideReferer;
	
	int port;
	
	boolean inited;
	boolean isSSL;
	
	String lowerCasePath;
	
	ArrayList<UrlComp> proxyToURL;
	
	ArrayList<HttpFilter> filterChain;
	
	ArrayList<AzRule> azRules;
	
	/**
	 * Returns the regex pattern used to identify this URL
	 * @return
	 */
	public Pattern getPattern() {
		return pattern;
	}

	/**
	 * Returns the weight of the URL.  When two UrlHolders match a URL the higher weight UrlHolder wins
	 * @return
	 */
	public int getWeight() {
		return weight;
	}
	
	/**
	 * Port of the URL this UrlHolder is tied to
	 * @return
	 */
	public int getPort() {
		return this.port;
	}
	
	/**
	 * Returns true if this URL is secured using SSL/TLS
	 * @return
	 */
	public boolean isSSL() {
		return this.isSSL;
	}

	/**
	 * UrlHolder constructor
	 * @param app
	 * @param url
	 * @param config
	 * @throws Exception
	 */
	public UrlHolder(ApplicationType app,UrlType url,ConfigManager config) throws Exception {
		this.app = app;
		this.url = url;
		this.cfg = config;
		
		parseProxyURL(url);
		if (url.getProxyTo() != null) {
			String val;
			int indexOfDollarSign = url.getProxyTo().indexOf('$');
			if (indexOfDollarSign >= 0) {
				val = url.getProxyTo().substring(0,indexOfDollarSign);
			} else {
				val = url.getProxyTo();
			}

			
			
			URL tmp = null;
			
			try {
				tmp= new URL(val);
			} catch (MalformedURLException e) {
				logger.warn("Could not process url : '" + val + "'",e);
				tmp = new URL("http://dne");
			}
			this.isSSL = tmp.getProtocol().equalsIgnoreCase("https");
			
			this.port = tmp.getPort();
			if (port == 0 || port == -1) {
				if (isSSL) {
					port = 443;
				} else {
					port = 80;
				}
			}
		} else {
			this.isSSL = false;
			this.port = 0;
		}
		
		this.inited = false;
		
		this.azRules = new ArrayList<AzRule>();
		if (url.getAzRules() != null) { 
			for (AzRuleType art : url.getAzRules().getRule()) {
				azRules.add(new AzRule(art.getScope(),art.getConstraint(),art.getClassName(),config,null));
			}
		}
		
		this.overrideHost = url.isOverrideHost();
		this.overrideReferer = url.isOverrideReferer();
		
	}

	/**
	 * Initializes a URL from the XML configuration.  Multiple calls perform no actions.
	 * @throws Exception
	 */
	public void init() throws Exception {
		if (! this.inited) {
			this.lowerCasePath = url.getUri().toLowerCase();
			this.filterChain = new ArrayList<HttpFilter>();
			List<FilterConfigType> filterCfgs= url.getFilterChain().getFilter();
			
			if (filterCfgs != null) {
				Iterator<FilterConfigType> it = filterCfgs.iterator();
				while (it.hasNext()) {
					FilterConfigType cfg = it.next();
					HttpFilter filter = (HttpFilter) Class.forName(cfg.getClazz()).newInstance();
					this.filterChain.add(filter);
					filter.initFilter(new HttpFilterConfig(cfg,this.cfg,app,url));
				}
			}
			this.inited = true;
		}
	}
	
	private void parseProxyURL(UrlType url) {
		if (this.url.isRegex()) {
			this.weight = 100;
			pattern = Pattern.compile(url.getUri());
			
		} else {
			StringTokenizer toker = new StringTokenizer(url.getUri(),"/",false);
			while (toker.hasMoreTokens()) {
				toker.nextToken();
				this.weight++;
			}
			
			if (this.url.getUri().endsWith("/")) {
				this.weight++;
			}
		}
		
		this.proxyToURL = new ArrayList<UrlComp>();
		
		String proxyTo = url.getProxyTo();
		
		int last  = 0;
		if (proxyTo != null) {
			int index = proxyTo.indexOf('$');
			while (index != -1) {
				int begin = index + 1;
				int end = proxyTo.indexOf('}',begin + 1);
				UrlComp comp = new UrlComp();
				comp.param = false;
				comp.val = proxyTo.substring(last,index);
				this.proxyToURL.add(comp);
				
				comp = new UrlComp();
				comp.param = true;
				comp.val = proxyTo.substring(begin + 1,end);
				this.proxyToURL.add(comp);
				last = end + 1;
				index = proxyTo.indexOf('$',last);
			}
			
			UrlComp comp = new UrlComp();
			comp.param = false;
			comp.val = proxyTo.substring(last);
			this.proxyToURL.add(comp);
		}
	}

	/**
	 * Returns application xml configuration
	 * @return
	 */
	public ApplicationType getApp() {
		return app;
	}

	/**
	 * Returns the Url configuration
	 * @return
	 */
	public UrlType getUrl() {
		return url;
	}
	
	
	/**
	 * Builds a new URL, if needed, from the components of the current URL and a proxy host 
	 * @param params
	 * @return
	 */
	public String getProxyURL(HashMap<String,String> params) {
		StringBuffer ret = new StringBuffer();
		
		Iterator<UrlComp> it = this.proxyToURL.iterator();
		while (it.hasNext()) {
			UrlComp comp = it.next();
			if (comp.param) {
				ret.append(params.get(comp.val));
			} else {
				ret.append(comp.val);
			}
		}
		
		return ret.toString();
	}
	
	/**
	 * Returns the URL's filters
	 * @return
	 */
	public List<HttpFilter> getFilterChain() {
		return this.filterChain;
	}
	
	/**
	 * Returns the configuration system for this URL
	 * @return
	 */
	public ConfigManager getConfig() {
		return this.cfg;
	}
	
	/**
	 * Returns the list of authorization rules for this URL
	 * @return
	 */
	public List<AzRule> getAzRules() {
		return this.azRules;
	}

	public boolean isOverrideHost() {
		return this.overrideHost;
	}
	
	public boolean isOverrideReferer() {
		return this.overrideReferer;
	}

	/**
	 * @return the lowerCasePath
	 */
	public String getLowerCasePath() {
		return lowerCasePath;
	}
	
}

/**
 * Utility Class
 *
 */
class UrlComp {
	boolean param;
	String val;
}