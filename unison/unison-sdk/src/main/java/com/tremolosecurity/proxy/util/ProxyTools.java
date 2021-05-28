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


package com.tremolosecurity.proxy.util;

import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Iterator;

import javax.servlet.http.HttpServletRequest;

import org.apache.logging.log4j.Logger;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.CookieConfigType;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.myvd.MyVDConnection;
import com.tremolosecurity.saml.Attribute;

public class ProxyTools {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(ProxyTools.class);
	
	static ProxyTools instance;
	BigInteger negone;
	
	public ProxyTools() {
		this.negone = BigInteger.valueOf(-1);
	}
	
	public static ProxyTools getInstance() {
		if (instance == null) {
			instance = new ProxyTools();
		}
		
		return instance;
	}
	
	public String getCookieDomain(CookieConfigType cfg,HttpServletRequest request) {
		
		
		//no cookie config, assume host cookie
		if (cfg == null) {
			return null;//request.getServerName();
		}
		
		//if (cfg.getScope().equals(negone)) {
			
			if (cfg.getDomain().equalsIgnoreCase("*") || cfg.getDomain().equalsIgnoreCase(request.getServerName())) {
				return null;//request.getServerName();
			} else {
				return cfg.getDomain();
			}
		//}
		
		//TODO add cookie scope work
		
		//return "";
	}
	
	public String getFqdnUrl(String url,HttpServletRequest req) {
		
		
		if (url.startsWith("http")) {
			return url;
			//return this.getHttpsUrl(url, req);
		} else {
			
			StringBuffer sb = new StringBuffer();
			String fwdProto = req.getHeader("X-Forwarded-Proto");
			
			if (fwdProto == null) {
				fwdProto = req.getHeader("x-forwarded-proto");
			}
			
			
			
			if (req.isSecure() || (fwdProto != null && fwdProto.startsWith("https"))) {
				sb.append("https://");
			} else {
				sb.append("http://");
			}
			
			
			
			sb.append(req.getServerName());
			
			
			String fwdPort = req.getHeader("X-Forwarded-Port");
			
			if (fwdPort == null) {
				
				fwdPort = req.getHeader("x-forwarded-port");
			}
			
			int serverPort = req.getServerPort();
			if (fwdPort != null) {
				try {
					serverPort = Integer.parseInt(fwdPort);
				} catch (NumberFormatException e) {
					logger.warn(new StringBuilder().append("Invalid port '").append(fwdPort).append("'"));
				}
			}
			
			if (serverPort != 80 && serverPort != 443 && serverPort != -1) {
				sb.append(':').append(serverPort);
			}
			
			sb.append(url);
			
			url = sb.toString();
		}
		
		return url;
	}
	
	public String getHttpsUrl(String url,HttpServletRequest req) {
		
		URL parsedURL = null;
		try {
			parsedURL = new URL(url);
		} catch (MalformedURLException e) {
			logger.warn("Could not parse " + url,e);
		}
		
		
		StringBuffer sb = new StringBuffer();
		String fwdProto = req.getHeader("X-Forwarded-Proto");
		
		if (fwdProto == null) {
			fwdProto = req.getHeader("x-forwarded-proto");
		}
		
		
		
		if (req.isSecure() || (fwdProto != null && fwdProto.startsWith("https"))) {
			sb.append("https://");
		} else {
			sb.append("http://");
		}
		
		
		
		sb.append(parsedURL.getHost());
		
		
		
		
		
		if (parsedURL.getPort() != 80 && parsedURL.getPort() != 443 && parsedURL.getPort() != -1) {
			sb.append(':').append(parsedURL.getPort());
		}
		
		sb.append(parsedURL.getPath());
		
		if (parsedURL.getQuery() != null) {
			sb.append('?').append(parsedURL.getQuery());
		}
		
		
		
		url = sb.toString();
		
		
		return url;
	}
	
	public StringBuffer getGETUrl(HttpFilterRequest req, UrlHolder holder,
			HashMap<String, String> uriParams) {
		StringBuffer proxyToURL = new StringBuffer();
		
		proxyToURL.append(holder.getProxyURL(uriParams));
		
		return proxyToURL;
	}
	
	/*public  String elementToString(Node n) {

	    String name = n.getNodeName();

	    short type = n.getNodeType();

	    if (Node.CDATA_SECTION_NODE == type) {
	      return "<![CDATA[" + n.getNodeValue() + "]]&gt;";
	    }

	    if (name.startsWith("#")) {
	      return "";
	    }

	    StringBuffer sb = new StringBuffer();
	    sb.append('<').append(name);

	    NamedNodeMap attrs = n.getAttributes();
	    if (attrs != null) {
	      for (int i = 0; i < attrs.getLength(); i++) {
	        Node attr = attrs.item(i);
	        sb.append(' ').append(attr.getNodeName()).append("=\"").append(attr.getNodeValue()).append(
	            "\"");
	      }
	    }

	    String textContent = null;
	    NodeList children = n.getChildNodes();

	    if (children.getLength() == 0) {
	      if ((textContent = XMLUtil.getTextContent(n)) != null && !"".equals(textContent)) {
	        sb.append(textContent).append("</").append(name).append('>');
	        ;
	      } else {
	        sb.append("/>").append('\n');
	      }
	    } else {
	      sb.append('>').append('\n');
	      boolean hasValidChildren = false;
	      for (int i = 0; i < children.getLength(); i++) {
	        String childToString = elementToString(children.item(i));
	        if (!"".equals(childToString)) {
	          sb.append(childToString);
	          hasValidChildren = true;
	        }
	      }

	      if (!hasValidChildren && ((textContent = XMLUtil.getTextContent(n)) != null)) {
	        sb.append(textContent);
	      }

	      sb.append("</").append(name).append('>');
	    }

	    return sb.toString();
	  }*/
}
