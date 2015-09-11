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

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletInputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpSession;

import org.apache.commons.collections.iterators.IteratorEnumeration;
import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileItemFactory;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.log4j.Logger;

import com.tremolosecurity.util.NVP;

public class ProxyRequest extends HttpServletRequestWrapper {
	
	static Logger logger = Logger.getLogger(ProxyRequest.class);

	HttpServletRequest request;
	HttpSession session;
	
	ArrayList<NVP> queryString;
	
	
	HashMap<String,ArrayList<String>> reqParams;
	HashMap<String,ArrayList<FileItem>> reqFiles;
	
	ArrayList<String> paramList;
	ArrayList<NVP> orderedList;
	
	boolean isMultiPart;
	boolean isParamsInBody;
	boolean isPush;
	
	public boolean isParamsInBody() {
		return isParamsInBody;
	}

	public ProxyRequest(HttpServletRequest req,HttpSession session) throws Exception {
		super(req);
		this.request = req;
		
		
		this.session = session;
		
		
		this.isMultiPart = ServletFileUpload.isMultipartContent(req);
		
		
		
		this.isParamsInBody = true;
		this.isPush = false;
		this.paramList = new ArrayList<String>();
		
		this.reqParams = new HashMap<String,ArrayList<String>>();
		this.queryString = new ArrayList<NVP>();
		
		if (request.getQueryString() != null && ! request.getQueryString().isEmpty()) {
			StringTokenizer toker = new StringTokenizer(request.getQueryString(),"&");
			while (toker.hasMoreTokens()) {
				String qp = toker.nextToken();
				int index = qp.indexOf('=');
				if (index > 0) {
					String name = qp.substring(0,qp.indexOf('='));
					String val = URLDecoder.decode(qp.substring(qp.indexOf('=') + 1),"UTf-8");
					this.queryString.add(new NVP(name,val));
				}
			}
		}
		
		if (this.isMultiPart) {
			this.isPush = true;
			// Create a factory for disk-based file items
			FileItemFactory factory = new DiskFileItemFactory();

			
			
			// Create a new file upload handler
			ServletFileUpload upload = new ServletFileUpload(factory);
			
			List<FileItem>  items = upload.parseRequest(req);
			
			
			this.reqFiles =  new HashMap<String,ArrayList<FileItem>>();
			
			for (FileItem item : items) {
				//this.paramList.add(item.getName());
				
				if (item.isFormField()) {
					ArrayList<String> vals = this.reqParams.get(item.getFieldName());
					if (vals == null) {
						vals = new ArrayList<String>();
						this.reqParams.put(item.getFieldName(), vals);
					}
					this.paramList.add(item.getFieldName());
					
					vals.add(item.getString());
				} else {
					ArrayList<FileItem> vals = this.reqFiles.get(item.getFieldName());
					if (vals == null) {
						vals = new ArrayList<FileItem>();
						this.reqFiles.put(item.getFieldName(), vals);
					}
					
					vals.add(item);
				}
			}
			
			
			
		} else {
			Enumeration enumer = req.getHeaderNames();
			
			String contentType = null;
			
			while (enumer.hasMoreElements()) {
				String name = (String) enumer.nextElement();
				if (name.equalsIgnoreCase("content-type") || name.equalsIgnoreCase("content-length")) {
					this.isPush = true;
					if (name.equalsIgnoreCase("content-type")) {
						contentType = req.getHeader(name);
					}
				}
				
				
			}
			
			if (this.isPush) {
				if (contentType == null || ! contentType.startsWith("application/x-www-form-urlencoded")) {
					this.isParamsInBody = false;
					ByteArrayOutputStream baos = new ByteArrayOutputStream();
					InputStream in = req.getInputStream();
					int len;
					byte[] buffer = new byte[1024];
					while ((len = in.read(buffer)) > 0) {
						
						baos.write(buffer, 0, len);
					}
					
					req.setAttribute(ProxySys.MSG_BODY, baos.toByteArray());
				} else if (contentType.startsWith("application/x-www-form-urlencoded")) {
					ByteArrayOutputStream baos = new ByteArrayOutputStream();
					InputStream in = req.getInputStream();
					int len;
					byte[] buffer = new byte[1024];
					while ((len = in.read(buffer)) > 0) {
						
						baos.write(buffer, 0, len);
					}
					
					StringTokenizer toker = new StringTokenizer(new String(baos.toByteArray()),"&");
					this.orderedList = new ArrayList<NVP>();
					while (toker.hasMoreTokens()) {
						String token = toker.nextToken();
						int index = token.indexOf('=');
						
						String name = token.substring(0,index);
						
						if (name.indexOf('%') != -1) {
							name = URLDecoder.decode(name,"UTF-8");
						}
						
						String val = "";
						if (index < (token.length() - 1)) {
							val = URLDecoder.decode(token.substring(token.indexOf('=') + 1), "UTF-8");
						} 
						
						this.orderedList.add(new NVP(name,val));
						this.paramList.add(name);
						ArrayList<String> params = this.reqParams.get(name);
						if (params == null) {
							params = new ArrayList<String>();
							this.reqParams.put(name, params);
						}
						
						params.add(val);
					}
				}
			}
		}
		
	}
	
	public ProxyRequest(HttpServletRequest req) throws Exception {
		this(req,null);
	}

	public void setSession(HttpSession session) {
		this.session = session;
	}
	
	@Override
	public String getLocalAddr() {
		return request.getLocalAddr();
	}

	@Override
	public String getLocalName() {
		return request.getLocalName();
	}

	@Override
	public int getLocalPort() {
		return request.getLocalPort();
	}

	@Override
	public int getRemotePort() {
		return request.getRemotePort();
	}
	@Override
	public String getAuthType() {
		return request.getAuthType();
	}

	@Override
	public String getContextPath() {
		return request.getContextPath();
	}

	@Override
	public Cookie[] getCookies() {
		return request.getCookies();
	}

	@Override
	public long getDateHeader(String name) {
		return request.getDateHeader(name);
	}

	@Override
	public String getHeader(String name) {
		return request.getHeader(name);
	}

	@Override
	public Enumeration getHeaderNames() {
		return request.getHeaderNames();
	}

	@Override
	public Enumeration getHeaders(String name) {
		return request.getHeaders(name);
	}

	@Override
	public int getIntHeader(String name) {
		return request.getIntHeader(name);
	}

	@Override
	public String getMethod() {
		return request.getMethod();
	}

	@Override
	public String getPathInfo() {
		return request.getPathInfo();
	}

	@Override
	public String getPathTranslated() {
		return request.getPathTranslated();
	}

	@Override
	public String getQueryString() {
		return request.getQueryString();
	}

	@Override
	public String getRemoteUser() {
		return request.getRemoteUser();
	}

	@Override
	public String getRequestURI() {
		return request.getRequestURI();
	}

	@Override
	public StringBuffer getRequestURL() {
		return request.getRequestURL();
	}

	@Override
	public String getRequestedSessionId() {
		return request.getRequestedSessionId();
		
	}

	@Override
	public String getServletPath() {
		return request.getServletPath();
	}

	@Override
	public HttpSession getSession() {
		return this.session;
	}

	@Override
	public HttpSession getSession(boolean arg0) {
		return this.session;
	}

	@Override
	public Principal getUserPrincipal() {
		return request.getUserPrincipal();
	}

	@Override
	public boolean isRequestedSessionIdFromCookie() {
		return request.isRequestedSessionIdFromCookie();
	}

	@Override
	public boolean isRequestedSessionIdFromURL() {
		return request.isRequestedSessionIdFromURL();
	}

	@Override
	public boolean isRequestedSessionIdFromUrl() {
		return request.isRequestedSessionIdFromUrl();
	}

	@Override
	public boolean isRequestedSessionIdValid() {
		return request.isRequestedSessionIdValid();
	}

	@Override
	public boolean isUserInRole(String role) {
		return request.isUserInRole(role);
	}

	@Override
	public Object getAttribute(String arg0) {
		return request.getAttribute(arg0);
	}

	@Override
	public Enumeration getAttributeNames() {
		return request.getAttributeNames();
	}

	@Override
	public String getCharacterEncoding() {
		return request.getCharacterEncoding();
	}

	@Override
	public int getContentLength() {
		return request.getContentLength();
	}

	@Override
	public String getContentType() {
		return request.getContentType();
	}
	

	@Override
	public ServletInputStream getInputStream() throws IOException {
		return request.getInputStream();
	}

	@Override
	public Locale getLocale() {
		return request.getLocale();
	}

	@Override
	public Enumeration getLocales() {
		return request.getLocales();
	}

	@Override
	public String getParameter(String name) {
		
			ArrayList<String> vals = this.reqParams.get(name);
			if (vals == null || vals.size() == 0) {
				String val = this.getQSParameter(name);
				if (val != null) {
					return val;
				} else {
					return null;
				}
			} else {
				return vals.get(0);
			}
		
	}
	
	public void removeParameter(String name) {
		this.reqParams.remove(name);
		ArrayList<NVP> toRM = new ArrayList<NVP>();
		
		
		for (NVP p : this.orderedList) {
			if (p.getName().equalsIgnoreCase(name)) {
				toRM.add(p);
			}
		}
		
		this.orderedList.removeAll(toRM);
	}

	@Override
	public Map getParameterMap() {
		
			return this.reqParams;
		
	}

	public boolean isMultiPart() {
		return isMultiPart;
	}

	@Override
	public Enumeration getParameterNames() {
		
		HashSet<String> paramListLocal = new HashSet<String>();
		paramListLocal.addAll(this.paramList);
		
		for (NVP p : this.queryString) {
			if (! paramListLocal.contains(p.getName())) {
				paramListLocal.add(p.getName());
			}
		}
		
			return new IteratorEnumeration(paramListLocal.iterator());
		
	}

	@Override
	public String[] getParameterValues(String name) {
		
			ArrayList<String> vals = this.reqParams.get(name);
			if (vals != null) {
				String[] svals = new String[vals.size()];
				vals.toArray(svals);
				return svals;
			} else {
				String val = this.getQSParameter(name);
				if (val != null) {
					return new String[] {val};
				} else {
					return null;
				}
			}
		
	}

	@Override
	public String getProtocol() {
		return request.getProtocol();
	}

	@Override
	public BufferedReader getReader() throws IOException {
		return request.getReader();
	}

	@Override
	public String getRealPath(String arg0) {
		return request.getRealPath(arg0);
	}

	@Override
	public String getRemoteAddr() {
		return request.getRemoteAddr();
	}

	@Override
	public String getRemoteHost() {
		return request.getRemoteHost();
	}

	@Override
	public RequestDispatcher getRequestDispatcher(String arg0) {
		return request.getRequestDispatcher(arg0);
	}

	@Override
	public String getScheme() {
		return request.getScheme();
	}

	@Override
	public String getServerName() {
		return request.getServerName();
	}

	@Override
	public int getServerPort() {
		return request.getServerPort();
	}

	@Override
	public boolean isSecure() {
		return request.isSecure();
	}

	@Override
	public void removeAttribute(String arg0) {
		request.removeAttribute(arg0);

	}

	@Override
	public void setAttribute(String arg0, Object arg1) {
		request.setAttribute(arg0, arg1);

	}

	@Override
	public void setCharacterEncoding(String arg0)
			throws UnsupportedEncodingException {
		request.setCharacterEncoding(arg0);

	}
	
	public HashMap<String,ArrayList<FileItem>> getFiles() {
		return this.reqFiles;
	}

	public HttpServletRequest getServletRequest() {
		return this.request;
	}

	public boolean isPush() {
		return this.isPush;
	}
	
	public ArrayList<NVP> getOrderedParameters() {
		return this.orderedList;
	}
	
	public List<NVP> getQueryStringParams() {
		return this.queryString;
	}

	public void copyQSParamsToFormParams() {
		for (NVP p : this.queryString) {
			ArrayList<String> vals = this.reqParams.get(p.getName());
			if (vals == null) {
				vals = new ArrayList<String>();
				this.paramList.add(p.getName());
				this.reqParams.put(p.getName(), vals);
				
			}
			
			vals.add(p.getValue());
		}
		
	}

	public String getQSParameter(String string) {
		for (NVP p : this.queryString) {
			if (p.getName().equalsIgnoreCase(string)) {
				return p.getValue();
			}
		}
		
		return null;
	}

	public Set<String> getFormParams() {
		return this.reqParams.keySet();
	}

	public List<String> getFormParam(String name) {
		return this.reqParams.get(name);
	}
}