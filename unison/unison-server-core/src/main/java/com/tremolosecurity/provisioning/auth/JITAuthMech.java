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


package com.tremolosecurity.provisioning.auth;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.util.*;

import com.novell.ldap.util.ByteArray;
import com.tremolosecurity.provisioning.core.ProvisioningParams;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.apache.logging.log4j.Logger;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.proxy.ProxyUtil;
import com.tremolosecurity.proxy.TremoloHttpSession;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.AuthMechanism;
import com.tremolosecurity.proxy.auth.AuthSys;
import com.tremolosecurity.proxy.auth.RequestHolder;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.auth.util.AuthUtil;
import com.tremolosecurity.proxy.myvd.MyVDConnection;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.proxy.util.ProxyTools;
import com.tremolosecurity.saml.*;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;


public class JITAuthMech implements AuthMechanism {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(JITAuthMech.class);
	
	
	
	ConfigManager cfgMgr;
	
	@Override
	public void doPost(HttpServletRequest req, HttpServletResponse resp,AuthStep as)
			throws ServletException, IOException {
		
		this.doGet(req, resp, as);
		
	}

	@Override
	public void doGet(HttpServletRequest req, HttpServletResponse resp,AuthStep as)
			throws ServletException, IOException {
		
		
		
		//HttpSession session = (HttpSession) req.getAttribute(ConfigFilter.AUTOIDM_SESSION);//((HttpServletRequest) req).getSession(); //SharedSession.getSharedSession().getSession(req.getSession().getId());
		HttpSession session = ((HttpServletRequest) req).getSession(); //SharedSession.getSharedSession().getSession(req.getSession().getId());
		UrlHolder holder = (UrlHolder) req.getAttribute(ProxyConstants.AUTOIDM_CFG);
		
		RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
		
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
		String nameAttr = null;
		if (authParams.get("nameAttr") == null) {
			throw new ServletException("No name attribute");
		}
		
		nameAttr = authParams.get("nameAttr").getValues().get(0);
		
		String workflowName;
		if (authParams.get("workflowName") == null) {
			throw new ServletException("No workflow specified");
		}
		
		workflowName = authParams.get("workflowName").getValues().get(0);
		
		
		long gracePeriod = 0;
		String reloadBaseDN = null;
		String lastUpdatedAttributeName = "";

		if (authParams.get("gracePeriod") != null) {
			gracePeriod = Long.parseLong(authParams.get("gracePeriod").getValues().get(0)) * 1000;
			reloadBaseDN = authParams.get("reloadBaseDN").getValues().get(0);
			lastUpdatedAttributeName = authParams.get("lastUpdatedAttributeName").getValues().get(0);
		}

		
		
		
		
		
		
		String urlChain = holder.getUrl().getAuthChain();
		AuthChainType act = holder.getConfig().getAuthChains().get(reqHolder.getAuthChainName());
		
		
		
		
		AuthMechType amt = act.getAuthMech().get(as.getId());
		
		AuthInfo authInfo = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();

		String sessionDN = (String) session.getAttribute(ProxyConstants.TREMOLO_SESSION_DN);

		boolean runJit = true;

		if (gracePeriod > 0) {
			Attribute lastAccessed = authInfo.getAttribs().get(lastUpdatedAttributeName);
			if (lastAccessed != null) {
				String lastAccessedValue = lastAccessed.getValues().get(0);
				if (lastAccessedValue != null && ! lastAccessedValue.isBlank()) {
					long lastAccessedTime = 0;
					try {
						lastAccessedTime = Long.parseLong(lastAccessedValue);
					} catch (NumberFormatException e) {

					}

					if ((System.currentTimeMillis() - gracePeriod) < lastAccessedTime) {
						runJit = false;
					}
				}
			} else {
				logger.warn(String.format("No last accessed attribute %s for user %s", lastUpdatedAttributeName, sessionDN));
			}
		}


		try {
			if (runJit) {
				com.tremolosecurity.provisioning.core.Workflow wf = holder.getConfig().getProvisioningEngine().getWorkFlow(workflowName);
				Map<String, Object> request = wf.getRequest();
				boolean reqNull = false;

				if (request == null) {
					request = new HashMap<>();
					reqNull = true;
				}

				if (sessionDN != null) {
					request.put(ProxyConstants.TREMOLO_SESSION_DN, sessionDN);
				}

				if (reqNull) {
					wf.executeWorkflow(authInfo, nameAttr, request);
				} else {
					wf.executeWorkflow(authInfo, nameAttr);
				}
			} else {


				if (reloadBaseDN == null) {
					if (act != null) {
						reloadBaseDN = act.getRoot();
					}
					if (reloadBaseDN == null) {
						reloadBaseDN = this.cfgMgr.getCfg().getLdapRoot();
					}
				}

				Attribute userid = authInfo.getAttribs().get(nameAttr);
				if (userid == null) {
					throw new ServletException(String.format("No %s attribute found for user %s", nameAttr, sessionDN));
				}

				LDAPSearchResults res = this.cfgMgr.getMyVD().search(reloadBaseDN, 2, equal(nameAttr,userid.getValues().get(0)).toString(), new ArrayList<String>());
				authInfo.getAttribs().clear();
				if (res.hasMore()) {

					LDAPEntry entry = res.next();
					while (res.hasMore()) res.next();
					authInfo.setUserDN(entry.getDN(), null);

					Iterator<LDAPAttribute> it = entry.getAttributeSet().iterator();

					while (it.hasNext()) {
						LDAPAttribute attrib = it.next();
						Attribute attr = new Attribute(attrib.getName());

						LinkedList<ByteArray> vals = attrib.getAllValues();
						for (ByteArray val : vals) {
							attr.getValues().add(new String(val.getValue()));
						}
						authInfo.getAttribs().put(attr.getName(), attr);
					}
				}
			}

			as.setSuccess(true);
		} catch ( LDAPException | ProvisioningException e) {
			StringBuffer b = new StringBuffer();
			b.append("Could not execute workflow '").append(workflowName).append("' on '").append(authInfo.getUserDN()).append("'");
			
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			PrintWriter err = new PrintWriter(new OutputStreamWriter(baos));
			
			e.printStackTrace(err);
			Throwable t = e.getCause();
			while (t != null) {
				t.printStackTrace(err);
				t = t.getCause();
			}
			
			logger.error(b.toString() + new String(baos.toByteArray()));
			as.setSuccess(false);
			logger.warn("Could not execute workflow " + workflowName + " for " + authInfo.getUserDN(),e);
		}
		
		
		
		holder.getConfig().getAuthManager().nextAuth(req, resp,session,false);
		
		
		
	}

	@Override
	public void doPut(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);
		
	}

	@Override
	public void doHead(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);
		
	}

	@Override
	public void doOptions(HttpServletRequest request,
			HttpServletResponse response,AuthStep as) throws IOException, ServletException {
		this.doGet(request, response, as);
		
	}

	@Override
	public void doDelete(HttpServletRequest request,
			HttpServletResponse response,AuthStep as) throws IOException, ServletException {
		this.doGet(request, response, as);
		
	}

	@Override
	public void init(ServletContext ctx, HashMap<String, Attribute> init) {
		this.cfgMgr = (ConfigManager) ctx.getAttribute(ProxyConstants.TREMOLO_CONFIG);
		
	}

	@Override
	public String getFinalURL(HttpServletRequest request,
			HttpServletResponse response) {
		
		return null;
	}

}
