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


package com.tremolosecurity.proxy.auth.secret;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.ArrayList;
import java.util.HashMap;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.provisioning.util.GenPasswd;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.AuthMechanism;
import com.tremolosecurity.proxy.auth.AuthSys;
import com.tremolosecurity.proxy.auth.RequestHolder;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.myvd.MyVDConnection;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;


public class SecretQuestionAuth implements AuthMechanism {

	ArrayList<String> questionList;
	private ConfigManager cfgMgr;
	
	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		HttpSession session = ((HttpServletRequest) request).getSession();
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
		
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		
		RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
		
		String urlChain = holder.getUrl().getAuthChain();
		AuthChainType act = holder.getConfig().getAuthChains().get(reqHolder.getAuthChainName());
		
		
		AuthMechType amt = act.getAuthMech().get(as.getId());
		
		
		
		
		
		AuthInfo user = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
		
		if (user == null) {
			throw new ServletException("No user present");
		}
		
		String questionAttrName = authParams.get("questionAttr").getValues().get(0);
		String loginForm = authParams.get("loginForm").getValues().get(0);
		
		Attribute qAttr = user.getAttribs().get(questionAttrName);
		if (qAttr == null) {
			throw new ServletException("User " + user.getUserDN() + " does not have secret questions");
		}
		
		byte[] encBytes = org.bouncycastle.util.encoders.Base64.decode(qAttr.getValues().get(0));
		
		
		
		ByteArrayInputStream bais = new ByteArrayInputStream(encBytes);
		ObjectInputStream ois = new ObjectInputStream(bais);
		
		ArrayList<SecretQuestion> questions = null;
		
		try {
			questions = (ArrayList<SecretQuestion>) ois.readObject();
		} catch (ClassNotFoundException e) {
			throw new ServletException("Could not load questions",e);
		}
		
		
		request.getSession(true).setAttribute("TREMOLO_SECRET_ANSWERS", questions);
		request.setAttribute("TREMOLO_SECRET_QUESTIONS", questions);
		request.setAttribute("TREMOLO_SECRET_QUESTION_LIST", this.questionList);
		
		request.getRequestDispatcher(loginForm).forward(request, response);

	}

	@Override
	public void doPost(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		MyVDConnection myvd = cfgMgr.getMyVD();
		//HttpSession session = (HttpSession) req.getAttribute(ConfigFilter.AUTOIDM_SESSION);//((HttpServletRequest) req).getSession(); //SharedSession.getSharedSession().getSession(req.getSession().getId());
		HttpSession session = ((HttpServletRequest) request).getSession(); //SharedSession.getSharedSession().getSession(req.getSession().getId());
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		
		RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
		
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
		
		String alg = authParams.get("alg").getValues().get(0);
		String salt = authParams.get("salt").getValues().get(0);
		
		String urlChain = holder.getUrl().getAuthChain();
		AuthChainType act = holder.getConfig().getAuthChains().get(reqHolder.getAuthChainName());
		
		
		
		
		AuthMechType amt = act.getAuthMech().get(as.getId());
		
		ArrayList<SecretQuestion> questions = (ArrayList<SecretQuestion>) request.getSession(true).getAttribute("TREMOLO_SECRET_ANSWERS");
		
		if (questions == null) {
			this.doGet(request, response, as);
			return;
		}
		
		int i=0;
		StringBuffer b = new StringBuffer();
		for (SecretQuestion sq : questions) {
			b.setLength(0);
			b.append("answer").append(i);
			String answer = request.getParameter(b.toString());
			if (! sq.checkAnswer(alg, answer, salt)) {
				if (amt.getRequired().equals("required")) {
					as.setSuccess(false);
					
					holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
					return;
				} 
			}
			i++;
		}
		
		as.setSuccess(true);
		
		holder.getConfig().getAuthManager().nextAuth(request, response,session,false);

	}

	@Override
	public void doPut(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		// TODO Auto-generated method stub

	}

	@Override
	public void doHead(HttpServletRequest request, HttpServletResponse response,AuthStep as)
			throws IOException, ServletException {
		// TODO Auto-generated method stub

	}

	@Override
	public void doOptions(HttpServletRequest request,
			HttpServletResponse response,AuthStep as) throws IOException, ServletException {
		// TODO Auto-generated method stub

	}

	@Override
	public void doDelete(HttpServletRequest request,
			HttpServletResponse response,AuthStep as) throws IOException, ServletException {
		// TODO Auto-generated method stub

	}

	@Override
	public void init(ServletContext ctx, HashMap<String, Attribute> init) {
		this.questionList = new ArrayList<String>();
		if (init.get("questionList") != null) {
			this.questionList.addAll(init.get("questionList").getValues());
		}
		this.cfgMgr = (ConfigManager) ctx.getAttribute(ProxyConstants.TREMOLO_CONFIG);

	}

	@Override
	public String getFinalURL(HttpServletRequest request,
			HttpServletResponse response) {
		// TODO Auto-generated method stub
		return null;
	}

}
