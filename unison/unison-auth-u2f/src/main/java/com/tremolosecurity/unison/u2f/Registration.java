/*******************************************************************************
 * Copyright 2017 Tremolo Security, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.tremolosecurity.unison.u2f;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.binary.Base64;

import com.google.gson.Gson;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.ProvisioningParams;
import com.tremolosecurity.provisioning.service.util.TremoloUser;
import com.tremolosecurity.provisioning.service.util.WFCall;
import com.tremolosecurity.provisioning.util.EncryptedMessage;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.u2f.util.U2fUtil;
import com.yubico.u2f.U2F;
import com.yubico.u2f.data.DeviceRegistration;
import com.yubico.u2f.data.messages.RegisterRequestData;
import com.yubico.u2f.data.messages.RegisterResponse;

import antlr.collections.List;

public class Registration implements HttpFilter {

	public static final String REGISTRATION_REQUEST = "com.tremolosecurity.unison.u2f.Registration.request";
	private static final String REGISTRATION_URI = "com.tremolosecurity.unison.u2f.Registration.url";
	private static final String REGISTRATION_REQUEST_JSON = "com.tremolosecurity.unison.u2f.Registration.request_json";
	static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(Registration.class.getName());
	static Gson gson = new Gson();
	
	static U2F u2f = new U2F();
	
	String encyrptionKeyName;
	String challengeStoreAttribute;
	String challengeURI;
	String workflowName;
	
	String uidAttributeName;
	String registrationCompleteURI;
	
	@Override
	public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		if (request.getMethod().equalsIgnoreCase("GET")) {
			//TODO switch this off
			
			AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
			ArrayList<DeviceRegistration> devices = U2fUtil.loadUserDevices(userData, challengeStoreAttribute, encyrptionKeyName);
			
			RegisterRequestData rrd = u2f.startRegistration(U2fUtil.getApplicationId(request.getServletRequest()), devices);
			String registerRequestJSON = rrd.getRegisterRequests().get(0).toJson();
			request.getSession().setAttribute(Registration.REGISTRATION_REQUEST_JSON, registerRequestJSON);
			request.getSession().setAttribute(Registration.REGISTRATION_REQUEST, rrd);
			request.setAttribute(REGISTRATION_URI, request.getRequestURL().toString());
			request.getRequestDispatcher(this.challengeURI).forward(request.getServletRequest(), response.getServletResponse());
		} else if (request.getMethod().equalsIgnoreCase("POST")) {
			RegisterRequestData rrd = (RegisterRequestData) request.getSession().getAttribute(Registration.REGISTRATION_REQUEST);
			RegisterResponse rr = RegisterResponse.fromJson(request.getParameter("tokenResponse").getValues().get(0));
			
			DeviceRegistration dr = u2f.finishRegistration(rrd, rr);
			AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
			ArrayList<DeviceRegistration> devices = U2fUtil.loadUserDevices(userData, challengeStoreAttribute, encyrptionKeyName);
			devices.add(dr);
			
			String encrypted = U2fUtil.encode(devices,encyrptionKeyName);
			WFCall wc = new WFCall();
			wc.setName(this.workflowName);
			wc.setUidAttributeName(this.uidAttributeName);
			TremoloUser tu = new TremoloUser();
			tu.setUid(userData.getAttribs().get(this.uidAttributeName).getValues().get(0));
			tu.getAttributes().add(new Attribute(this.uidAttributeName,userData.getAttribs().get(this.uidAttributeName).getValues().get(0)));
			tu.getAttributes().add(new Attribute(this.challengeStoreAttribute,encrypted));
			wc.setUser(tu);
			Map<String,Object> req = new HashMap<String,Object>();
			req.put(ProvisioningParams.UNISON_EXEC_TYPE, ProvisioningParams.UNISON_EXEC_SYNC);
			wc.setRequestParams(req);
			
			GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getWorkFlow(this.workflowName).executeWorkflow(wc);
			
			request.getRequestDispatcher(this.registrationCompleteURI).forward(request.getServletRequest(), response.getServletResponse());
			
		}
			

	}
	
	

	@Override
	public void filterResponseText(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			StringBuffer data) throws Exception {
		// TODO Auto-generated method stub

	}

	@Override
	public void filterResponseBinary(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			byte[] data, int length) throws Exception {
		// TODO Auto-generated method stub

	}

	@Override
	public void initFilter(HttpFilterConfig config) throws Exception {
		this.encyrptionKeyName = loadAttributeValue("encryptionKeyName","Encryption Key",config);
		this.challengeStoreAttribute = loadAttributeValue("attribute","Attribute Name",config);
		this.challengeURI = loadAttributeValue("challengeURI","Challenge URI",config);
		this.workflowName = loadAttributeValue("workflowName","Workflow Name",config);
		
		this.uidAttributeName = loadAttributeValue("uidAttributeName","UID Attribute Name",config );
		this.registrationCompleteURI = loadAttributeValue("completedURI","Registration Completed URI",config );
		

	}
	
	private String loadAttributeValue(String name,String label,HttpFilterConfig config) throws Exception {
		Attribute attr = config.getAttribute(name);
		if (attr == null) {
			throw new Exception(label + " not found");
		}
		
		String val = attr.getValues().get(0);
		logger.info(label + ": '" + val + "'");
		
		return val;
	}

}
