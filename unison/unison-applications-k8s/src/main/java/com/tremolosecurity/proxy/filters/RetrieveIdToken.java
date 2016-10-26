/*******************************************************************************
 * Copyright 2016 Tremolo Security, Inc.
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
package com.tremolosecurity.proxy.filters;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.servlet.ServletException;

import org.apache.commons.codec.binary.Base64;

import com.google.gson.Gson;
import com.tremolosecurity.idp.providers.OpenIDConnectIdP;
import com.tremolosecurity.idp.providers.oidc.model.OIDCSession;
import com.tremolosecurity.json.Token;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.server.GlobalEntries;



public class RetrieveIdToken implements HttpFilter {

	
	String idpName;
	String trustName;
	
	@Override
	public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		HashMap<String,OpenIDConnectIdP> idps = (HashMap<String, OpenIDConnectIdP>) GlobalEntries.getGlobalEntries().get(OpenIDConnectIdP.UNISON_OPENIDCONNECT_IDPS);
		
		OpenIDConnectIdP idp = idps.get(this.idpName);
		if (idp == null) {
			throw new ServletException("Could not find idp '" + this.idpName + "'");
		}
		Gson gson = new Gson();
		String json = this.inflate(request.getParameter("refresh_token").getValues().get(0));
		Token token = gson.fromJson(json, Token.class);
		
		byte[] iv = org.bouncycastle.util.encoders.Base64.decode(token.getIv());
		
		
	    IvParameterSpec spec =  new IvParameterSpec(iv);
	    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, GlobalEntries.getGlobalEntries().getConfigManager().getSecretKey(idp.getTrusts().get(this.trustName).getCodeLastmileKeyName()),spec);
	    
		byte[] encBytes = org.bouncycastle.util.encoders.Base64.decode(token.getEncryptedRequest());
		String refreshToken = new String(cipher.doFinal(encBytes));
		
		OIDCSession session = idp.getSessionByRefreshToken(refreshToken);
		
		if (session == null) {
			response.setStatus(401);
		} else {
			response.getWriter().print(session.getIdToken());
		}

	}

	@Override
	public void filterResponseText(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			StringBuffer data) throws Exception {
		chain.nextFilterResponseText(request, response, chain, data);

	}

	@Override
	public void filterResponseBinary(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			byte[] data, int length) throws Exception {
		chain.nextFilterResponseBinary(request, response, chain, data, length);

	}

	@Override
	public void initFilter(HttpFilterConfig config) throws Exception {
		this.idpName = config.getAttribute("idpName").getValues().get(0);
		this.trustName = config.getAttribute("trustName").getValues().get(0);

	}
	
	private String inflate(String saml) throws Exception {
		byte[] compressedData = Base64.decodeBase64(saml);
		ByteArrayInputStream bin = new ByteArrayInputStream(compressedData);
		
		InflaterInputStream decompressor  = new InflaterInputStream(bin,new Inflater(true));
		//decompressor.setInput(compressedData);
		
		// Create an expandable byte array to hold the decompressed data
		ByteArrayOutputStream bos = new ByteArrayOutputStream(compressedData.length);
		
		// Decompress the data
		byte[] buf = new byte[1024];
		int len;
		while ((len = decompressor.read(buf)) > 0) {
		    
		        
		        bos.write(buf, 0, len);
		    
		}
		try {
		    bos.close();
		} catch (IOException e) {
		}

		// Get the decompressed data
		byte[] decompressedData = bos.toByteArray();
		
		String decoded = new String(decompressedData);
		
		return decoded;
	}

}
