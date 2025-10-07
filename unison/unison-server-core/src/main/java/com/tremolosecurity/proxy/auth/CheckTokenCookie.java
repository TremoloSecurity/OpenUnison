/*
 * Copyright 2025 Tremolo Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.tremolosecurity.proxy.auth;

import com.google.gson.Gson;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.provisioning.util.EncryptedMessage;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.apache.http.Header;
import org.apache.http.message.BasicHeader;
import org.apache.log4j.Logger;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

public class CheckTokenCookie implements AuthMechanism {
    static Logger logger = Logger.getLogger(CheckTokenCookie.class.getName());
    static Gson gson = new Gson();

    @Override
    public void init(ServletContext ctx, HashMap<String, Attribute> init) {

    }

    @Override
    public String getFinalURL(HttpServletRequest request, HttpServletResponse response) {
        return "";
    }

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response, AuthStep as) throws IOException, ServletException {
        HttpSession session = ((HttpServletRequest) request).getSession();
        UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
        if (holder == null) {
            throw new ServletException("Holder is null");
        }

        RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();

        HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);

        List<Header> corsHeaders = new ArrayList<Header>();
        Attribute cors = authParams.get("cors-headers");


        if (cors != null) {
            for (String value : cors.getValues()) {
                String headerName = value.substring(0, value.indexOf("="));
                String headerValue = value.substring(value.indexOf("=") + 1);
                corsHeaders.add(new BasicHeader(headerName, headerValue));
            }


        }

        String id = (String) request.getAttribute("tremolo.io/oauth2/jwt/id");

        if (id == null) {

            corsHeaders.forEach(header -> response.addHeader(header.getName(), header.getValue()));
            as.setExecuted(true);
            as.setSuccess(false);
            holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
            return;
        }

        String cookieName = authParams.get("tokenCookieName").getValues().get(0);
        Cookie[] cookies = request.getCookies();

        if (cookies == null) {

            corsHeaders.forEach(header -> response.addHeader(header.getName(), header.getValue()));
            as.setExecuted(true);
            as.setSuccess(false);
            holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
            return;
        }

        for (Cookie cookie : cookies) {

            if (cookie.getName().equals(cookieName)) {
                String value = cookie.getValue();
                byte[] json = Base64.getDecoder().decode(value);
                String keyName = authParams.get("keyName").getValues().get(0);
                SecretKey key = GlobalEntries.getGlobalEntries().getConfigManager().getSecretKey(keyName);
                if (key == null) {
                    logger.warn(String.format("Could not load key %s",keyName));
                    corsHeaders.forEach(header -> response.addHeader(header.getName(), header.getValue()));
                    as.setExecuted(true);
                    as.setSuccess(false);
                    holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
                    return;
                }

                try {


                    ByteArrayInputStream bin = new ByteArrayInputStream(json);

                    InflaterInputStream decompressor = new InflaterInputStream(bin, new Inflater(true));
                    //decompressor.setInput(compressedData);

                    // Create an expandable byte array to hold the decompressed data
                    ByteArrayOutputStream bos = new ByteArrayOutputStream(json.length);

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


                    EncryptedMessage em = gson.fromJson(new String(bos.toByteArray()), EncryptedMessage.class);
                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

                    byte[] iv = em.getIv();
                    IvParameterSpec spec = new IvParameterSpec(iv);
                    cipher.init(Cipher.DECRYPT_MODE, key,spec);
                    byte[] decBytes = em.getMsg();
                    String idFromCookie = new String(cipher.doFinal(decBytes));


                    as.setExecuted(true);
                    as.setSuccess(id.equals(idFromCookie));

                    if (!as.isSuccess()) {
                        corsHeaders.forEach(header -> response.addHeader(header.getName(), header.getValue()));
                    }

                    holder.getConfig().getAuthManager().nextAuth(request, response,session,false);


                } catch (Exception e) {
                    logger.error("Could not decrypt key",e);
                    corsHeaders.forEach(header -> response.addHeader(header.getName(), header.getValue()));
                    as.setExecuted(true);
                    as.setSuccess(false);
                    holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
                    return;
                }

            }
        }


        corsHeaders.forEach(header -> response.addHeader(header.getName(), header.getValue()));
        as.setExecuted(true);
        as.setSuccess(false);
        holder.getConfig().getAuthManager().nextAuth(request, response,session,false);


    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response, AuthStep as) throws IOException, ServletException {
        doGet(request,response,as);
    }

    @Override
    public void doPut(HttpServletRequest request, HttpServletResponse response, AuthStep as) throws IOException, ServletException {
        doGet(request,response,as);
    }

    @Override
    public void doHead(HttpServletRequest request, HttpServletResponse response, AuthStep as) throws IOException, ServletException {
        doGet(request,response,as);
    }

    @Override
    public void doOptions(HttpServletRequest request, HttpServletResponse response, AuthStep as) throws IOException, ServletException {
        doGet(request,response,as);
    }

    @Override
    public void doDelete(HttpServletRequest request, HttpServletResponse response, AuthStep as) throws IOException, ServletException {
        doGet(request,response,as);
    }
}
