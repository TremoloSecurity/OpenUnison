/*
 * Copyright 2026 Tremolo Security, Inc.
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

package com.tremolosecurity.proxy;

import com.google.gson.Gson;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.ApplicationType;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.json.Token;
import com.tremolosecurity.openunison.OpenUnisonConstants;
import com.tremolosecurity.proxy.auth.AnonAuth;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.proxy.util.ProxyTools;
import jakarta.servlet.ServletContext;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;
import org.joda.time.DateTime;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SessionTools {

    SecureRandom random;
    ServletContext ctx;
    SessionManager sessionManager;

    ConfigManager configManager;

    static Logger logger = Logger.getLogger(SessionTools.class.getName());

    private AuthChainType anonChainType;

    private AnonAuth anonMech;

    public SessionTools(ServletContext ctx,SessionManager sm,ConfigManager cm) {
        this.ctx = ctx;
        this.sessionManager = sm;

        try {
            this.random = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            logger.error("Could not load secure random", e);
        }

        this.configManager = cm;

        for (String key : this.configManager.getAuthChains().keySet()) {
            AuthChainType act = this.configManager.getAuthChains().get(key);
            if (act.getLevel() == 0) {
                this.anonChainType = act;
                String mechName = act.getAuthMech().get(0).getName();
                this.anonMech = (AnonAuth) configManager.getAuthMech(configManager.getAuthMechs()
                        .get(mechName).getUri());
            }
        }

        if (this.anonMech == null) {
            this.anonChainType = new AuthChainType();
            this.anonChainType.setFinishOnRequiredSucess(true);
            this.anonChainType.setLevel(0);
            this.anonChainType.setName("anon");

            this.anonMech = new AnonAuth();

        }
    }

    private HttpSession locateSession(UrlHolder holder,
                                      HttpServletRequest request, ServletContext ctx, String cookieName,
                                      HttpServletResponse resp) throws Exception {
        Cookie sessionCookie = null;

        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (int i = 0; i < cookies.length; i++) {
                Cookie cookie = cookies[i];
                if (cookie.getName().equalsIgnoreCase(cookieName)) {
                    sessionCookie = cookie;
                    break;
                }
            }
        }

        ConfigManager cfg = (ConfigManager) ctx
                .getAttribute(ProxyConstants.TREMOLO_CONFIG);

        ApplicationType app;

        if (holder != null) {
            app = holder.getApp();
        } else {
            app = null;

            String appName = null;
            if (cookies != null) {
                for (int i = 0; i < cookies.length; i++) {
                    if (cookies[i].getName().equals("autoIdmAppName")) {
                        appName = URLDecoder.decode(cookies[i].getValue(),
                                "UTF-8");
                        break;
                    }
                }
            }

            if (appName == null) {
                // TODO create open session
                if (cookies != null) {
                    for (int i = 0; i < cookies.length; i++) {
                        if (cookies[i].getName().equals(cfg.getCfg().getApplications().getOpenSessionCookieName())) {
                            String sessionID = cookies[i].getValue();
                            TremoloHttpSession tsession = this.sessionManager.getSessionById(sessionID);
                            // TODO add timeouts
                            if (tsession == null) {
                                return this.createOpenSession(request, resp,
                                        ctx);
                            } else {
                                return tsession;
                            }

                        }
                    }
                }

                return createOpenSession(request, resp, ctx);
            } else {
                app = cfg.getApp(appName);

                if (app == null) {
                    throw new Exception("No application named '" + appName
                            + "' found");
                }

            }
        }

        SecretKey encKey = cfg
                .getSecretKey(app.getCookieConfig().getKeyAlias());

        // TremoloHttpSession tsession = (TremoloHttpSession)
        // request.getSession().getAttribute(app.getCookieConfig().getSessionCookieName());

        if (sessionCookie == null) {
            // if (tsession != null) tsession.invalidate();
            return createSession(app, request, resp, ctx, encKey);
        } else {

            HttpSession session = null;

            try {

                try {

                    TremoloHttpSession tsession = findSessionFromCookie(sessionCookie, encKey,this.sessionManager);

                    if (tsession == null) {
                        return createSession(app, request, resp, ctx, encKey);
                    }

                    String fromSessionID = (String) tsession
                            .getAttribute(OpenUnisonConstants.TREMOLO_SESSION_ID);

                    if (app.getCookieConfig().getTimeout() > 0) {
                        if (logger.isDebugEnabled()) {
                            logger.debug("Application - '" + tsession.getAppName() + "' - Timeout greater then 0");
                        }
                        ExternalSessionExpires extSession = (ExternalSessionExpires) tsession.getAttribute(SessionManagerImpl.TREMOLO_EXTERNAL_SESSION);

                        if (extSession != null) {
                            if (logger.isDebugEnabled()) {
                                logger.debug("Application - '" + tsession.getAppName() + "' - External session");
                            }
                            DateTime now = new DateTime();
                            DateTime lastAccessed = (DateTime) tsession
                                    .getAttribute(SessionManagerImpl.TREMOLO_SESSION_LAST_ACCESSED);

                            if (logger.isDebugEnabled()) {
                                logger.debug("Application - '" + tsession.getAppName() + "' - now='" + now + "' ext expired='" + extSession.isExpired() + "'");
                                logger.debug("Application - '" + tsession.getAppName() + "' - now='" + now + "' expires='" + lastAccessed + "' expired='" + (now.minusSeconds(app.getCookieConfig().getTimeout())
                                        .isAfter(lastAccessed)) + "'");
                            }

                            if (extSession.isExpired(app.getCookieConfig().getTimeout(),lastAccessed.getMillis())) {
                                if (logger.isDebugEnabled()) {
                                    logger.debug("Application - '" + tsession.getAppName() + "' - Invalidating and creating");
                                }
                                //external session has expired, create a new one
                                tsession.invalidate();
                                return createSession(app, request, resp, ctx,
                                        encKey);
                            } else {
                                if (logger.isDebugEnabled()) {
                                    logger.debug("Application - '" + tsession.getAppName() + "' - Session OK");
                                }
                                tsession.setAttribute(
                                        SessionManagerImpl.TREMOLO_SESSION_LAST_ACCESSED,
                                        now);
                                session = tsession;
                            }

                        } else {

                            if (logger.isDebugEnabled()) {
                                logger.debug("Application - '" + tsession.getAppName() + "' - Not external session");
                            }

                            DateTime lastAccessed = (DateTime) tsession
                                    .getAttribute(SessionManagerImpl.TREMOLO_SESSION_LAST_ACCESSED);
                            DateTime now = new DateTime();

                            if (logger.isDebugEnabled()) {
                                logger.debug("Application - '" + tsession.getAppName() + "' - now='" + now + "' expires='" + lastAccessed + "' expired='" + (now.minusSeconds(app.getCookieConfig().getTimeout())
                                        .isAfter(lastAccessed)) + "'");
                            }

                            if (now.minusSeconds(app.getCookieConfig().getTimeout())
                                    .isAfter(lastAccessed)) {

                                if (logger.isDebugEnabled()) {
                                    logger.debug("Application - '" + tsession.getAppName() + "' - Invalidating sesssion and recreating");
                                }

                                tsession.invalidate();
                                return createSession(app, request, resp, ctx,
                                        encKey);
                            } else {
                                if (logger.isDebugEnabled()) {
                                    logger.debug("Application - '" + tsession.getAppName() + "' - Session OK");
                                }

                                tsession.setAttribute(
                                        SessionManagerImpl.TREMOLO_SESSION_LAST_ACCESSED,
                                        now);
                                session = tsession;
                            }
                        }
                    } else {
                        session = tsession;
                    }

                } catch (Exception e) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Exception loading session", e);
                    }
                    return createSession(app, request, resp, ctx, encKey);

                }

                // this.sessions.put(session.getSessionID(), key);
                // }

            } catch (Exception e) {
                logger.error("Error generating session", e);
            }
            if (session == null) {
                // session.invalidate();
                return createSession(app, request, resp, ctx, encKey);
            }

            // session.resetAccess();

            return session;

        }
    }



    public static TremoloHttpSession findSessionFromCookie(Cookie sessionCookie, SecretKey encKey,SessionManager sessionMgr)
            throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        String tokenHeader = new String(
                org.bouncycastle.util.encoders.Base64
                        .decode(sessionCookie.getValue().getBytes(
                                "UTF-8")));
        Gson gson = new Gson();
        Token token = gson.fromJson(tokenHeader, Token.class);
        byte[] iv = org.bouncycastle.util.encoders.Base64
                .decode(token.getIv());

        IvParameterSpec spec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, encKey, spec);

        byte[] encBytes = org.bouncycastle.util.encoders.Base64
                .decode(token.getEncryptedRequest());
        String requestToken = new String(cipher.doFinal(encBytes));

        TremoloHttpSession tsession = sessionMgr.getSessions().get(requestToken);
        return tsession;
    }

    private HttpSession createSession(ApplicationType app,
                                      HttpServletRequest req, HttpServletResponse resp,
                                      ServletContext ctx, SecretKey encKey) throws Exception {

        byte[] idBytes = new byte[20];
        random.nextBytes(idBytes);

        StringBuffer b = new StringBuffer();
        b.append('f').append(Hex.encodeHexString(idBytes));
        String id = b.toString();

        // HttpSession session = req.getSession(true);
        TremoloHttpSession tsession = new TremoloHttpSession(id);
        tsession.setAppName(app.getName());
        tsession.refresh(this.ctx, this.sessionManager);
        tsession.setOpen(false);
        this.anonMech.createSession(tsession, this.anonChainType);

        AuthController actl = (AuthController) tsession
                .getAttribute(ProxyConstants.AUTH_CTL);

        AuthInfo auInfo = actl.getAuthInfo();
        auInfo.setAuthComplete(true);

        // session.setAttribute(app.getCookieConfig().getSessionCookieName(),
        // tsession);

        tsession.setAttribute(OpenUnisonConstants.TREMOLO_SESSION_ID, id);
        tsession.setMaxInactiveInterval(app.getCookieConfig().getTimeout());

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, encKey);

        byte[] encSessionKey = cipher.doFinal(id.getBytes("UTF-8"));
        String base64d = new String(
                org.bouncycastle.util.encoders.Base64.encode(encSessionKey));

        Token token = new Token();
        token.setEncryptedRequest(base64d);
        token.setIv(new String(org.bouncycastle.util.encoders.Base64
                .encode(cipher.getIV())));

        Gson gson = new Gson();

        String cookie = gson.toJson(token);

        byte[] btoken = cookie.getBytes("UTF-8");
        String encCookie = new String(
                org.bouncycastle.util.encoders.Base64.encode(btoken));

        Cookie sessionCookie;

        sessionCookie = new Cookie(
                app.getCookieConfig().getSessionCookieName(), encCookie);

        // logger.debug("session size : " +
        // org.apache.directory.shared.ldap.util.Base64.encode(encSession).length);
        String domain = ProxyTools.getInstance().getCookieDomain(
                app.getCookieConfig(), req);
        if (domain != null) {
            sessionCookie.setDomain(domain);
        }
        sessionCookie.setPath("/");
        sessionCookie.setSecure(false);
        sessionCookie.setMaxAge(-1);
        sessionCookie.setSecure(app.getCookieConfig().isSecure());
        sessionCookie.setHttpOnly(app.getCookieConfig().isHttpOnly() != null && app.getCookieConfig().isHttpOnly());
        //resp.addCookie(sessionCookie);
        ProxyResponse.addCookieToResponse(app, sessionCookie, resp);

        // delete the opensession if it exists
        if (configManager.getCfg().getApplications().getOpenSessionCookieName() != null && ! configManager.getCfg().getApplications().getOpenSessionCookieName().isEmpty()) {
            Cookie openSessionCookie = new Cookie(configManager.getCfg().getApplications()
                    .getOpenSessionCookieName(), id);

            openSessionCookie.setPath("/");
            openSessionCookie.setSecure(configManager.getCfg().getApplications().isOpenSessionSecure());
            openSessionCookie.setHttpOnly(configManager.getCfg().getApplications().isOpenSessionHttpOnly());
            openSessionCookie.setMaxAge(0);
            resp.addCookie(openSessionCookie);
        }

        sessionManager.putSession(id,tsession);

        return tsession;
    }

    private HttpSession createOpenSession(HttpServletRequest req,
                                          HttpServletResponse resp, ServletContext ctx) throws Exception {

        byte[] idBytes = new byte[20];
        random.nextBytes(idBytes);
        StringBuffer b = new StringBuffer();
        b.append('f').append(Hex.encodeHexString(idBytes));
        String id = b.toString();

        // HttpSession session = req.getSession(true);
        TremoloHttpSession tsession = new TremoloHttpSession(id);
        tsession.setOpen(true);
        tsession.refresh(this.ctx, this.sessionManager);
        this.anonMech.createSession(tsession, this.anonChainType);

        AuthController actl = (AuthController) tsession
                .getAttribute(ProxyConstants.AUTH_CTL);

        AuthInfo auInfo = actl.getAuthInfo();
        auInfo.setAuthComplete(true);

        // session.setAttribute(app.getCookieConfig().getSessionCookieName(),
        // tsession);

        tsession.setAttribute(OpenUnisonConstants.TREMOLO_SESSION_ID, id);

        // TODO add global session timeout
        // tsession.setMaxInactiveInterval(app.getCookieConfig().getTimeout());

        // TODO add global open session name
        Cookie sessionCookie = new Cookie(configManager.getCfg().getApplications()
                .getOpenSessionCookieName(), id);

        sessionCookie.setPath("/");
        sessionCookie.setSecure(configManager.getCfg().getApplications().isOpenSessionSecure());
        sessionCookie.setHttpOnly(configManager.getCfg().getApplications().isOpenSessionHttpOnly());
        sessionCookie.setMaxAge(-1);
        // TODO add secure?
        // sessionCookie.setSecure(app.getCookieConfig().isSecure());
        resp.addCookie(sessionCookie);

        this.sessionManager.putSession(id,tsession);


        return tsession;
    }

    public HttpSession getSession(UrlHolder holder, HttpServletRequest request,
                                  HttpServletResponse response, ServletContext ctx) throws Exception {

        // if we are not using a secure session, use generic session
        if (holder.getApp().getCookieConfig() == null) {
            return request.getSession();
        }

        String cookieName = holder.getApp().getCookieConfig()
                .getSessionCookieName();
        if (cookieName == null || cookieName.length() == 0) {
            return request.getSession();
        }

        HttpSession session = locateSession(holder, request, ctx, cookieName,
                response);
        if (session instanceof HttpSession) {
            ((TremoloHttpSession) session).refresh(ctx, this.sessionManager);
        }

        return session;

    }

    public HttpSession getSession(String sessionCookieName, UrlHolder holder,
                                  HttpServletRequest request, HttpServletResponse response,
                                  ServletContext ctx) throws Exception {
        return this.locateSession(holder, request, ctx, sessionCookieName,
                response);
    }
}
