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

package com.tremolosecurity.proxy.auth.oauth2;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.saml.Attribute;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.util.HashMap;


public interface WebFingerCredentialLoader {
    /**
     * load a bearer token
     * @param request
     * @param response
     * @param as
     * @param session
     * @param authParams
     * @return
     * @throws ServletException
     */
    public String loadBearerToken(HttpServletRequest request, HttpServletResponse response, AuthStep as, HttpSession session, HashMap<String, Attribute> authParams) throws ServletException;
}
