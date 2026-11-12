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

package com.tremolosecurity.util;

import jakarta.servlet.http.HttpServletRequest;

import java.util.Map;

public class LdapUtils {
    public static String genFilter(String lookupFilter, Map jwtNVP) {
        StringBuffer b = new StringBuffer();
        int lastIndex = 0;
        int index = lookupFilter.indexOf('$');
        while (index >= 0) {
            b.append(lookupFilter.substring(lastIndex,index));
            lastIndex = lookupFilter.indexOf('}',index) + 1;
            String reqName = lookupFilter.substring(index + 2,lastIndex - 1);
            String value = "";
            if (jwtNVP.containsKey(reqName)) {
                value = jwtNVP.get(reqName).toString();
                value = escapeLdapFilterValue(value);
            }

            b.append(value);
            index = lookupFilter.indexOf('$',index+1);
        }
        b.append(lookupFilter.substring(lastIndex));
        return b.toString();
    }

    public static String genFilter(String lookupFilter, HttpServletRequest request) {
        StringBuffer b = new StringBuffer();
        int lastIndex = 0;
        int index = lookupFilter.indexOf('$');
        while (index >= 0) {
            b.append(lookupFilter.substring(lastIndex,index));
            lastIndex = lookupFilter.indexOf('}',index) + 1;
            String reqName = lookupFilter.substring(index + 2,lastIndex - 1);
            String value = request.getParameter(reqName);
            if (value != null) {
                value = escapeLdapFilterValue(value);
            } else {
                value = "";
            }

            b.append(value);
            index = lookupFilter.indexOf('$',index+1);
        }
        b.append(lookupFilter.substring(lastIndex));
        return b.toString();
    }

    public static String escapeLdapFilterValue(String value) {
        java.util.Objects.requireNonNull(value, "value");
        StringBuilder out = new StringBuilder(value.length());

        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\0': out.append("\\00"); break;
                case '(':  out.append("\\28"); break;
                case ')':  out.append("\\29"); break;
                case '*':  out.append("\\2a"); break;
                case '\\': out.append("\\5c"); break;
                default:   out.append(c);
            }
        }
        return out.toString();
    }
}


