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

import jakarta.servlet.http.Cookie;

public class ProxyCookie extends Cookie {
    Cookie source;

    /**
     * Constructs a cookie with the specified name and value.
     *
     * <p>
     * The name must conform to RFC 6265. However, vendors may provide a configuration option that allows cookie names
     * conforming to the original Netscape Cookie Specification to be accepted.
     *
     * <p>
     * The name of a cookie cannot be changed once the cookie has been created.
     *
     * <p>
     * The value can be anything the server chooses to send. Its value is probably of interest only to the server. The
     * cookie's value can be changed after creation with the <code>setValue</code> method.
     *
     * @param name  the name of the cookie
     * @param value the value of the cookie
     * @throws IllegalArgumentException if the cookie name is null or empty or contains any illegal characters (for example,
     *                                  a comma, space, or semicolon) or matches a token reserved for use by the cookie protocol
     * @see #setValue
     * @see #setVersion
     */
    public ProxyCookie(String name, String value) {
        super(name, value);
    }

    public ProxyCookie(Cookie source) {
        super(source.getName(), source.getValue());
        this.source = source;
    }

    @Override
    public String getValue() {
        String value = super.getValue();
        if (value.startsWith("\"") && value.endsWith("\"")) {
            value = value.substring(1, value.length() - 1);
        }

        return value;
    }


}
