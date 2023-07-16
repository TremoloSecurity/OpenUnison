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
package com.tremolosecurity.scalejs.util;

import jakarta.servlet.http.HttpServletResponse;

import com.tremolosecurity.proxy.filter.HttpFilterResponse;

public class ScaleJSUtils {

	
	public static void addCacheHeaders(HttpFilterResponse response) {
		response.addHeader("cacheSeconds", "0");
		response.addHeader("useExpiresHeader", "true");
		response.addHeader("useCacheControlHeader", "true");
		response.addHeader("useCacheControlNoStore", "true");

		// The above alone did not solve the problem in IE9, so here are some more!

		// Set to expire far in the past.
		response.setHeader("Expires", "Mon, 23 Aug 1982 12:00:00 GMT");

		// Set standard HTTP/1.1 no-cache headers.
		response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");

		// Set IE extended HTTP/1.1 no-cache headers (use addHeader).
		response.addHeader("Cache-Control", "post-check=0, pre-check=0");

		// Set standard HTTP/1.0 no-cache header.
		response.setHeader("Pragma", "no-cache");
	}
}
