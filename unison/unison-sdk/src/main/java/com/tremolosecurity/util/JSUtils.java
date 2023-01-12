/*******************************************************************************
 * Copyright (c) 2023 Tremolo Security, Inc.
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
 *******************************************************************************/
package com.tremolosecurity.util;

import java.io.UnsupportedEncodingException;
import java.util.Base64;

/**
 * Utility class because graalvm js doesn't play well with Java String<->byte[]
 */
public class JSUtils {
	public static byte[] string2bytes(String s) {
		try {
			return s.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			return null;
		}
	}
	
	public static String bytes2string(byte[] bytes) {
		return new String(bytes);
	}
	
	public static String base64Decode(String src) {
		return new String(Base64.getDecoder().decode(src));
	}
}
