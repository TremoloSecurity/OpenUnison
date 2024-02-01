/*******************************************************************************
 * Copyright (c) 2024 Tremolo Security, Inc.
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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

public class ObjUtils {
	public static Map<String,String> props2map(Object obj) throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
		Map<String,String> map = new HashMap<String,String>();
		
		StringBuilder sb = new StringBuilder();
		
		Method[] methods = obj.getClass().getMethods();
		
		for (Method method : methods) {
			if (method.getName().startsWith("get") && method.canAccess(obj) && method.getParameterCount() == 0) {
				String propName = method.getName().substring(3);
				
				char firstChar = Character.toLowerCase(propName.charAt(0));
				sb.setLength(0);
				sb.append(firstChar).append(propName.substring(1));
				propName = sb.toString();
				
				Object val = method.invoke(obj);
				if (val != null) {
					map.put(propName,val.toString());
				}
			}
		}
		
		
		return map;
	}
	
	public static void map2props(Map<String,String> props,Object obj) throws NumberFormatException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
		StringBuilder sb = new StringBuilder();
		
		Method[] methods = obj.getClass().getMethods();
		
		for (Method method : methods) {
			if (method.getName().startsWith("set") && method.canAccess(obj) && method.getParameterCount() == 1) {
				String propName = method.getName().substring(3);
				
				char firstChar = Character.toLowerCase(propName.charAt(0));
				sb.setLength(0);
				sb.append(firstChar).append(propName.substring(1));
				propName = sb.toString();
				
				String val = props.get(propName);
				if (val != null) {
					if (method.getParameters()[0].getType().equals(Integer.class)) {
						method.invoke(obj, Integer.parseInt(val));
					} else if (method.getParameters()[0].getType().equals(Long.class)) {
						method.invoke(obj, Long.parseLong(val));
					} else if (method.getParameters()[0].getType().equals(String.class)) {
						method.invoke(obj, val);
					}
				}
			}
		}
	}
}
