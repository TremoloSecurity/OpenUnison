/*
Copyright 2015, 2016 Tremolo Security, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


package com.tremolosecurity.proxy.util;

import java.util.Enumeration;
import java.util.Iterator;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.proxy.myvd.MyVDConnection;

public class ItEnumeration implements Enumeration<Object> {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(ItEnumeration.class);
	
	Iterator it;
	
	public ItEnumeration(Iterator it) {
		this.it = it;
	}
	
	@Override
	public boolean hasMoreElements() {
		return it.hasNext();
	}

	@Override
	public Object nextElement() {
		return it.next();
	}

}
