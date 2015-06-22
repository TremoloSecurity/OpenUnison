/*
Copyright 2015 Tremolo Security, Inc.

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


package com.tremolosecurity.certs;

import java.util.Comparator;

public class CertEntry implements Comparable {
	String name;
	String expires;
	int daysLeft;
	
	public CertEntry(String name,String expires,int daysLeft) {
		this.name = name;
		this.expires = expires;
		this.daysLeft = daysLeft;
	}

	public String getName() {
		return name;
	}

	public String getExpires() {
		return expires;
	}

	public int getDaysLeft() {
		return daysLeft;
	}

	

	@Override
	public int compareTo(Object o) {
		CertEntry e2 = (CertEntry) o;
		
		if (this.daysLeft == e2.getDaysLeft()) {
			return 0;
		} else if (this.daysLeft < e2.getDaysLeft()) {
			return -1;
		} else {
			return 1;
		}
	}
	
	
	
}
