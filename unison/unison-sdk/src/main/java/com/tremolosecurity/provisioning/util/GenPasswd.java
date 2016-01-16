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


package com.tremolosecurity.provisioning.util;
import java.util.Random;


public class GenPasswd {
	static char[] lowercase = new char[] {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z'};
	static char[] uppercase = new char[] {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'};
	static char[] spec = new char[] {'!','@','#','$','%','^'};
	
	
	
	int len;
	private boolean useUpperCase;
	private boolean useLowerCase;
	private boolean useSpecial;
	private boolean useNumbers;
	
	private Random random;
	
	public GenPasswd(int len) {
		this(len,true,true,true,true);
	}
	
	public GenPasswd(int keyLen, boolean useUpperCase, boolean useLowerCase,
			boolean useNumbers, boolean useSpecial) {
		this.len = keyLen;
		this.useUpperCase = useUpperCase;
		this.useLowerCase = useLowerCase;
		this.useSpecial = useSpecial;
		this.useNumbers = useNumbers;
		this.random = new Random();
	}

	public String getPassword() {
		boolean usedUpper  = false;
		boolean usedSpecial = false;
		boolean usedNum = false;
		
		
		StringBuffer pwd = new StringBuffer();
		
		for (int i=0;i<len;i++) {
			int type = randomType();
			
			if (this.useUpperCase) {
				if (i+3 == len && ! usedUpper) {
					type = 1;
				}
			}
			
			if (this.useSpecial) {
				if (i+2 == len && ! usedSpecial) {
					type = 2;
				}
			}
			
			if (this.useNumbers) {
				if (i+1 == len && ! usedNum) {
					type = 3;
				}
			}
			
			
			switch (type) {
				case 0 : pwd.append(lowercase[Math.abs(random.nextInt()) % 26]); break;
				case 1 : usedUpper = true; pwd.append(uppercase[Math.abs(random.nextInt()) % 26]); break;
				case 2 : usedSpecial = true;; pwd.append(spec[Math.abs(random.nextInt()) % 6]); break;
				case 3 : usedNum = true; pwd.append(Math.abs(random.nextInt()) % 10); break;
			}
		}
		
		return pwd.toString();
	}
	
	private int randomType() {
		int type = Math.abs(random.nextInt()) % 4;
		
		if (type == 0 && !this.useLowerCase) {
			return randomType();
		}
		
		if (type == 1 && !this.useUpperCase) {
			return randomType();
		}
		
		if (type == 2 && ! this.useSpecial) {
			return randomType();
		}
		
		if (type == 3 && ! this.useNumbers) {
			return randomType();
		}
		
		return type;
		
	}
	
	public String getPasswordAlphaNumeric() {
		boolean usedUpper  = false;
		
		boolean usedNum = false;
		
		Random random = new Random();
		StringBuffer pwd = new StringBuffer();
		
		for (int i=0;i<len;i++) {
			int type = Math.abs(random.nextInt()) % 3;
			
			if (i+2 == len && ! usedUpper) {
				type = 1;
			}
			
			
			
			if (i+1 == len && ! usedNum) {
				type = 3;
			}
			
			
			switch (type) {
				case 0 : pwd.append(lowercase[Math.abs(random.nextInt()) % 26]); break;
				case 1 : usedUpper = true; pwd.append(uppercase[Math.abs(random.nextInt()) % 26]); break;
				case 2 : usedNum = true; pwd.append(Math.abs(random.nextInt()) % 10); break;
				
			}
		}
		
		return pwd.toString();
	}
}
