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


package com.tremolosecurity.util;

import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class TestJCE {

	public static void main(String[] args) {
		
		try {
			int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
		    
			
		    if (maxKeyLen > 128) {
		    	System.out.println("OK");
		    } else {
		    	System.out.println("FAIL");
		    }
		} catch (Throwable t) {
			System.out.println("FAIL");
		}

	}

}
