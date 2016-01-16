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

import java.io.Serializable;

public class EncryptedMessage implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 9109714828839302406L;
	byte[] iv;
	byte[] msg;
	
	public EncryptedMessage() {
		
	}

	public byte[] getIv() {
		return iv;
	}

	public void setIv(byte[] iv) {
		this.iv = iv;
	}

	public byte[] getMsg() {
		return msg;
	}

	public void setMsg(byte[] msg) {
		this.msg = msg;
	}
	
	
}
