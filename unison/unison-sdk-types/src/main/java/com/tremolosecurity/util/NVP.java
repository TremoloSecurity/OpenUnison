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

import java.io.Serializable;

/**
 * Utility class for representing a single name/value pair
 *
 */
public class NVP implements Serializable {
	
	private static final long serialVersionUID = 6584834326667625441L;
	String name;
	String value;
	int num;
	
	
	/**
	 * Optional number in hosted list
	 * @return
	 */
	public int getNum() {
		return num;
	}

	/**
	 * Name of the value
	 * @return
	 */
	public String getName() {
		return name;
	}

	/**
	 * Value for the name
	 * @return
	 */
	public String getValue() {
		return value;
	}

	/**
	 * Creates an name/value pair
	 * @param name Name
	 * @param value Value
	 */
	public NVP(String name,String value) {
		this.name = name;
		this.value = value;
	}
	
	/**
	 * Creates a name/value pair with an options number
	 * @param name Name
	 * @param value Value
	 * @param num Number
	 */
	public NVP(String name,String value, int num) {
		this(name,value);
		this.num = num;
	}
	
	/**
	 * Creates an empty name/value pair
	 */
	public NVP() {
		this("","");
		this.num = 0;
	}
}
