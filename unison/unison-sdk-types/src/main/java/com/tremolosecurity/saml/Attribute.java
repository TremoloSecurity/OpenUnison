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


	package com.tremolosecurity.saml;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import org.apache.logging.log4j.Logger;


/**
 * Primary class for representing an attribute with a name and one or more values
 * 
 *
 */
public class Attribute implements Serializable {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 3652987806606284542L;

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(Attribute.class);
	

	List<String> values;
	String name;

	/**
	 * Creates an attribute with an empty name and no values
	 */
	public Attribute() {
		this.name = "";
		this.values = new ArrayList<String>();
	}
	
	/**
	 * Creates an attribute with a given name and no values
	 * @param name Name for the attribute
	 */
	public Attribute(String name) {
		this.name = name;
		this.values = new ArrayList<String>();
	}
	
	/**
	 * Creates an attribute with a name and single value
	 * @param name Name of the attribute
	 * @param value First value
	 */
	public Attribute(String name,String value) {
		this(name);
		this.values.add(value);
	}
	
	
	/**
	 * Creates an attribute with values from an array of strings
	 * @param name Name of the attribute
	 * @param values List of values
	 */
	public Attribute(String name,String[] values) {
		this(name);
		
		for (int i=0;i<values.length;i++) {
			this.values.add(values[i]);
		}
	}
	
	/**
	 * Attribute values
	 * @return Attribute's values
	 */
	public List<String> getValues() {
		
		return this.values;
	}
	
	/**
	 * Replaces the attribute's values
	 * @param values Values to replace the current values with
	 */
	public void setValues(List<String> values) {
		this.values.clear();
		this.values.addAll(values);
	}
	
	/**
	 * Retrieve the attribute's name
	 * @return Attribute's name
	 */
	public String getName() {
		return this.name;
	}
	
	/**
	 * String representation of the attribute, prints all values
	 */
	public String toString() {
		StringBuffer buf = new StringBuffer();
		buf.append(this.name).append(" : ");
		for (String val : this.values) {
			buf.append('\'').append(val).append('\'').append(' ');
		}
		
		return buf.toString();
	}
}
