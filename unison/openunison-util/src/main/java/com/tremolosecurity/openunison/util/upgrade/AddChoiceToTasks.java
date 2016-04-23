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
package com.tremolosecurity.openunison.util.upgrade;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Properties;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class AddChoiceToTasks {
	static Logger logger = Logger.getLogger(AddChoiceToTasks.class);
	
	static HashSet<String> checkTags;
	static HashSet<String> ignoreTags;
	
	public static void convert(String path) throws Exception {
		
		checkTags = new HashSet<String>();
		checkTags.add("ifNotUserExists");
		checkTags.add("mapping");
		checkTags.add("ifAttrExists");
		checkTags.add("approval");
		checkTags.add("ifAttrHasValue");
		
		ignoreTags = new HashSet<String>();
		ignoreTags.add("map");
		ignoreTags.add("emailTemplate");
		ignoreTags.add("approvers");
		ignoreTags.add("mailAttr");
		ignoreTags.add("failureEmailSubject");
		ignoreTags.add("failureEmailMsg");
		ignoreTags.add("escalationPolicy");

		
		
		//make a backup
		String backup = path + ".backup";
		
		logger.info("Backing up '" + path + "' to '" + backup + "'");
		
		BufferedReader in = new BufferedReader(new InputStreamReader(new FileInputStream(path)));
		PrintWriter out = new PrintWriter(new FileOutputStream(backup));
		String line = null;
		
		while ((line = in.readLine()) != null) {
			out.println(line);
		}
		
		in.close();
		out.flush();
		out.close();
		
		logger.info("Backup complete");
		
		logger.info("Loading XML");
		
		DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory
		        .newInstance();
		    DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
		    Document document = docBuilder.parse(new File(path));
		
		walkDOM(document.getDocumentElement());
		
		logger.info("Saving XML");
		Transformer transformer = TransformerFactory.newInstance().newTransformer();
		Result output = new StreamResult(System.out);//new StreamResult(new File(path));
		Source input = new DOMSource(document);

		transformer.transform(input, output);
		
		
	}
	
	
	private static void walkDOM(Node node) throws Exception {
		String name = node.getNodeName();
		String prefix = null;
		if (name.indexOf(':') >= 0) {
			prefix = name.substring(0,name.indexOf(':'));
			name = name.substring(name.indexOf(':') + 1);
		}
		
		logger.debug("Name : '" + name + "' (prefix : '" + prefix + "')");
		
		if (checkTags.contains(name)) {
			logger.debug("Found tag to convert");
			
			NodeList nodeList = node.getChildNodes();
		    
			Node onSuccess = node.getOwnerDocument().createElement( prefix == null ? "onSuccess" : prefix + ":onSuccess"   );
			ArrayList<Node> toMove = new ArrayList<Node>();
			
			for (int i = 0; i < nodeList.getLength(); i++) {
		        org.w3c.dom.Node currentNode = nodeList.item(i);
		        if (currentNode.getNodeType() == Node.ELEMENT_NODE ) {
		        	
		        	String lname = node.getNodeName();
		    		String lprefix = null;
		    		if (lname.indexOf(':') >= 0) {
		    			lprefix = lname.substring(0,lname.indexOf(':'));
		    			lname = lname.substring(lname.indexOf(':') + 1);
		    		}
		        	
		        	if (! ignoreTags.contains(lname)) {
		        		toMove.add(currentNode);
		        	}
		        }
		        
		    }
			
			for (Node n : toMove) {
				onSuccess.appendChild(n);
			}
			
			node.appendChild(onSuccess);
			node = onSuccess;
		}
		
		
		NodeList nodeList = node.getChildNodes();
		
		
		for (int i = 0; i < nodeList.getLength(); i++) {
	        org.w3c.dom.Node currentNode = nodeList.item(i);
	        if (currentNode.getNodeType() == Node.ELEMENT_NODE) {
	            //calls this method for all the children which is Element
	            walkDOM(currentNode);
	        }
	    }
	}
	
	public static void main(String[] args) throws Exception {
		Properties props = new Properties();
		props.put("log4j.rootLogger", "debug,console");
		
		//props.put("log4j.appender.console","org.apache.log4j.RollingFileAppender");
		//props.put("log4j.appender.console.File","/home/mlb/myvd.log");
		props.put("log4j.appender.console","org.apache.log4j.ConsoleAppender");
		props.put("log4j.appender.console.layout","org.apache.log4j.PatternLayout");
		props.put("log4j.appender.console.layout.ConversionPattern","[%d][%t] %-5p %c{1} - %m%n");
		
		
		
		PropertyConfigurator.configure(props);
		
		AddChoiceToTasks.convert("/Users/mlb/Documents/git/unison/unison-appliance/unit-tests/test/xml/testMapper.xml");
	}
}
