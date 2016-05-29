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
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
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

import org.apache.logging.log4j.Logger;


import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class AddChoiceToTasks {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(AddChoiceToTasks.class);
	
	static HashSet<String> checkTags;
	static HashSet<String> ignoreTags;
	
	public static void convert(InputStream input,OutputStream output) throws Exception {
		
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
		ignoreTags.add("onSuccess");
		ignoreTags.add("onFailure");

		
		
		//make a backup
		//String backup = path + ".backup";
		
		//logger.info("Backing up '" + path + "' to '" + backup + "'");
		
		/*BufferedReader in = new BufferedReader(new InputStreamReader(input));
		PrintWriter out = new PrintWriter(new FileOutputStream(backup));
		String line = null;
		
		while ((line = in.readLine()) != null) {
			out.println(line);
		}
		
		in.close();
		out.flush();
		out.close();*/
		
		logger.info("Backup complete");
		
		logger.info("Loading XML");
		
		DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory
		        .newInstance();
		    DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
		    Document document = docBuilder.parse(input);
		
		    
		Node workflows = findWorkflows(document.getDocumentElement());
		if (workflows != null) {
			walkDOM(workflows);
			walkDOMTasks(workflows);
			
			logger.info("Saving XML");
			Transformer transformer = TransformerFactory.newInstance().newTransformer();
			Result outputDoc = new StreamResult(output);//new StreamResult(new File(path));
			Source inputDoc = new DOMSource(document);
	
			transformer.transform(inputDoc, outputDoc);
		} else {
			logger.warn("No workflows found");
		}
		
		
	}
	
	
	private static Node findWorkflows(Node node) throws Exception {
		String name = node.getNodeName();
		String prefix = null;
		
		
		Node found = null;
		
		if (name.indexOf(':') >= 0) {
			prefix = name.substring(0,name.indexOf(':'));
			name = name.substring(name.indexOf(':') + 1);
		}
		
		if (name.equals("workflows")) {
			return node;
		} else {
			NodeList nodeList = node.getChildNodes();
			
			
			for (int i = 0; i < nodeList.getLength(); i++) {
		        org.w3c.dom.Node currentNode = nodeList.item(i);
		        if (currentNode.getNodeType() == Node.ELEMENT_NODE) {
		            //calls this method for all the children which is Element
		        	found = findWorkflows(currentNode);
		        	if (found != null) {
		        		return found;
		        	}
		        }
		    }
			
			return null;
		}
	}
	
	
	private static boolean isSuccessSet(Node node) throws Exception {
		NodeList nodeList = node.getChildNodes();
		for (int i=0;i<nodeList.getLength();i++) {
			Node n = nodeList.item(i);
			if (n.getNodeName().contains("onSuccess") || n.getNodeName().contains("onFailure")) {
				return true;
			}
				
		}
		
		return false;
	}
	
	private static boolean isTasksSet(Node node) throws Exception {
		NodeList nodeList = node.getChildNodes();
		for (int i=0;i<nodeList.getLength();i++) {
			Node n = nodeList.item(i);
			if (n.getNodeName().contains("tasks")) {
				return true;
			}
				
		}
		
		return false;
	}
	
	private static void walkDOM(Node node) throws Exception {
		String name = node.getNodeName();
		String prefix = null;
		if (name.indexOf(':') >= 0) {
			prefix = name.substring(0,name.indexOf(':'));
			name = name.substring(name.indexOf(':') + 1);
		}
		
		logger.debug("Name : '" + name + "' (prefix : '" + prefix + "')");
		
		if (checkTags.contains(name) && ! isSuccessSet(node)) {
			logger.debug("Found tag to convert");
			
			NodeList nodeList = node.getChildNodes();
		    
			Node onSuccess = node.getOwnerDocument().createElement( prefix == null ? "onSuccess" : prefix + ":onSuccess"   );
			ArrayList<Node> toMove = new ArrayList<Node>();
			
			for (int i = 0; i < nodeList.getLength(); i++) {
		        org.w3c.dom.Node currentNode = nodeList.item(i);
		        if (currentNode.getNodeType() == Node.ELEMENT_NODE ) {
		        	
		        	String lname = currentNode.getNodeName();
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
	
	
	private static void walkDOMTasks(Node node) throws Exception {
		String name = node.getNodeName();
		String prefix = null;
		if (name.indexOf(':') >= 0) {
			prefix = name.substring(0,name.indexOf(':'));
			name = name.substring(name.indexOf(':') + 1);
		}
		
		logger.debug("Name : '" + name + "' (prefix : '" + prefix + "')");
		
		if (name.equalsIgnoreCase("workflow") && ! isTasksSet(node)) {
			logger.debug("Found tag to convert");
			
			NodeList nodeList = node.getChildNodes();
		    
			Node tasks = node.getOwnerDocument().createElement( prefix == null ? "tasks" : prefix + ":tasks"   );
			ArrayList<Node> toMove = new ArrayList<Node>();
			
			for (int i = 0; i < nodeList.getLength(); i++) {
		        org.w3c.dom.Node currentNode = nodeList.item(i);
		        if (currentNode.getNodeType() == Node.ELEMENT_NODE ) {
		        	
		        	String lname = currentNode.getNodeName();
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
				tasks.appendChild(n);
			}
			
			
			Element dynamicConfig = (Element) node.getOwnerDocument().createElement( prefix == null ? "dynamicConfiguration" : prefix + ":dynamicConfiguration"   );
			dynamicConfig.setAttribute("dynamic", "false");
			node.appendChild(dynamicConfig);
			node.appendChild(tasks);
			node = tasks;
		}
		
		
		NodeList nodeList = node.getChildNodes();
		
		
		for (int i = 0; i < nodeList.getLength(); i++) {
	        org.w3c.dom.Node currentNode = nodeList.item(i);
	        if (currentNode.getNodeType() == Node.ELEMENT_NODE) {
	            //calls this method for all the children which is Element
	            walkDOMTasks(currentNode);
	        }
	    }
	}
	

}
