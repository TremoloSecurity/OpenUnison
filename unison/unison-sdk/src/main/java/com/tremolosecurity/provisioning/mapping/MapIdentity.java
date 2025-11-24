/*
Copyright 2015, 2017 Tremolo Security, Inc.

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


package com.tremolosecurity.provisioning.mapping;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import com.novell.ldap.LDAPEntry;
import org.apache.logging.log4j.Logger;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPSearchConstraints;
import com.tremolosecurity.config.xml.IdpMappingType;
import com.tremolosecurity.config.xml.ProvisionMappingType;
import com.tremolosecurity.config.xml.ProvisionMappingsType;
import com.tremolosecurity.config.xml.TargetAttributeType;
import com.tremolosecurity.config.xml.TargetType;
import com.tremolosecurity.config.xml.TargetsType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;

import com.tremolosecurity.provisioning.mapping.MapIdentity.MappingType;
import com.tremolosecurity.saml.Attribute;

import net.sourceforge.myvd.chain.PostSearchEntryInterceptorChain;
import net.sourceforge.myvd.types.Bool;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.types.Filter;
import net.sourceforge.myvd.types.Int;

public class MapIdentity implements Serializable {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -4547872022098138034L;
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(MapIdentity.class.getName());
	
	public enum MappingType {
		staticValue,
		userAttr,
		custom,
		composite
	};
	

	
	HashMap<String,MappingEntry> map;
	HashSet<String> attributes;
	
	boolean strict;
	public MapIdentity() {
		
	}

	public MapIdentity(List<Map<String,String>> mappings,boolean strict) throws ProvisioningException {
		this.strict = strict;
		map = new HashMap<String,MappingEntry>();
		this.attributes = new HashSet<String>();
		for (Map<String,String> mapping : mappings) {

			String name = mapping.get("name");
			String source = mapping.get("source");
			String sourceType = mapping.get("sourceType");

			String targetType = "string";


			if (mapping.get("targetType") != null) {
				targetType = mapping.get("targetType");
			}



			MappingEntry entry = new MappingEntry();
			if (sourceType.equalsIgnoreCase("static")) {
				entry.type = MappingType.staticValue;
				entry.staticValue = source;
			} else if (sourceType.equalsIgnoreCase("user")) {
				entry.type = MappingType.userAttr;
				entry.userAttr = source;
			} else if (sourceType.equalsIgnoreCase("custom")) {
				entry.type = MappingType.custom;
				try {


					String className = source;
					createCustomMapping(entry, className);
				} catch (Exception e) {
					throw new ProvisioningException("Could not load custom mapping",e);
				}
			} else if (sourceType.equalsIgnoreCase("composite")) {
				entry.type = MappingType.composite;
				entry.composite = new ArrayList<MappingPart>();
				int lastIndex = 0;
				int index = source.indexOf('$');
				while (index >= 0) {
					MappingPart mp = new MappingPart();
					mp.isAttr = false;
					mp.val = source.substring(lastIndex,index);
					entry.composite.add(mp);

					lastIndex = source.indexOf('}',index) + 1;
					String reqName = source.substring(index + 2,lastIndex - 1);
					mp = new MappingPart();
					mp.isAttr = true;
					mp.val = reqName;
					entry.composite.add(mp);

					index = source.indexOf('$',index+1);
				}
				MappingPart mp = new MappingPart();
				mp.isAttr = false;
				mp.val = source.substring(lastIndex);
				entry.composite.add(mp);

			} else {
				throw new ProvisioningException("Invalid mapping type: " + sourceType + " from " + mapping);
			}

			if (targetType == null) {
				entry.destType = Attribute.DataType.string;
			} else if (targetType.equalsIgnoreCase("string")) {
				entry.destType = Attribute.DataType.string;
			} else if (targetType.equalsIgnoreCase("int")) {
				entry.destType = Attribute.DataType.intNum;
			} else if (targetType.equalsIgnoreCase("long")) {
				entry.destType = Attribute.DataType.longNum;
			} else if (targetType.equalsIgnoreCase("date")) {
				entry.destType = Attribute.DataType.date;
			} else if (targetType.equalsIgnoreCase("timestamp")) {
				entry.destType = Attribute.DataType.timeStamp;
			} else {
				entry.destType = Attribute.DataType.string;
			}

			this.map.put(name, entry);
			this.attributes.add(name);

		}
	}

	public MapIdentity(TargetType mapping) throws ProvisioningException {
		map = new HashMap<String,MappingEntry>();
		Iterator<TargetAttributeType> it = mapping.getTargetAttribute().iterator();
		this.attributes = new HashSet<String>();
		while (it.hasNext()) {
			TargetAttributeType mapper = it.next();
			MappingEntry entry = new MappingEntry();
			if (mapper.getSourceType().equalsIgnoreCase("static")) {
				entry.type = MappingType.staticValue;
				entry.staticValue = mapper.getSource();
			} else if (mapper.getSourceType().equalsIgnoreCase("user")) {
				entry.type = MappingType.userAttr;
				entry.userAttr = mapper.getSource();
			} else if (mapper.getSourceType().equalsIgnoreCase("custom")) {
				entry.type = MappingType.custom;
				try {
					
					
					String className = mapper.getSource();
					createCustomMapping(entry, className);
				} catch (Exception e) {
					throw new ProvisioningException("Could not load custom mapping",e);
				}
			} else if (mapper.getSourceType().equalsIgnoreCase("composite")) {
				entry.type = MappingType.composite;
				entry.composite = new ArrayList<MappingPart>();
				int lastIndex = 0;
				int index = mapper.getSource().indexOf('$');
				while (index >= 0) {
					MappingPart mp = new MappingPart();
					mp.isAttr = false;
					mp.val = mapper.getSource().substring(lastIndex,index);
					entry.composite.add(mp);
					
					lastIndex = mapper.getSource().indexOf('}',index) + 1;
					String reqName = mapper.getSource().substring(index + 2,lastIndex - 1);
					mp = new MappingPart();
					mp.isAttr = true;
					mp.val = reqName;
					entry.composite.add(mp);
					
					index = mapper.getSource().indexOf('$',index+1);
				}
				MappingPart mp = new MappingPart();
				mp.isAttr = false;
				mp.val = mapper.getSource().substring(lastIndex);
				entry.composite.add(mp);
				
			}
			
			if (mapper.getTargetType() == null) {
				entry.destType = Attribute.DataType.string;
			} else if (mapper.getTargetType().equalsIgnoreCase("string")) {
				entry.destType = Attribute.DataType.string;
			} else if (mapper.getTargetType().equalsIgnoreCase("int")) {
				entry.destType = Attribute.DataType.intNum;
			} else if (mapper.getTargetType().equalsIgnoreCase("long")) {
				entry.destType = Attribute.DataType.longNum;
			} else if (mapper.getTargetType().equalsIgnoreCase("date")) {
				entry.destType = Attribute.DataType.date;
			} else if (mapper.getTargetType().equalsIgnoreCase("timestamp")) {
				entry.destType = Attribute.DataType.timeStamp;
			} else {
				entry.destType = Attribute.DataType.string;
			}
			
			this.map.put(mapper.getName(), entry);
			this.attributes.add(mapper.getName());
		}
	}
	
	
	
	public MapIdentity(ProvisionMappingsType mappings) throws ProvisioningException {
		map = new HashMap<String,MappingEntry>();
		Iterator<ProvisionMappingType> it = mappings.getMapping().iterator();
		this.attributes = new HashSet<String>();
		while (it.hasNext()) {
			ProvisionMappingType mapper = it.next();
			//System.out.println("Source Type : " + mapper.getSourceType());
			MappingEntry entry = new MappingEntry();
			if (mapper.getSourceType().equalsIgnoreCase("static")) {
				entry.type = MappingType.staticValue;
				entry.staticValue = mapper.getTargetAttributeSource();
			} else if (mapper.getSourceType().equalsIgnoreCase("user")) {
				entry.type = MappingType.userAttr;
				entry.userAttr = mapper.getTargetAttributeSource();
			} else if (mapper.getSourceType().equalsIgnoreCase("custom")) {
				entry.type = MappingType.custom;
				try {
					String className = mapper.getTargetAttributeSource();
					createCustomMapping(entry, className);
				} catch (Exception e) {
					throw new ProvisioningException("Could not load custom mapping",e);
				}
			} else if (mapper.getSourceType().equalsIgnoreCase("composite")) {
				entry.type = MappingType.composite;
				entry.composite = new ArrayList<MappingPart>();
				int lastIndex = 0;
				int index = mapper.getTargetAttributeSource().indexOf('$');
				while (index >= 0) {
					MappingPart mp = new MappingPart();
					mp.isAttr = false;
					mp.val = mapper.getTargetAttributeSource().substring(lastIndex,index);
					entry.composite.add(mp);
					
					lastIndex = mapper.getTargetAttributeSource().indexOf('}',index) + 1;
					String reqName = mapper.getTargetAttributeSource().substring(index + 2,lastIndex - 1);
					mp = new MappingPart();
					mp.isAttr = true;
					mp.val = reqName;
					entry.composite.add(mp);
					
					index = mapper.getTargetAttributeSource().indexOf('$',index+1);
				}
				MappingPart mp = new MappingPart();
				mp.isAttr = false;
				mp.val = mapper.getTargetAttributeSource().substring(lastIndex);
				entry.composite.add(mp);
				
			}
			
			this.map.put(mapper.getTargetAttributeName(), entry);
			this.attributes.add(mapper.getTargetAttributeName());
		}
	}

	public MapIdentity(IdpMappingType mappings) throws ProvisioningException {
		map = new HashMap<String,MappingEntry>();
		Iterator<ProvisionMappingType> it = mappings.getMapping().iterator();
		this.attributes = new HashSet<String>();
		while (it.hasNext()) {
			ProvisionMappingType mapper = it.next();
			MappingEntry entry = new MappingEntry();
			if (mapper.getSourceType().equalsIgnoreCase("static")) {
				entry.type = MappingType.staticValue;
				entry.staticValue = mapper.getTargetAttributeSource();
			} else if (mapper.getSourceType().equalsIgnoreCase("user")) {
				entry.type = MappingType.userAttr;
				entry.userAttr = mapper.getTargetAttributeSource();
			} else if (mapper.getSourceType().equalsIgnoreCase("custom")) {
				entry.type = MappingType.custom;
				try {
					String className = mapper.getTargetAttributeSource();
					createCustomMapping(entry, className);
				} catch (Exception e) {
					throw new ProvisioningException("Could not load custom mapping",e);
				}
			} else if (mapper.getSourceType().equalsIgnoreCase("composite")) {
				entry.type = MappingType.composite;
				entry.composite = new ArrayList<MappingPart>();
				int lastIndex = 0;
				int index = mapper.getTargetAttributeSource().indexOf('$');
				while (index >= 0) {
					MappingPart mp = new MappingPart();
					mp.isAttr = false;
					mp.val = mapper.getTargetAttributeSource().substring(lastIndex,index);
					entry.composite.add(mp);
					
					lastIndex = mapper.getTargetAttributeSource().indexOf('}',index) + 1;
					String reqName = mapper.getTargetAttributeSource().substring(index + 2,lastIndex - 1);
					mp = new MappingPart();
					mp.isAttr = true;
					mp.val = reqName;
					entry.composite.add(mp);
					
					index = mapper.getTargetAttributeSource().indexOf('$',index+1);
				}
				MappingPart mp = new MappingPart();
				mp.isAttr = false;
				mp.val = mapper.getTargetAttributeSource().substring(lastIndex);
				entry.composite.add(mp);
				
			}
			
			this.map.put(mapper.getTargetAttributeName(), entry);
			this.attributes.add(mapper.getTargetAttributeName());
		}
		
		this.strict = mappings.isStrict();
	}
	private void createCustomMapping(MappingEntry entry, String className)
			throws InstantiationException, IllegalAccessException, ClassNotFoundException {
		List<String> params = new ArrayList<String>();
		int paramBreak = className.indexOf('|');
		if (paramBreak > 0) {
			String paramVals = className.substring(paramBreak + 1);
			className = className.substring(0,paramBreak);
			
			StringTokenizer toker = new StringTokenizer(paramVals,",",false);
			while (toker.hasMoreTokens()) {
				params.add(toker.nextToken());
			}
		}
		entry.mapping = (CustomMapping) Class.forName(className).newInstance();
		String[] paramsarray = new String[params.size()];
		entry.mapping.setParams(params.toArray(paramsarray));
	}


	public User mapUser(User userObj) throws ProvisioningException {
		return this.mapUser(userObj, this.strict);
	}
	
	public User mapUser(User userObj,boolean strict) throws ProvisioningException {
		return this.mapUser(userObj,strict,null,null);
	}


	
	public void mapUser(PostSearchEntryInterceptorChain chain,Entry entry, DistinguishedName base, Int scope,
			Filter filter, ArrayList<net.sourceforge.myvd.types.Attribute> attributes2, Bool typesOnly, LDAPSearchConstraints constraints) {
		
		for (String name : this.map.keySet()) {
			MappingEntry mapping = this.map.get(name);
			
			LDAPAttribute ldapAttr = new  LDAPAttribute(name);
			switch (mapping.type) {
				case staticValue:
					try {
						ldapAttr.addValue(mapping.staticValue.getBytes("UTF-8"));
					} catch (UnsupportedEncodingException e) {
						
					}
					break;
				case userAttr:
					LDAPAttribute source = entry.getEntry().getAttribute(mapping.userAttr);
					if (source != null) {
						ldapAttr.setAllValues(source.getAllValues());
					}
					break;
					
				case custom:
					User srcUser = new User(entry.getEntry());
					Attribute mappedUser = mapping.mapping.doMapping(srcUser, name);
					if (mappedUser != null) {
						for (String val : mappedUser.getValues()) {
							try {
								ldapAttr.addValue(val.getBytes("UTF-8"));
							} catch (UnsupportedEncodingException e) {
								
							}
						}
					}
					break;
					
				case composite:
					StringBuilder b = new StringBuilder();
					for (MappingPart mp : mapping.composite) {
						 if (mp.isAttr) {
							 LDAPAttribute attr = entry.getEntry().getAttribute(mp.val);
							 
							 if (attr != null) {
								b.append(attr.getStringValue());
							 }
						 } else {
							 b.append(mp.val);
						 }
					 }
					
					 String newVal = b.toString();
					try {
						ldapAttr.addValue(b.toString().getBytes("UTF-8"));
					} catch (UnsupportedEncodingException e) {
						
					}
					 break;
					
			}
			
			if (ldapAttr.getAllValues().size() > 0) {
				if (entry.getEntry().getAttributeSet().getAttribute(ldapAttr.getName()) != null) {
					entry.getEntry().getAttributeSet().remove(ldapAttr.getName());
				}
				entry.getEntry().getAttributeSet().add(ldapAttr);
			}
			
		}
		
	}
	
	public User mapUser(User userObj,boolean strict,Map<String,Object> request,WorkflowTask task) throws ProvisioningException {
		User newUser = new User(userObj.getUserID());
		newUser.setPassword(userObj.getPassword());
		newUser.getGroups().addAll(userObj.getGroups());
		
		HashSet<String> mapped = new HashSet<String>();
		
		Iterator<String> names = this.map.keySet().iterator();
		while (names.hasNext()) {
			String name = names.next();
			String origName = name;
			if (request != null) {
				name = task.renderTemplate(name, request);
			}
			
			
			
			MappingEntry mapping = this.map.get(origName);
			
			
			
			Attribute newAttrib;
			
			switch (mapping.type) {
				case staticValue : 
								   if (name.equalsIgnoreCase("TREMOLO_USER_ID")) {
									   newUser.setUserID(mapping.staticValue);
								   } else {
									   newAttrib = new Attribute(name);
									   newAttrib.setDataType(mapping.destType);
									   if (request != null) {
										   newAttrib.getValues().add(task.renderTemplate(mapping.staticValue,request));
									   } else {
										   newAttrib.getValues().add(mapping.staticValue);
									   }
									   newUser.getAttribs().put(name, newAttrib);
								   }
								   
								   break;
								   
				case userAttr : newAttrib = new Attribute(name);
								newAttrib.setDataType(mapping.destType);
								String attrName = mapping.userAttr;
								
								if (request != null) {
									attrName = task.renderTemplate(attrName, request);
								}
								
								if (logger.isDebugEnabled()) {
									logger.debug("Attribute Name : '" + attrName + "' + '" + userObj.getAttribs().containsKey(attrName) + "'");
								}
								
								if (name.equalsIgnoreCase("TREMOLO_USER_ID")) {
									newUser.setUserID(userObj.getAttribs().get(attrName).getValues().get(0));
								} else {
									if (attrName.equalsIgnoreCase("TREMOLO_USER_ID")) {
										newAttrib.getValues().add(userObj.getUserID());
										newUser.getAttribs().put(name, newAttrib);
									} else if (userObj.getAttribs().containsKey(attrName)) {
										newAttrib.getValues().addAll(userObj.getAttribs().get(attrName).getValues());
										newUser.getAttribs().put(name, newAttrib);
									}
								}
								
								
				   				
				   				
				   				break;
				   				
				case custom : 	if (name.equalsIgnoreCase("TREMOLO_USER_ID")) {
									newUser.setUserID(mapping.mapping.doMapping(userObj, name).getValues().get(0));
								} else {
									newAttrib = mapping.mapping.doMapping(userObj, name);
									if (newAttrib != null) {
										newAttrib.setDataType(mapping.destType);
										newUser.getAttribs().put(name, newAttrib);
									}

								}
					            
				   				break;
				
				case composite : StringBuffer b = new StringBuffer();
								 for (MappingPart mp : mapping.composite) {
									 if (mp.isAttr) {
										 if (userObj.getAttribs().containsKey(mp.val)) {
											b.append(userObj.getAttribs().get(mp.val).getValues().get(0));
										 }
									 } else {
										 b.append(mp.val);
									 }
								 }
								
								 String newVal = b.toString();
								 if (request != null) {
									 newVal = task.renderTemplate(newVal, request);
								 }
								 
								 if (name.equalsIgnoreCase("TREMOLO_USER_ID")) {
									 newUser.setUserID(newVal);
								 } else {
									 newAttrib = new Attribute(name);
									 newAttrib.setDataType(mapping.destType);
									 newAttrib.getValues().add(newVal);
									 newUser.getAttribs().put(name, newAttrib);
								 }
								 
								 
								 break;
			}
			
			mapped.add(name);
			
		}
		
		if (! strict) {
			names = userObj.getAttribs().keySet().iterator();
			while (names.hasNext()) {
				String name = names.next();
				if (! mapped.contains(name)) {
					Attribute newAttrib = new Attribute(name);
					
					newAttrib.getValues().addAll(userObj.getAttribs().get(name).getValues());
					newUser.getAttribs().put(name, newAttrib);
				}
			}
		} else {
			
		}
		
		newUser.setResync(userObj.isResync());
		newUser.setKeepExternalAttrs(userObj.isKeepExternalAttrs());
		
		return newUser;
	}

	public HashSet<String> getAttributes() {
		return this.attributes;
	}
	public HashMap<String, MappingEntry> getMap() {
		return map;
	}
	public void setMap(HashMap<String, MappingEntry> map) {
		this.map = map;
	}
	public boolean isStrict() {
		return strict;
	}
	public void setStrict(boolean strict) {
		this.strict = strict;
	}
	public void setAttributes(HashSet<String> attributes) {
		this.attributes = attributes;
	}
	
	
	public String getSourceAttributeName(String mapTo) {
		MappingEntry mapFrom = this.map.get(mapTo);
		if (mapFrom != null) {
			if (mapFrom.type == MappingType.userAttr) {
				return mapFrom.userAttr;
			}
		}
		
		return null;
	}
	
	
}

class MappingEntry implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 8177213218546735985L;
	MappingType type;
	Attribute.DataType destType;
	String userAttr;
	String staticValue;
	CustomMapping mapping;
	List<MappingPart> composite;
}

class MappingPart implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = -8283736662740071079L;
	boolean isAttr;
	String val;
}
