/*******************************************************************************
 * Copyright 2018 Tremolo Security, Inc.
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
package com.tremolosecurity.unison.openshiftv3.myvd;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Properties;

import org.apache.logging.log4j.Logger;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.util.DN;
import com.novell.ldap.util.RDN;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.service.util.TremoloUser;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

import net.sourceforge.myvd.chain.AddInterceptorChain;
import net.sourceforge.myvd.chain.BindInterceptorChain;
import net.sourceforge.myvd.chain.CompareInterceptorChain;
import net.sourceforge.myvd.chain.DeleteInterceptorChain;
import net.sourceforge.myvd.chain.ExetendedOperationInterceptorChain;
import net.sourceforge.myvd.chain.ModifyInterceptorChain;
import net.sourceforge.myvd.chain.PostSearchCompleteInterceptorChain;
import net.sourceforge.myvd.chain.PostSearchEntryInterceptorChain;
import net.sourceforge.myvd.chain.RenameInterceptorChain;
import net.sourceforge.myvd.chain.SearchInterceptorChain;
import net.sourceforge.myvd.core.NameSpace;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.types.Attribute;
import net.sourceforge.myvd.types.Bool;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.types.ExtendedOperation;
import net.sourceforge.myvd.types.Filter;
import net.sourceforge.myvd.types.FilterNode;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;
import net.sourceforge.myvd.util.EntryUtil;
import net.sourceforge.myvd.util.IteratorEntrySet;

/**
 * K8sCrdInsert
 */
public class OpenShiftInsert implements Insert {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(OpenShiftInsert.class.getName());

    DN baseDN;
	
	String name;
	
	String osTarget;
	
	
	

    @Override
    public String getName() {
        return name;
    }

    @Override
    public void configure(String name, Properties props, NameSpace nameSpace) throws LDAPException {
        this.name = name;
        this.baseDN = new DN(nameSpace.getBase().getDN().toString());
        
        
        
        this.osTarget = props.getProperty("osTargetName");
        

    }

    @Override
    public void add(AddInterceptorChain chain, Entry entry, LDAPConstraints constraints) throws LDAPException {
        throw new LDAPException("Unsupported", LDAPException.UNWILLING_TO_PERFORM, LDAPException.resultCodeToString(LDAPException.UNWILLING_TO_PERFORM));
    }

    @Override
    public void bind(BindInterceptorChain chain, DistinguishedName dn, Password pwd, LDAPConstraints constraints)
            throws LDAPException {
                throw new LDAPException("Unsupported", LDAPException.UNWILLING_TO_PERFORM, LDAPException.resultCodeToString(LDAPException.UNWILLING_TO_PERFORM));

    }

    @Override
    public void compare(CompareInterceptorChain chain, DistinguishedName dn, Attribute attrib,
            LDAPConstraints constraints) throws LDAPException {
                throw new LDAPException("Unsupported", LDAPException.UNWILLING_TO_PERFORM, LDAPException.resultCodeToString(LDAPException.UNWILLING_TO_PERFORM));

    }

    @Override
    public void delete(DeleteInterceptorChain chain, DistinguishedName dn, LDAPConstraints constraints)
            throws LDAPException {
                throw new LDAPException("Unsupported", LDAPException.UNWILLING_TO_PERFORM, LDAPException.resultCodeToString(LDAPException.UNWILLING_TO_PERFORM));

    }

    @Override
    public void extendedOperation(ExetendedOperationInterceptorChain chain, ExtendedOperation op,
            LDAPConstraints constraints) throws LDAPException {
                throw new LDAPException("Unsupported", LDAPException.UNWILLING_TO_PERFORM, LDAPException.resultCodeToString(LDAPException.UNWILLING_TO_PERFORM));

    }

    @Override
    public void modify(ModifyInterceptorChain chain, DistinguishedName dn, ArrayList<LDAPModification> mods,
            LDAPConstraints constraints) throws LDAPException {
                throw new LDAPException("Unsupported", LDAPException.UNWILLING_TO_PERFORM, LDAPException.resultCodeToString(LDAPException.UNWILLING_TO_PERFORM));

    }

    @Override
    public void search(SearchInterceptorChain chain, DistinguishedName base, Int scope, Filter filter,
            ArrayList<Attribute> attributes, Bool typesOnly, Results results, LDAPSearchConstraints constraints)
            throws LDAPException {
    	
    	OpenShiftTarget os = null;
		try {
			os = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(this.osTarget).getProvider();
		} catch (ProvisioningException e1) {
			logger.error("Could not retrieve kubernetes target",e1);
			throw new LDAPException("Could not connect to kubernetes",LDAPException.OPERATIONS_ERROR,LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR));
		}

        //base search
        if (scope.getValue() == 0) {
            //  dir root
        	if (base.getDN().equals(this.baseDN)) {
        		ArrayList<Entry> ret = new ArrayList<Entry>();
        		ret.add(new Entry(EntryUtil.createBaseEntry(this.baseDN)));
        		chain.addResult(results, new IteratorEntrySet(ret.iterator()), base, scope, filter, attributes, typesOnly, constraints);
        		return;
        	} else {
        		String name = ((RDN)base.getDN().getRDNs().get(0)).getValue();
        		loadUserFromOpenShift(chain, base, scope, filter, attributes, typesOnly, results, constraints, os, name,base.getDN().toString(),true);
				return;
        		
        	}

            
        } else if (scope.getValue() == 1) {
        	if (base.getDN().equals(this.baseDN)) {
        		String name = userFromFilter(filter.getRoot());
        		
        		loadUserFromOpenShift(chain, base, scope, filter, attributes, typesOnly, results, constraints, os, name,new StringBuilder().append("uid=").append(name).append(",").append(base.getDN().toString()).toString(),false);
				return;
        	}
        } else {
        	//only subtree left
        	String name = userFromFilter(filter.getRoot());
    		
    		loadUserFromOpenShift(chain, base, scope, filter, attributes, typesOnly, results, constraints, os, name,new StringBuilder().append("uid=").append(name).append(",").append(this.baseDN.toString()).toString(),false);
			return;
        }

    }

	private void loadUserFromOpenShift(SearchInterceptorChain chain, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly, Results results, LDAPSearchConstraints constraints,
			OpenShiftTarget k8s, String name,String entryDN,boolean exceptionOnNotFound) throws LDAPException {
		
		User user;
		try {
			HashSet<String> toFind = new HashSet<String>();
			toFind.add("fullName");
			user = k8s.findUser(name, toFind, new HashMap<String,Object>());
		} catch (ProvisioningException e1) {
			throw new LDAPException("Could not load user",LDAPException.OPERATIONS_ERROR,LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),e1);
		}
		
		
		
		ArrayList<Entry> ret = new ArrayList<Entry>();
		try {
			HttpCon con = k8s.createClient();
			
			try {
				
				
				
				if (user == null) {
					if (exceptionOnNotFound) {
						throw new LDAPException("user not found",LDAPException.NO_SUCH_OBJECT,LDAPException.resultCodeToString(LDAPException.NO_SUCH_OBJECT));
					} 
				} else {
				
				
					LDAPEntry ldapUser = new LDAPEntry(entryDN);
					ldapUser.getAttributeSet().add(new LDAPAttribute("objectClass",GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getUserObjectClass()));
					ldapUser.getAttributeSet().add(new LDAPAttribute("uid",user.getUserID()));
					
					if (user.getAttribs().get("fullName") != null) {
						ldapUser.getAttributeSet().add(new LDAPAttribute("fullName",user.getAttribs().get("fullName").getValues().get(0)));
					}
					
					
					if (user.getGroups().size() > 0) {
						LDAPAttribute groups = new LDAPAttribute("groups");
						for (String group : user.getGroups()) {
							groups.addValue(group);
						}
						
						ldapUser.getAttributeSet().add(groups);
					}
					
					ret.add(new Entry(ldapUser));
				}
				
				
				
				chain.addResult(results, new IteratorEntrySet(ret.iterator()), base, scope, filter, attributes, typesOnly, constraints);
				return;
				
				
			} finally {
				con.getHttp().close();
				con.getBcm().close();
			}
			
		} catch (LDAPException le) {
			
			throw le;
		} catch (Exception e) {
			logger.error("Could not search k8s",e);
			throw new LDAPException("Error searching kubernetes",LDAPException.OPERATIONS_ERROR,LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),e);
			
		}
	}

    @Override
    public void rename(RenameInterceptorChain chain, DistinguishedName dn, DistinguishedName newRdn, Bool deleteOldRdn,
			LDAPConstraints constraints) throws LDAPException {
                throw new LDAPException("Unsupported", LDAPException.UNWILLING_TO_PERFORM, LDAPException.resultCodeToString(LDAPException.UNWILLING_TO_PERFORM));
	}

	@Override
	public void rename(RenameInterceptorChain chain, DistinguishedName dn, DistinguishedName newRdn,
			DistinguishedName newParentDN, Bool deleteOldRdn, LDAPConstraints constraints) throws LDAPException {
                throw new LDAPException("Unsupported", LDAPException.UNWILLING_TO_PERFORM, LDAPException.resultCodeToString(LDAPException.UNWILLING_TO_PERFORM));
	}

	@Override
	public void postSearchEntry(PostSearchEntryInterceptorChain chain, Entry entry, DistinguishedName base, Int scope,
			Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints)
			throws LDAPException {
		
	}

	@Override
	public void postSearchComplete(PostSearchCompleteInterceptorChain chain, DistinguishedName base, Int scope,
			Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints)
			throws LDAPException {
		
	}

	@Override
	public void shutdown() {
		
	}
	
	private String userFromFilter(FilterNode node) {
		switch (node.getType()) {
			case EQUALS:
				if (node.getName().equalsIgnoreCase("uid")) {
					return node.getValue();
				} else if (node.getName().equalsIgnoreCase("sub")) {
					return OpenShiftTarget.sub2uid(node.getValue());
				}
				break;
			case AND:
			case OR:
				for (FilterNode kid : node.getChildren()) {
					String ret = userFromFilter(kid);
					if (ret != null) {
						return ret;
					}
				}
				break;
			case NOT:
				return userFromFilter(node.getNot());
			default:
				return null;
		}
		return null;
	}

    
}