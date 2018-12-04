/*
Copyright 2015, 2016 Tremolo Security, Inc.

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


package com.tremolosecurity.proxy.myvd.inserts.otp;


import java.util.ArrayList;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;













import com.google.gson.Gson;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.util.DN;
import com.tremolosecurity.json.Token;
import com.tremolosecurity.proxy.auth.otp.TOTPKey;
import com.tremolosecurity.server.GlobalEntries;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder;

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
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;

public class AuthTOTPInsert implements Insert {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(AuthTOTPInsert.class.getName());
	
	String name;
	String encyrptionKey;
	String attribute;
	private NameSpace nameSpace;
	int window;
	
	public String getName() {
		return name;
	}

	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		this.name = name;
		this.encyrptionKey = props.getProperty("encryptionKey");
		logger.info("Encryption Key : '" + encyrptionKey + "'");
		this.attribute = props.getProperty("attribute");
		logger.info("Key attribute : '" + this.attribute + "'");
		
		String w = props.getProperty("window");
		if (w == null) {
			logger.warn("No window specified, defaulting to 3");
			this.window = 3;
		} else {
			this.window = Integer.parseInt(w);
		}
		
		logger.info("Window size : '" + this.window + "'");
		
		this.nameSpace = nameSpace;
	}

	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextAdd(entry, constraints);

	}

	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		
		DistinguishedName localdn = new DistinguishedName(new DN(dn.getDN().toString()));
		
		logger.debug("In bind");
		
		SearchInterceptorChain schain = chain.createSearchChain();
		ArrayList<Attribute> searchattrs = new ArrayList<Attribute>();
		//searchattrs.add(new Attribute(this.attribute));
		
		logger.debug("searching...");
		
		Results res = new Results(chain.getInterceptors(),chain.getPos());
		logger.debug("Created res");
		schain.nextSearch(localdn, new Int(0), new Filter("(objectClass=*)"), searchattrs, new Bool(false), res, new LDAPSearchConstraints());
		logger.debug("ran search");
		res.start();
		logger.debug("res started");
		
		if (! res.hasMore()) {
			logger.debug("user not found");
			throw new LDAPException("Could not find " + localdn.getDN().toString(),LDAPException.NO_SUCH_OBJECT,"Could not find " + localdn.getDN().toString());
		}
		
		logger.debug("user found");
		
		LDAPEntry entry = res.next().getEntry();
		LDAPAttribute key = entry.getAttribute(this.attribute);
		if (key == null) {
			logger.debug("No key");
			throw new LDAPException("Invalid Credentials",LDAPException.NO_SUCH_OBJECT,"Invalid Credentials");
		}
		
		try {
			String keyjson = key.getStringValue();
			if (logger.isDebugEnabled()) logger.debug("token json : '" + keyjson + "'");
			Gson gson = new Gson();
			Token token = gson.fromJson(new String(Base64.decode(keyjson)), Token.class);
			byte[] iv = org.bouncycastle.util.encoders.Base64.decode(token.getIv());
			IvParameterSpec spec =  new IvParameterSpec(iv);
		    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, GlobalEntries.getGlobalEntries().getConfigManager().getSecretKey(this.encyrptionKey),spec);
			
		    
			byte[] encBytes = org.bouncycastle.util.encoders.Base64.decode(token.getEncryptedRequest());
			String totpJson = new String(cipher.doFinal(encBytes));
			if (logger.isDebugEnabled()) logger.debug("totp json : '" + totpJson + "'");
			TOTPKey totp = gson.fromJson(totpJson, TOTPKey.class);
			
			
			GoogleAuthenticatorConfigBuilder b = new GoogleAuthenticatorConfigBuilder();
			b.setWindowSize(this.window);
			
			GoogleAuthenticatorConfig cfg = b.build();
			
			GoogleAuthenticator ga = new GoogleAuthenticator(cfg);
			
			String spwd = new String(pwd.getValue());
			
			if (spwd.indexOf(':') == -1) {
				logger.debug("no colon");
				throw new LDAPException("Invalid credentials",LDAPException.INVALID_CREDENTIALS,"Invalid Credentials");
			}
			
			String scode = spwd.substring(spwd.indexOf(':') + 1);
			
			int code = Integer.parseInt(scode);
			
			
			
			if (! ga.authorize(totp.getSecretKey(), code)) {
				logger.debug("Verify failed");
				throw new LDAPException("Invalid credentials",LDAPException.INVALID_CREDENTIALS,"Invalid Credentials");
			}
			logger.debug("verify succeeded");
			pwd.setValue(spwd.substring(0,spwd.indexOf(':')).getBytes("UTF-8"));
			chain.nextBind(dn, pwd, constraints);
			
		} catch (Exception e) {
			logger.error("Could not work",e);
			if (e instanceof LDAPException) {
				throw ((LDAPException) e);
			} else {
				throw new LDAPException("Could not decrypt key",LDAPException.OPERATIONS_ERROR,"Could not decrypt key",e);
			}
		}

	}

	public void compare(CompareInterceptorChain chain, DistinguishedName dn,
			Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		chain.nextCompare(dn, attrib, constraints);

	}

	public void delete(DeleteInterceptorChain chain, DistinguishedName dn,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextDelete(dn, constraints);

	}

	public void extendedOperation(ExetendedOperationInterceptorChain chain,
			ExtendedOperation op, LDAPConstraints constraints)
			throws LDAPException {
		chain.nextExtendedOperations(op, constraints);

	}

	public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
			ArrayList<LDAPModification> mods, LDAPConstraints constraints)
			throws LDAPException {
		chain.nextModify(dn, mods, constraints);

	}

	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes,
			Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		chain.nextSearch(base, scope, filter, attributes, typesOnly, results, constraints);

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, Bool deleteOldRdn,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextRename(dn, newRdn, deleteOldRdn, constraints);

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, DistinguishedName newParentDN,
			Bool deleteOldRdn, LDAPConstraints constraints)
			throws LDAPException {
		chain.nextRename(dn, newRdn, newParentDN, deleteOldRdn, constraints);

	}

	public void postSearchEntry(PostSearchEntryInterceptorChain chain,
			Entry entry, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		chain.nextPostSearchEntry(entry, base, scope, filter, attributes, typesOnly, constraints);

	}

	public void postSearchComplete(PostSearchCompleteInterceptorChain chain,
			DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		chain.nextPostSearchComplete(base, scope, filter, attributes, typesOnly, constraints);

	}

	public void shutdown() {
		

	}

}
