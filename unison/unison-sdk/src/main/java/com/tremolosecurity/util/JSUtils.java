/*******************************************************************************
 * Copyright (c) 2023 Tremolo Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.tremolosecurity.util;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.tremolosecurity.provisioning.core.Group;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.server.GlobalEntries;
import net.sourceforge.myvd.types.Filter;
import org.apache.directory.api.ldap.model.filter.FilterParser;
import org.apache.log4j.Logger;


import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Utility class because graalvm js doesn't play well with Java String<->byte[]
 */
public class JSUtils {

	static Logger logger = Logger.getLogger(JSUtils.class);
	public static byte[] string2bytes(String s) {
		try {
			return s.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			return null;
		}
	}
	
	public static String bytes2string(byte[] bytes) {
		return new String(bytes);
	}
	
	public static String base64Decode(String src) {
		return new String(Base64.getDecoder().decode(src));
	}

	public static HttpRequest.BodyPublisher formEncode(String template,String ... values) throws UnsupportedEncodingException {
		String[] transformed = new String[values.length];
		for (int i = 0; i < values.length; i++) {
			transformed[i] = URLEncoder.encode(values[i],"UTF-8");
		}

		String formPost = String.format(template,transformed);
		return HttpRequest.BodyPublishers.ofString(formPost);
	}

	public static boolean checkUserAgainstFilter(User user,String memberOfAttribute,String filter) {
		LDAPEntry ldap = new LDAPEntry("cn=x");
		ldap.getAttributeSet().add(new LDAPAttribute("objectClass",GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getUserObjectClass()));
		user.getAttribs().keySet().forEach(attr -> {
			LDAPAttribute ldapAttribute = new LDAPAttribute(attr);
			user.getAttribs().get(attr).getValues().forEach(val -> {
				ldapAttribute.addValue(val.getBytes(StandardCharsets.UTF_8));
			});
			ldap.getAttributeSet().add(ldapAttribute);
		});

		LDAPAttribute ldapGroups = new LDAPAttribute(memberOfAttribute);
		user.getGroups().forEach(group -> {
			ldapGroups.addValue(group.getBytes(StandardCharsets.UTF_8));
		});
		if (ldapGroups.getAllValues().size() > 0) {
			ldap.getAttributeSet().add(ldapGroups);
		}

        try {
            Filter parsedFilter = new Filter(filter);
			return parsedFilter.getRoot().checkEntry(ldap);
        } catch (LDAPException e) {
            logger.warn("Could not parse filter",e);
			return false;
        }
    }

	public static boolean checkGroupAgainstFilter(Group group, String filter) {
		LDAPEntry ldap = new LDAPEntry("cn=x");
		ldap.getAttributeSet().add(new LDAPAttribute("cn",group.getName()));
		ldap.getAttributeSet().add(new LDAPAttribute("objectClass",GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getGroupObjectClass()));
		group.getAttributes().keySet().forEach(attr -> {
			LDAPAttribute ldapAttribute = new LDAPAttribute(attr);
			group.getAttributes().get(attr).getValues().forEach(val -> {
				ldapAttribute.addValue(val.getBytes(StandardCharsets.UTF_8));
			});
			ldap.getAttributeSet().add(ldapAttribute);
		});

		LDAPAttribute ldapGroups = new LDAPAttribute(GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getGroupMemberAttribute());
		group.getMembers().forEach(member -> {
			ldapGroups.addValue(member.getBytes(StandardCharsets.UTF_8));
		});
		if (ldapGroups.getAllValues().size() > 0) {
			ldap.getAttributeSet().add(ldapGroups);
		}

		try {
			Filter parsedFilter = new Filter(filter);
			return parsedFilter.getRoot().checkEntry(ldap);
		} catch (LDAPException e) {
			logger.warn("Could not parse filter",e);
			return false;
		}
	}
}
