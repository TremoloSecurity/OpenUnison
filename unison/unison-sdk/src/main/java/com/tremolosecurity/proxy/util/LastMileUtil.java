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


package com.tremolosecurity.proxy.util;

import javax.crypto.SecretKey;

import org.apache.http.client.methods.HttpRequestBase;
import org.joda.time.DateTime;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.lastmile.LastMile;
import com.tremolosecurity.saml.Attribute;

public class LastMileUtil {
	public static void addLastMile(ConfigManager cfg,String username,String userNameAttr,HttpRequestBase req,String keyAlias,boolean addHeader) throws Exception {
		if (! addHeader) {
			return;
		}
		
		String uri = req.getURI().getPath();
		DateTime now = new DateTime();
		DateTime notBefore = now.minus(5 * 60 * 1000);
		DateTime notAfter = now.plus(5 * 60 * 1000);
		
		LastMile lm = new LastMile(uri,notBefore,notAfter,0,"nochain");
		
		lm.getAttributes().add(new Attribute(userNameAttr,username));
		
		SecretKey sk = cfg.getSecretKey(keyAlias);
		String header = lm.generateLastMileToken(sk);
		
		req.addHeader("tremoloHeader", header);
	}
}
