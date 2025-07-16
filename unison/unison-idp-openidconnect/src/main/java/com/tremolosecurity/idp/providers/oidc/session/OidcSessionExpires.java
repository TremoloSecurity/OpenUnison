/*******************************************************************************
 * Copyright 2019 Tremolo Security, Inc.
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
package com.tremolosecurity.idp.providers.oidc.session;

import org.apache.log4j.Logger;

import com.tremolosecurity.idp.providers.oidc.model.OidcSessionState;
import com.tremolosecurity.idp.providers.oidc.model.OidcSessionStore;
import com.tremolosecurity.proxy.ExternalSessionExpires;

public class OidcSessionExpires implements ExternalSessionExpires {
	static Logger logger = Logger.getLogger(OidcSessionExpires.class);
	String sessionid;
	OidcSessionStore sessions;
	
	
	public OidcSessionExpires(String sessionid,OidcSessionStore sessions) {
		this.sessionid = sessionid;
		this.sessions = sessions;
	}

//	@Override
//	public long getExpires() {
//		try {
//			OidcSessionState session = sessions.getSession(this.sessionid);
//			if (session != null) {
//				return session.getExpires().getMillis();
//			} else {
//				return 0;
//			}
//		} catch (Exception e) {
//			logger.warn("Could not load session",e);
//			return 0;
//		}
//
//	}

	@Override
	public boolean isExpired(long timeout, long lastAccessed) {
		return this.isExpired();
	}

	@Override
	public boolean isExpired() {
		try {
			OidcSessionState session = sessions.getSession(this.sessionid);
			if (session != null) {
				return session.getExpires().getMillis() < System.currentTimeMillis();
			} else {
				return true;
			}
		} catch (Exception e) {
			logger.warn("Could not load session",e);
			return true;
		}
	}

	@Override
	public long getEstimatedExpires() {
		return 0;
	}
}
