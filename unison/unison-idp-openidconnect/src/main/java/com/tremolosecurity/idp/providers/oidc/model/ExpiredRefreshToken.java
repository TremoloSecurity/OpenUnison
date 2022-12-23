/*******************************************************************************
 * Copyright (c) 2022 Tremolo Security, Inc.
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
package com.tremolosecurity.idp.providers.oidc.model;

import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.json.simple.JSONObject;

public class ExpiredRefreshToken {
	String token;
	DateTime expired;
	
	static Logger logger = Logger.getLogger(ExpiredRefreshToken.class.getName());
	
	public ExpiredRefreshToken(String token,DateTime expired) {
		this.token = token;
		this.expired = expired;
	}
	
	public ExpiredRefreshToken(JSONObject obj) {
		this.token = (String) obj.get("token");
		this.expired = DateTime.parse((String) obj.get("expired"),org.joda.time.format.ISODateTimeFormat.dateHourMinuteSecondMillis());
	}

	public String getToken() {
		return token;
	}

	public DateTime getExpired() {
		return expired;
	}
	
	public JSONObject toJSONObject() {
		JSONObject obj = new JSONObject();
		obj.put("token", this.token);
		obj.put("expired", this.expired.toString(org.joda.time.format.ISODateTimeFormat.dateHourMinuteSecondMillis()));
		
		return obj;
	}
	
	public boolean isStillInGracePeriod(int gracePeriodMillis) {
		if (logger.isDebugEnabled()) {
			logger.debug(String.format("Grace period %s / expired %s / expired+graceperiod %s / now: %s",gracePeriodMillis,this.expired.toString(),this.expired.plusMillis(gracePeriodMillis),DateTime.now().toString()));
		}
		return this.expired.plusMillis(gracePeriodMillis).isAfterNow();
	}
	
	
	
	
}
