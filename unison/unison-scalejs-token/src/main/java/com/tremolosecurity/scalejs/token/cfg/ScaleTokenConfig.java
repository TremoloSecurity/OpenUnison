/*******************************************************************************
 * Copyright 2016 Tremolo Security, Inc.
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
package com.tremolosecurity.scalejs.token.cfg;

import com.tremolosecurity.scalejs.cfg.ScaleFrontPage;

public class ScaleTokenConfig {
	
	
	transient String  displayNameAttribute;
	
	ScaleFrontPage frontPage;
	String logoutURL;
	String homeURL;
	
	public ScaleTokenConfig() {
		this.frontPage = new ScaleFrontPage();
	}
	
	
	
	public String getDisplayNameAttribute() {
		return displayNameAttribute;
	}
	public void setDisplayNameAttribute(String displayNameAttribute) {
		this.displayNameAttribute = displayNameAttribute;
	}
	
	
	public ScaleFrontPage getFrontPage() {
		return frontPage;
	}
	public void setFrontPage(ScaleFrontPage frontPage) {
		this.frontPage = frontPage;
	}
	public String getLogoutURL() {
		return logoutURL;
	}
	public void setLogoutURL(String logoutURL) {
		this.logoutURL = logoutURL;
	}



	public String getHomeURL() {
		return homeURL;
	}



	public void setHomeURL(String homeURL) {
		this.homeURL = homeURL;
	}
	
	
	
}
