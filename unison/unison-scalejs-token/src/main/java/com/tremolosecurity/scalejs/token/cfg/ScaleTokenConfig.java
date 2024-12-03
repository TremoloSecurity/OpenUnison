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
	String qrCodeAttribute;
	int warnMinutesLeft;
	
	

	
	String themePrimaryMain;
	String themePrimaryDark;
	String themePrimaryLight;
	
	String themeSecondaryMain;
	String themeSecondaryDark;
	String themeSecondaryLight;
	
	String headerTitle;
	
	String errorColor;
	
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



	public String getQrCodeAttribute() {
		return qrCodeAttribute;
	}



	public void setQrCodeAttribute(String qrCodeAttribute) {
		this.qrCodeAttribute = qrCodeAttribute;
	}



	public int getWarnMinutesLeft() {
		return warnMinutesLeft;
	}



	public void setWarnMinutesLeft(int warnMinutesLeft) {
		this.warnMinutesLeft = warnMinutesLeft;
	}



	public String getThemePrimaryMain() {
		return themePrimaryMain;
	}



	public void setThemePrimaryMain(String themePrimaryMain) {
		this.themePrimaryMain = themePrimaryMain;
	}



	public String getThemePrimaryDark() {
		return themePrimaryDark;
	}



	public void setThemePrimaryDark(String themePrimaryDark) {
		this.themePrimaryDark = themePrimaryDark;
	}



	public String getThemePrimaryLight() {
		return themePrimaryLight;
	}



	public void setThemePrimaryLight(String themePrimaryLight) {
		this.themePrimaryLight = themePrimaryLight;
	}



	public String getThemeSecondaryMain() {
		return themeSecondaryMain;
	}



	public void setThemeSecondaryMain(String themeSecondaryMain) {
		this.themeSecondaryMain = themeSecondaryMain;
	}



	public String getThemeSecondaryDark() {
		return themeSecondaryDark;
	}



	public void setThemeSecondaryDark(String themeSecondaryDark) {
		this.themeSecondaryDark = themeSecondaryDark;
	}



	public String getThemeSecondaryLight() {
		return themeSecondaryLight;
	}



	public void setThemeSecondaryLight(String themeSecondaryLight) {
		this.themeSecondaryLight = themeSecondaryLight;
	}



	public String getHeaderTitle() {
		return headerTitle;
	}



	public void setHeaderTitle(String headerTitle) {
		this.headerTitle = headerTitle;
	}



	public String getErrorColor() {
		return errorColor;
	}



	public void setErrorColor(String errorColor) {
		this.errorColor = errorColor;
	}
	
	
	
	
}
