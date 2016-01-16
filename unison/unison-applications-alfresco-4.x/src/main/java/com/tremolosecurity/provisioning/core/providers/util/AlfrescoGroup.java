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


package com.tremolosecurity.provisioning.core.providers.util;

public class AlfrescoGroup {
	String authorityType;
	String shortName;
	String fullName;
	String displayName;
	boolean isRootGroup;
	boolean isAdminGroup;
	String url;
	
	public AlfrescoGroup() {
		
	}

	public String getAuthorityType() {
		return authorityType;
	}

	public void setAuthorityType(String authorityType) {
		this.authorityType = authorityType;
	}

	public String getShortName() {
		return shortName;
	}

	public void setShortName(String shortName) {
		this.shortName = shortName;
	}

	public String getFullName() {
		return fullName;
	}

	public void setFullName(String fullName) {
		this.fullName = fullName;
	}

	public String getDisplayName() {
		return displayName;
	}

	public void setDisplayName(String displayName) {
		this.displayName = displayName;
	}

	public boolean isRootGroup() {
		return isRootGroup;
	}

	public void setRootGroup(boolean isRootGroup) {
		this.isRootGroup = isRootGroup;
	}

	public boolean isAdminGroup() {
		return isAdminGroup;
	}

	public void setAdminGroup(boolean isAdminGroup) {
		this.isAdminGroup = isAdminGroup;
	}

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}
	
	
}
