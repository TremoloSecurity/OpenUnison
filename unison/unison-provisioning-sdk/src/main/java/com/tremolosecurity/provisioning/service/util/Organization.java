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


package com.tremolosecurity.provisioning.service.util;

import java.util.ArrayList;
import java.util.List;

public class Organization {

	String id;
	String name;
	String description;
	
	boolean showInPortal;
	boolean showInRequest;
	boolean showInReports;
	
	List<Organization> subOrgs;
	
	public Organization() {
		this.subOrgs = new ArrayList<Organization>();
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public List<Organization> getSubOrgs() {
		return subOrgs;
	}

	public void setSubOrgs(List<Organization> subOrgs) {
		this.subOrgs = subOrgs;
	}

	public boolean isShowInPortal() {
		return showInPortal;
	}

	public void setShowInPortal(boolean showInPortal) {
		this.showInPortal = showInPortal;
	}

	public boolean isShowInRequest() {
		return showInRequest;
	}

	public void setShowInRequest(boolean showInRequest) {
		this.showInRequest = showInRequest;
	}

	public boolean isShowInReports() {
		return showInReports;
	}

	public void setShowInReports(boolean showInReports) {
		this.showInReports = showInReports;
	}
	
	

}
