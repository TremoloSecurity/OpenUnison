/*******************************************************************************
 * Copyright 2020 Tremolo Security, Inc.
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
package com.tremolosecurity.provisioning.tasks.dataobj;

public class GitFile {
	String fileName;
	String dirName;
	String data;
	boolean delete;
	boolean isNamespace;
	boolean patch;
	
	public GitFile(String fileName,String dirName,String data) {
		this.fileName = fileName;
		this.dirName = dirName;
		this.data = data;
		this.delete = false;
		this.isNamespace = false;
		this.patch = false;
	}
	
	public GitFile(String fileName,String dirName,boolean delete,boolean isNamespace) {
		this.fileName = fileName;
		this.dirName = dirName;
		this.data = null;
		this.delete = delete;
		this.isNamespace = isNamespace;
		this.patch = false;
	}

	public String getFileName() {
		return fileName;
	}

	public void setFileName(String fileName) {
		this.fileName = fileName;
	}

	public String getDirName() {
		return dirName;
	}

	public void setDirName(String dirName) {
		this.dirName = dirName;
	}

	public String getData() {
		return data;
	}

	public void setData(String data) {
		this.data = data;
	}

	public boolean isDelete() {
		return delete;
	}

	public void setDelete(boolean delete) {
		this.delete = delete;
	}

	public boolean isNamespace() {
		return isNamespace;
	}

	public void setNamespace(boolean isNamespace) {
		this.isNamespace = isNamespace;
	}

	public boolean isPatch() {
		return patch;
	}

	public void setPatch(boolean patch) {
		this.patch = patch;
	}
	
	
	
	
	
}
