/*
Copyright 2022 Tremolo Security, Inc.

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

package com.tremolosecurity.proxy.auth.saml2;

import java.util.HashMap;

import org.apache.log4j.Logger;

import com.tremolosecurity.server.StopableThread;

public class MetaDataChecker implements StopableThread {
	static Logger logger = Logger.getLogger(MetaDataChecker.class);
	
	boolean keepRunning;
	
	private HashMap<String,Saml2MetadataLookup> metadataLookups;
	
	public MetaDataChecker(HashMap<String,Saml2MetadataLookup> metadataLookups) {
		this.keepRunning = true;
		this.metadataLookups = metadataLookups;
	}
	
	@Override
	public void run() {
		
		while (keepRunning) {
			try {
				Thread.sleep(60000);
			} catch (InterruptedException e) {
				
			}
			
			for (String url : this.metadataLookups.keySet()) {
				try {
					this.metadataLookups.get(url).pullMetaData();
				} catch (Exception e) {
					logger.warn(new StringBuilder().append("Could not load metadata '").append(url).append("'").toString(),e);
				}
			}
		}

	}

	@Override
	public void stop() {
		keepRunning = false;

	}

}
