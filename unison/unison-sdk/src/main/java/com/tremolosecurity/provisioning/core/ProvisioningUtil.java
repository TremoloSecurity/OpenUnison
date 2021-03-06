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


package com.tremolosecurity.provisioning.core;

public class ProvisioningUtil {
	/**
	 * Describes the type of provisioning action
	 * @author Tremolo Security Inc.
	 *
	 */
	public enum ActionType {
		/**
		 * Adding a new entry
		 */
		Add,
		/**
		 * Deleting an existing entry
		 */
		Delete,
		/**
		 * Replacing an existing entry
		 */
		Replace
	}
	
	
	public static final String SKIP_SYNC_GROUPS = "com.tremolosecurity.unison.provisioning.SkipSyncGroups";
	
	public static final String SET_PASSWORD = "com.tremolosecurity.unison.provisioning.SetPassword";
}


