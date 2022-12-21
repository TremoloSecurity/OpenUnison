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
package com.tremolosecurity.openunison.notifications;

import java.util.Map;

import com.tremolosecurity.provisioning.core.SmtpMessage;
import com.tremolosecurity.saml.Attribute;

/**
 * Implementations of this class will notify users of actions inside of openunison
 * @author marcboorshtein
 *
 */
public interface NotificationSystem {
	/**
	 * Initializes the notification system
	 * @param name Name of the notification
	 * @param config notification configuration
	 * @throws Exception
	 */
	public abstract void init(String name,Map<String,Attribute> config) throws Exception; 
	
	/**
	 * Called on shutdown of the system
	 * @throws Exception
	 */
	public abstract void shutdown() throws Exception;
	
	/**
	 * Sends a message using this system
	 * @param msg
	 * @throws Exception
	 */
	public abstract void sendMessage(SmtpMessage msg) throws Exception;
}
