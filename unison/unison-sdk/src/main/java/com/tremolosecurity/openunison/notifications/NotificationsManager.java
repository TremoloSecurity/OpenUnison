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

import com.tremolosecurity.saml.Attribute;

/**
 * Manages running notification systems
 * @author marcboorshtein
 *
 */
public interface NotificationsManager {
	/**
	 * Add a new notification system, if one already exists with the same name it will be replaced
	 * @param name how the notification system will be referenced
	 * @param config notification system configuration
	 * @throws Exception
	 */
	public abstract void addNotificationSystem(String name, String className, Map<String,Attribute> config) throws Exception ;
	
	/**
	 * Retrieve a notification system by name, if none exists null is returned
	 * @param name
	 * @return
	 */
	public abstract NotificationSystem getNotificationSystem(String name);
	
	/**
	 * Removes the notification system named, if it doesn't exist then this method is a no-op
	 * @param name
	 */
	public abstract void removeNotificationSystem(String name);
	
	
	
}
