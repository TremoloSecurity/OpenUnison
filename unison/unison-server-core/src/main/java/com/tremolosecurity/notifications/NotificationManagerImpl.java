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

package com.tremolosecurity.notifications;

import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;

import com.tremolosecurity.openunison.notifications.NotificationSystem;
import com.tremolosecurity.openunison.notifications.NotificationsManager;
import com.tremolosecurity.saml.Attribute;

public class NotificationManagerImpl implements NotificationsManager {

	static Logger logger = Logger.getLogger(NotificationManagerImpl.class.getName());
	
	Map<String,NotificationSystem> notifiers;
	
	public NotificationManagerImpl() {
		this.notifiers = new HashMap<String,NotificationSystem>();
	}
	
	@Override
	public void addNotificationSystem(String name, String className, Map<String, Attribute> config) throws Exception {
		NotificationSystem notifier = (NotificationSystem) Class.forName(className).getConstructor().newInstance();
		
		notifier.init(name, config);
		
		synchronized (this.notifiers) {
			if (notifiers.get(name) != null) {
				this.removeNotificationSystem(name);
			}
			
			this.notifiers.put(name, notifier);
		}

	}

	@Override
	public NotificationSystem getNotificationSystem(String name) {
		return this.notifiers.get(name);
	}

	@Override
	public void removeNotificationSystem(String name) {
		synchronized (this.notifiers) {
			NotificationSystem notifier = this.notifiers.get(name);
			
			if (notifier != null) {
				try {
					notifier.shutdown();
				} catch (Exception e) {
					logger.warn(String.format("Could not shutdown %S",name),e);
				}
			}
		}

	}

}
