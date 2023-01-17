package com.tremolosecurity.notifications;

import java.util.Map;

import com.tremolosecurity.openunison.notifications.NotificationSystem;
import com.tremolosecurity.openunison.notifications.NotificationsManager;
import com.tremolosecurity.provisioning.core.SmtpMessage;
import com.tremolosecurity.saml.Attribute;

public class NoNotifications implements NotificationSystem {

	@Override
	public void init(String name, Map<String, Attribute> config) throws Exception {
		
		
	}

	@Override
	public void shutdown() throws Exception {
		
		
	}

	@Override
	public void sendMessage(SmtpMessage msg) throws Exception {
		
		
	}

	
}
