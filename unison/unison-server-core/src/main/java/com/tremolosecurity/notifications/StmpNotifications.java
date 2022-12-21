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

import java.util.Map;
import java.util.Properties;

import javax.mail.Authenticator;
import javax.mail.Message;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import org.apache.log4j.Logger;

import com.tremolosecurity.openunison.notifications.NotificationSystem;
import com.tremolosecurity.provisioning.core.SmtpMessage;
import com.tremolosecurity.saml.Attribute;

public class StmpNotifications implements NotificationSystem {
	static Logger logger = Logger.getLogger(StmpNotifications.class.getName());
	String from;
	String host;
	String localHost;
	String password;
	String SOCKSProxyHost;
	String subject;
	String user;
	boolean tls;

	int port;
	int SOCKSProxyPort;
	boolean SOCKSproxy;

	String name;

	@Override
	public void init(String name, Map<String, Attribute> config) throws Exception {
		this.name = name;
		this.from = config.get("from").getValues().get(0);
		this.host = config.get("host").getValues().get(0);
		this.subject = config.get("subject").getValues().get(0);
		this.port = Integer.parseInt(config.get("port").getValues().get(0));
		if (config.get("localHost") != null) {
			this.localHost = config.get("localHost").getValues().get(0);
		}

		if (config.get("user") != null) {
			this.user = config.get("user").getValues().get(0);
		}

		if (config.get("password") != null) {
			this.password = config.get("password").getValues().get(0);
		}

		if (config.get("SOCKSProxyPort") != null) {
			this.SOCKSProxyHost = config.get("SOCKSProxyPort").getValues().get(0);
		}

		if (config.get("SOCKSProxyPort") != null) {
			this.SOCKSProxyPort = Integer.parseInt(config.get("SOCKSProxyPort").getValues().get(0));
		}

		if (config.get("tls") != null) {
			this.tls = config.get("tls").getValues().get(0).equalsIgnoreCase("true");
		}

		if (config.get("useSOCKSproxy") != null) {
			this.SOCKSproxy = config.get("useSOCKSProxy").getValues().get(0).equalsIgnoreCase("true");
		}

	}

	@Override
	public void shutdown() throws Exception {
		// TODO Auto-generated method stub

	}

	@Override
	public void sendMessage(SmtpMessage msg) throws Exception {
		Properties props = new Properties();
		boolean doAuth = false;
		props.setProperty("mail.smtp.host", this.host);
		props.setProperty("mail.smtp.port", Integer.toString(this.port));
		if (this.user != null && !this.user.isEmpty()) {
			if (logger.isDebugEnabled()) {
				logger.debug("SMTP user found '" + this.user + "', enabling authentication");
			}
			props.setProperty("mail.smtp.user", this.user);
			props.setProperty("mail.smtp.auth", "true");
			doAuth = true;
		} else {
			if (logger.isDebugEnabled()) {
				logger.debug("No SMTP user, disabling authentication");
			}
			doAuth = false;
			props.setProperty("mail.smtp.auth", "false");
		}
		props.setProperty("mail.transport.protocol", "smtp");
		props.setProperty("mail.smtp.starttls.enable", Boolean.toString(this.tls));
		if (logger.isDebugEnabled()) {
			props.setProperty("mail.debug", "true");
			props.setProperty("mail.socket.debug", "true");
		}

		if (this.localHost != null && !this.localHost.isEmpty()) {
			props.setProperty("mail.smtp.localhost", this.localHost);
		}

		if (this.SOCKSproxy) {

			props.setProperty("mail.smtp.socks.host", this.SOCKSProxyHost);

			props.setProperty("mail.smtp.socks.port", Integer.toString(this.SOCKSProxyPort));
			props.setProperty("mail.smtps.socks.host", this.SOCKSProxyHost);

			props.setProperty("mail.smtps.socks.port", Integer.toString(this.SOCKSProxyPort));
		}

		// Session session = Session.getInstance(props, new
		// SmtpAuthenticator(this.smtpUser,this.smtpPassword));

		Session session = null;
		if (doAuth) {
			logger.debug("Creating authenticated session");
			session = Session.getInstance(props, new Authenticator() {
				protected PasswordAuthentication getPasswordAuthentication() {
					return new PasswordAuthentication(user, password);
				}
			});
		} else {
			logger.debug("Creating unauthenticated session");
			session = Session.getInstance(props);
		}
		if (logger.isDebugEnabled()) {
			session.setDebugOut(System.out);
			session.setDebug(true);
		}
		// Transport tr = session.getTransport("smtp");
		// tr.connect();

		// tr.connect(this.smtpHost,this.smtpPort, this.smtpUser, this.smtpPassword);

		Message msgToSend = new MimeMessage(session);
		msgToSend.setFrom(new InternetAddress(msg.getFrom()));
		msgToSend.addRecipient(Message.RecipientType.TO, new InternetAddress(msg.getTo()));
		msgToSend.setSubject(msg.getSubject());

		if (msg.getContentType() != null) {
			msgToSend.setContent(msg.getMsg(), msg.getContentType());
		} else {
			msgToSend.setText(msg.getMsg());
		}

		msgToSend.saveChanges();
		Transport.send(msgToSend);

		// tr.sendMessage(msg, msg.getAllRecipients());
		// tr.close();

	}

}
