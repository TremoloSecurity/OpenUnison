/*******************************************************************************
 * Copyright (c) 2021 Tremolo Security, Inc.
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
package com.tremolosecurity.proxy.auth;

import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Properties;

import javax.mail.Authenticator;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.servlet.ServletException;

import com.tremolosecurity.saml.Attribute;

public class SmtpOtp extends SMSAuth {

	@Override
	public void sendSMS(HashMap<String, Attribute> authParams, String from, String message, String to)
			throws ServletException {
		
		Properties props = new Properties();
		props.setProperty("mail.smtp.host", authParams.get("host").getValues().get(0));
		props.setProperty("mail.smtp.port", authParams.get("port").getValues().get(0));
		props.setProperty("mail.transport.protocol", "smtp");
		props.setProperty("mail.smtp.starttls.enable", authParams.get("tls").getValues().get(0));
		
		boolean doAuth = false;
		
		if (authParams.get("user") != null) {
			props.setProperty("mail.smtp.user", authParams.get("user").getValues().get(0));
			props.setProperty("mail.smtp.auth", "true");
			doAuth = true;
		} else {
			doAuth = false;
			props.setProperty("mail.smtp.auth", "false");
		}
		
		Session session = null;
		if (doAuth) {
			logger.debug("Creating authenticated session");
			session = Session.getInstance(props, 
					new Authenticator(){
				protected PasswordAuthentication getPasswordAuthentication() {
				   return new PasswordAuthentication(authParams.get("user").getValues().get(0), authParams.get("password").getValues().get(0));
				}});
		} else {
			logger.debug("Creating unauthenticated session");
			session = Session.getInstance(props);
		}
		
		Message msgToSend = new MimeMessage(session);
		try {
			msgToSend.setFrom(new InternetAddress(from));
			msgToSend.addRecipient( Message.RecipientType.TO, new InternetAddress(to));
			msgToSend.setSubject(authParams.get("subject").getValues().get(0));
			msgToSend.setText(message);
			
			msgToSend.saveChanges();
			Transport.send(msgToSend);
		} catch (MessagingException e) {
			throw new ServletException("Could not send one-time-password",e);
		}
		
		
		

	}
	


}
