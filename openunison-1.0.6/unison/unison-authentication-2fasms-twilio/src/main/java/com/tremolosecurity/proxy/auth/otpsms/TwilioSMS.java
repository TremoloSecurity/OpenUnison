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


package com.tremolosecurity.proxy.auth.otpsms;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;

import com.tremolosecurity.proxy.auth.SMSAuth;
import com.tremolosecurity.saml.Attribute;

import com.twilio.sdk.TwilioRestClient;
import com.twilio.sdk.TwilioRestException;
import com.twilio.sdk.resource.factory.SmsFactory;
import com.twilio.sdk.resource.instance.Account;


public class TwilioSMS extends SMSAuth {

	
	
	
	public void sendSMS(HashMap<String,Attribute> authParams,String from,
			String message, String to) throws ServletException {
		
		String accountSID = authParams.get("accountSID").getValues().get(0);
		String authToken = authParams.get("authToken").getValues().get(0);
		
		
		TwilioRestClient client = new TwilioRestClient(accountSID,authToken);
		Account account = client.getAccount();
		SmsFactory smsFactory = account.getSmsFactory();
		Map<String, String> smsParams = new HashMap<String, String>();
		smsParams.put("To", to); // Replace with a valid phone number
		smsParams.put("From", from); // Replace with a valid phone
													// number in your account
		smsParams.put("Body", message);
		try {
			smsFactory.create(smsParams);
		} catch (TwilioRestException e) {
			throw new ServletException("Could not send SMS",e);
		}
	}
	
}
