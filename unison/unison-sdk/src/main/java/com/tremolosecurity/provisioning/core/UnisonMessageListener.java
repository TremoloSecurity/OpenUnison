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

import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.util.HashMap;

import javax.jms.Message;
import javax.jms.MessageListener;
import javax.jms.TextMessage;

import org.apache.logging.log4j.Logger;

import com.google.gson.Gson;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.util.EncryptedMessage;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

public abstract class UnisonMessageListener implements MessageListener {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(UnisonMessageListener.class.getName());
	
	
	@Override
	public void onMessage(Message msg) {
		try {
			TextMessage smsg = (TextMessage) msg;
			ConfigManager cfgMgr = (ConfigManager) GlobalEntries.getGlobalEntries().get(ProxyConstants.CONFIG_MANAGER);
			Gson gson = new Gson();
			EncryptedMessage em = gson.fromJson(smsg.getText(), EncryptedMessage.class);
			Object obj = cfgMgr.getProvisioningEngine().decryptObject(em);
			
			this.onMessage(cfgMgr,obj,msg);
			msg.acknowledge();
		} catch (Throwable t) {
			logger.error("Unable to run listener",t);
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			PrintWriter baout = new PrintWriter(baos);
			t.printStackTrace(baout);
			baout.flush();
			baout.close();
			StringBuffer b = new StringBuffer();
			b.append("Could not run listener").append(new String(baos.toByteArray()));
			throw new RuntimeException(b.toString(),t);
		}

	}
	
	public abstract void onMessage(ConfigManager cfg,Object payload,Message msg) throws ProvisioningException;
	
	public abstract void init(ConfigManager cfg,HashMap<String,Attribute> attributes) throws ProvisioningException;

}
