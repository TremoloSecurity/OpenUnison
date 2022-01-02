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


package com.tremolosecurity.proxy.auth.secret;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Map;

import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.config.xml.AuthMechType;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.config.xml.ParamWithValueType;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;

public class CreateSecretQuestionsTask implements CustomTask {

	int numQuestions;
	String questionNamePrefix;
	String questionValuePrefix;
	String chainName;
	String mechName;
	
	String alg;
	String salt;
	String attrName;
	String questionAttr;
	
	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params)
			throws ProvisioningException {
		numQuestions = Integer.parseInt(params.get("numQuestions").getValues().get(0));
		questionNamePrefix = params.get("questionNamePrefix").getValues().get(0);
		questionValuePrefix = params.get("questionValuePrefix").getValues().get(0);
		chainName = params.get("chainName").getValues().get(0);
		
		
		if (params.get("mechName") != null) {
			this.mechName = params.get("mechName").getValues().get(0);
		} else {
			this.mechName = "SecretQuestions";
		}
		
		for (AuthChainType act : task.getConfigManager().getCfg().getAuthChains().getChain()) {
			if (act.getName().equalsIgnoreCase(chainName)) {
				for (AuthMechType amt : act.getAuthMech()) {
					if (amt.getName().equalsIgnoreCase(this.mechName)) {
						for (ParamWithValueType pt : amt.getParams().getParam()) {
							String value = "";
							
							if (pt.getValue() != null && ! pt.getValue().isBlank()) {
								value = pt.getValue();
							} else {
								value = pt.getValueAttribute();
							}
							
							if (pt.getName().equalsIgnoreCase("alg")) {
								this.alg = value;
							}
							
							if (pt.getName().equalsIgnoreCase("salt")) {
								this.salt = value;
							}
							
							if (pt.getName().equalsIgnoreCase("questionAttr")) {
								this.questionAttr = value;
							}
						}
					}
				}
			}
		}
		

	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		

	}

	@Override
	public boolean doTask(User user, Map<String, Object> request)
			throws ProvisioningException {
		
		ArrayList<SecretQuestion> sqs = new ArrayList<SecretQuestion>();
		
		for (int i=0;i<this.numQuestions;i++) {
			int questionNum = Integer.parseInt(user.getAttribs().get(this.questionNamePrefix + Integer.toString(i)).getValues().get(0));
			user.getAttribs().remove(this.questionNamePrefix + Integer.toString(i));
			
			String answer = user.getAttribs().get(this.questionValuePrefix + Integer.toString(i)).getValues().get(0);
			user.getAttribs().remove(this.questionValuePrefix + Integer.toString(i));
			
			
			SecretQuestion sq = new SecretQuestion();
			sq.setQuestion(questionNum);
			try {
				sq.setAnswer(this.alg, answer, this.salt);
			} catch (NoSuchAlgorithmException e) {
				throw new ProvisioningException("Could not set answer",e);
			} catch (UnsupportedEncodingException e) {
				throw new ProvisioningException("Could not set answer",e);
			}
			
			sqs.add(sq);
			
		}
		
		try {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			ObjectOutputStream oos = new ObjectOutputStream(baos);
			oos.writeObject(sqs);
			oos.close();
			baos.close();
			
			
			user.getAttribs().put(this.questionAttr, new Attribute(this.questionAttr,new String(org.bouncycastle.util.encoders.Base64.encode(baos.toByteArray()))));
		} catch (Exception e) {
			throw new ProvisioningException("Could not set answer",e);
		}
		
		return true;
	}

}
