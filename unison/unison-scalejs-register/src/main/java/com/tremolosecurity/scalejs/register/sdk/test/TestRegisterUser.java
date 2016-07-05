package com.tremolosecurity.scalejs.register.sdk.test;

import java.util.HashMap;
import java.util.List;

import org.apache.log4j.Logger;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.service.util.WFCall;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.scalejs.register.cfg.ScaleJSRegisterConfig;
import com.tremolosecurity.scalejs.register.data.NewUserRequest;
import com.tremolosecurity.scalejs.register.sdk.CreateRegisterUser;
import com.tremolosecurity.scalejs.register.ws.ScaleRegister;

public class TestRegisterUser implements CreateRegisterUser {
	
	static Logger logger = Logger.getLogger(TestRegisterUser.class.getName());

	@Override
	public void init(ScaleJSRegisterConfig registerConfig)
			throws ProvisioningException {
		logger.info("config:" + registerConfig.getCustomSubmissionConfig().get("option1"));

	}

	@Override
	public String createTremoloUser(NewUserRequest newUser, List<String> errors) throws ProvisioningException {
		errors.add("This doesn't do anything");
		return null;
	}

}
