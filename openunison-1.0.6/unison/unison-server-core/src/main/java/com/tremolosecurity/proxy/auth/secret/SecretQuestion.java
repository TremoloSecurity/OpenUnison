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

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.log4j.Logger;

public class SecretQuestion implements Serializable {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -1738492295208319948L;

	static Logger logger = Logger.getLogger(SecretQuestion.class.getName());
	
	int question;
	byte[] answer;
	
	public SecretQuestion() {
		
	}

	public int getQuestion() {
		return question;
	}

	public void setQuestion(int question) {
		this.question = question;
	}

	public byte[] getAnswer() {
		return answer;
	}

	public void setAnswer(byte[] answer) {
		this.answer = answer;
	}
	
	public void setAnswer(String alg,String answer,String salt) throws NoSuchAlgorithmException, UnsupportedEncodingException {
		this.answer = this.hashAnswer(alg, answer, salt);
	}
	
	public boolean checkAnswer(String alg, String userAnswer,String salt) {
		try {
			byte[] hashed = hashAnswer(alg, userAnswer, salt);
			
			if (hashed.length != this.answer.length) {
				return false;
			}
			
			for (int i=0;i<hashed.length;i++) {
				if (hashed[i] != this.answer[i]) {
					return false;
				}
			}
			
			return true;
		} catch (Exception e) {
			logger.error("Error processing secret question",e);
			return false;
		}
	}

	private byte[] hashAnswer(String alg, String userAnswer, String salt)
			throws NoSuchAlgorithmException, UnsupportedEncodingException {
		StringBuffer tocheck = new StringBuffer();
		tocheck.append(salt).append(userAnswer);
		MessageDigest md = MessageDigest.getInstance(alg);
		md.reset();
		md.update(tocheck.toString().getBytes("UTF-8"));
		byte[] hashed = md.digest();
		return hashed;
	}
}
