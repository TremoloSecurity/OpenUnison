/*******************************************************************************
 * Copyright 2015, 2016 Tremolo Security, Inc.
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
package com.tremolosecurity.unison.proxy.filters.s3;

import org.apache.logging.log4j.Logger;


import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.saml.Attribute;

import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.ResponseInputStream;

import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Object;

public class AwsS3Proxy implements HttpFilter {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(AwsS3Proxy.class);
	
	String accessKey;
	String secretKey;
	S3Client s3Client;
	String topBucket;
	
	@Override
	public void doFilter(HttpFilterRequest req, HttpFilterResponse resp,HttpFilterChain chain) throws Exception {
		chain.setNoProxy(true);
		
		
		
		String uri = req.getRequestURI();
		
		
		
		int start = uri.indexOf(this.topBucket);
		if (start == -1) {
			resp.sendError(404);
			
		} else {
			String bucket = uri.substring(start + 1,uri.lastIndexOf('/'));
			String key = uri.substring(uri.lastIndexOf('/') + 1);
		
			if (logger.isDebugEnabled()) {
				logger.debug("Bucket - '" + bucket + "', Key - '" + key + "'");
			}
			
			ResponseInputStream<GetObjectResponse> response = s3Client.getObject(GetObjectRequest.builder().key(key).bucket(bucket).build());
			chain.setIns(response);
			resp.setContentType(response.response().contentType());
		}

	}

	@Override
	public void filterResponseBinary(HttpFilterRequest arg0,
			HttpFilterResponse arg1, HttpFilterChain arg2, byte[] arg3, int arg4)
			throws Exception {
		

	}

	@Override
	public void filterResponseText(HttpFilterRequest arg0,
			HttpFilterResponse arg1, HttpFilterChain arg2, StringBuffer arg3)
			throws Exception {
		

	}

	@Override
	public void initFilter(HttpFilterConfig config) throws Exception {
		this.accessKey = this.getConfigAttr(config, "accessKey");
		logger.info("Access Key : ************");
		this.secretKey = this.getConfigAttr(config, "secretKey");
		logger.info("Secret Key : *************");
		this.topBucket = "/" + this.getConfigAttr(config, "topBucket") + "/";
		logger.info("Top Bucket : '" + this.topBucket + "'");
		
		
		
		this.s3Client = S3Client.builder().credentialsProvider(StaticCredentialsProvider.create(new AwsCredentials() {

			@Override
			public String accessKeyId() {
				return accessKey;
			}

			@Override
			public String secretAccessKey() {
				return secretKey;
			}})).build();
				
				
				
	}
	
	private String getConfigAttr(HttpFilterConfig config,String name) throws Exception {
		Attribute attr = config.getAttribute(name);
		if (attr == null) {
			throw new Exception(name + " is required");
		}
		
		return attr.getValues().get(0);
	}

}
