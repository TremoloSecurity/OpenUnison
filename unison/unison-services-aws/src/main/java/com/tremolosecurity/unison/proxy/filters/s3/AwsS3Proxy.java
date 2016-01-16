/*******************************************************************************
 * Copyright 2015 Tremolo Security, Inc.
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

import org.apache.log4j.Logger;

import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.S3Object;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.saml.Attribute;

public class AwsS3Proxy implements HttpFilter {

	static Logger logger = Logger.getLogger(AwsS3Proxy.class);
	
	String accessKey;
	String secretKey;
	AmazonS3 s3Client;
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
			
			S3Object object = s3Client.getObject(new GetObjectRequest(bucket,key));
			chain.setIns(object.getObjectContent());
			resp.setContentType(object.getObjectMetadata().getContentType());
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
		
		
		
		this.s3Client = new AmazonS3Client(new BasicAWSCredentials(this.accessKey,this.secretKey));
	}
	
	private String getConfigAttr(HttpFilterConfig config,String name) throws Exception {
		Attribute attr = config.getAttribute(name);
		if (attr == null) {
			throw new Exception(name + " is required");
		}
		
		return attr.getValues().get(0);
	}

}
