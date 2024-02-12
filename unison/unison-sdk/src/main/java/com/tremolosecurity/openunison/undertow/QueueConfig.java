/*******************************************************************************
 * Copyright 2021 Tremolo Security, Inc.
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
package com.tremolosecurity.openunison.undertow;

import java.util.ArrayList;
import java.util.List;

public class QueueConfig {
	boolean useInternalQueue;
	long maxProducers;
	String connectionFactory;
	long maxConsumers;
	long maxSessionsPerConnection;
	String taskQueueName;
	String smtpQueueName;
	String encryptionKeyName;
	long numQueues;
	boolean multiTaskQueues;
	long keepAliveMillis;
	List<QueueConfigParam> params;
	
	boolean manualDlq;
	int manualDlqMaxAttempts;
	String manualDlqName;
	
	
	public QueueConfig() {
		this.params = new ArrayList<QueueConfigParam>();
		this.manualDlq = false;
	}

	public boolean isUseInternalQueue() {
		return useInternalQueue;
	}

	public void setUseInternalQueue(boolean useInternalQueue) {
		this.useInternalQueue = useInternalQueue;
	}

	public long getMaxProducers() {
		return maxProducers;
	}

	public void setMaxProducers(long maxProducers) {
		this.maxProducers = maxProducers;
	}

	public String getConnectionFactory() {
		return connectionFactory;
	}

	public void setConnectionFactory(String connectionFactory) {
		this.connectionFactory = connectionFactory;
	}

	public long getMaxConsumers() {
		return maxConsumers;
	}

	public void setMaxConsumers(long maxConsumers) {
		this.maxConsumers = maxConsumers;
	}

	public long getMaxSessionsPerConnection() {
		return maxSessionsPerConnection;
	}

	public void setMaxSessionsPerConnection(long maxSessionsPerConnection) {
		this.maxSessionsPerConnection = maxSessionsPerConnection;
	}

	public String getTaskQueueName() {
		return taskQueueName;
	}

	public void setTaskQueueName(String taskQueueName) {
		this.taskQueueName = taskQueueName;
	}

	public String getSmtpQueueName() {
		return smtpQueueName;
	}

	public void setSmtpQueueName(String smtpQueueName) {
		this.smtpQueueName = smtpQueueName;
	}

	public String getEncryptionKeyName() {
		return encryptionKeyName;
	}

	public void setEncryptionKeyName(String encryptionKeyName) {
		this.encryptionKeyName = encryptionKeyName;
	}

	public long getNumQueues() {
		return numQueues;
	}

	public void setNumQueues(long numQueues) {
		this.numQueues = numQueues;
	}

	public boolean isMultiTaskQueues() {
		return multiTaskQueues;
	}

	public void setMultiTaskQueues(boolean multiTaskQueues) {
		this.multiTaskQueues = multiTaskQueues;
	}

	public long getKeepAliveMillis() {
		return keepAliveMillis;
	}

	public void setKeepAliveMillis(long keepAliveMillis) {
		this.keepAliveMillis = keepAliveMillis;
	}

	public List<QueueConfigParam> getParams() {
		return params;
	}

	public void setParams(List<QueueConfigParam> params) {
		this.params = params;
	}

	public boolean isManualDlq() {
		return manualDlq;
	}

	public void setManualDlq(boolean manualDlq) {
		this.manualDlq = manualDlq;
	}

	public int getManualDlqMaxAttempts() {
		return manualDlqMaxAttempts;
	}

	public void setManualDlqMaxAttempts(int manualDlqMaxAttempts) {
		this.manualDlqMaxAttempts = manualDlqMaxAttempts;
	}

	public String getManualDlqName() {
		return manualDlqName;
	}

	public void setManualDlqName(String manualDlqName) {
		this.manualDlqName = manualDlqName;
	}
	
	
	
}
