/*
Copyright 2015, 2016 Tremolo Security, Inc.

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


package com.tremolosecurity.provisioning.scheduler;

import org.apache.logging.log4j.Logger;
import org.quartz.Scheduler;
import org.quartz.SchedulerException;

import com.tremolosecurity.server.StopableThread;

public class StopScheduler implements StopableThread {
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(StopScheduler.class.getName());
	private Scheduler scheduler;
	
	
	public StopScheduler(Scheduler scheduler) {
		logger.info("Initializing stop scheduler thread");
		this.scheduler = scheduler;
	}
	
	@Override
	public void run() {
		//nothing to do

	}

	@Override
	public void stop() {
		try {
			logger.info("Shutting down the scheduler");
			this.scheduler.shutdown();
			logger.info("Scheduler shut down");
		} catch (SchedulerException e) {
			logger.error("Could not shutdown scheduler",e);
		}

	}

}
