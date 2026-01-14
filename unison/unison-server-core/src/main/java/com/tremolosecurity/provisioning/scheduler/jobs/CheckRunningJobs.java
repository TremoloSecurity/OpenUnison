/*
 * Copyright 2026 Tremolo Security, Inc.
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
 */

package com.tremolosecurity.provisioning.scheduler.jobs;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.scheduler.UnisonJob;
import org.apache.log4j.Logger;
import org.quartz.Job;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;
import org.quartz.Scheduler;
import org.quartz.JobExecutionContext;
import org.quartz.JobKey;

import java.util.List;
import java.util.concurrent.TimeUnit;

public class CheckRunningJobs extends UnisonJob {
    static Logger logger = Logger.getLogger(CheckRunningJobs.class.getName());
    private static final long MAX_RUNTIME_MS = TimeUnit.MINUTES.toMillis(1);

    @Override
    public void execute(ConfigManager configManager, JobExecutionContext context) throws ProvisioningException {

        logger.info("Checking running jobs...");
        Scheduler scheduler = context.getScheduler();
        try {
            List<JobExecutionContext> runningJobs =
                    scheduler.getCurrentlyExecutingJobs();

            long now = System.currentTimeMillis();

            for (JobExecutionContext running : runningJobs) {

                long runtimeMs = running.getJobRunTime();

                if (runtimeMs > MAX_RUNTIME_MS) {
                    JobKey jobKey = running.getJobDetail().getKey();

                    logger.warn(
                            String.format(
                            "Scheduled job %s running too long: %s ms (started at %s)",
                            jobKey,
                            runtimeMs,
                            running.getFireTime())
                    );
                } else {
                    JobKey jobKey = running.getJobDetail().getKey();
                    logger.info(String.format("Scheduled job %s running since %s for %s ms",jobKey,running.getFireTime(),runtimeMs));
                }
            }

        } catch (Throwable t) {
            logger.warn(
                    "Error checking for long-running scheduled jobs", t
            );
        }

        logger.info("Finished checking for long-running scheduled jobs");
    }
}
