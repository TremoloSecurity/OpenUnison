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

package com.tremolosecurity.proxy.auth.saml2;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.scheduler.UnisonJob;
import org.apache.log4j.Logger;
import org.quartz.JobExecutionContext;

public class Saml2DigestCleaner extends UnisonJob {
    static Logger logger = Logger.getLogger(Saml2DigestCleaner.class.getName());
    @Override
    public void execute(ConfigManager configManager, JobExecutionContext context) throws ProvisioningException {
        Saml2DigestCache cache = Saml2DigestCache.getInstance();
        if (cache != null) {
            int numRemoved = cache.clearExpiredDigests();
            logger.info("Number of expired digests removed: " + numRemoved);
        }
    }
}
