/*******************************************************************************
 * Copyright 2020 Tremolo Security, Inc.
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
package com.tremolosecurity.git;

import java.io.File;

import org.apache.sshd.client.SshClient;
import org.eclipse.jgit.api.TransportConfigCallback;
import org.eclipse.jgit.errors.TransportException;
import org.eclipse.jgit.internal.transport.sshd.JGitSshClient;
import org.eclipse.jgit.transport.CredentialsProvider;

import org.eclipse.jgit.transport.SshSessionFactory;
import org.eclipse.jgit.transport.SshTransport;
import org.eclipse.jgit.transport.Transport;
import org.eclipse.jgit.transport.URIish;
import org.eclipse.jgit.transport.sshd.SshdSession;
import org.eclipse.jgit.transport.sshd.SshdSessionFactory;
import org.eclipse.jgit.util.FS;





public class SshTransportConfigCallback implements TransportConfigCallback {
	
	File sshPath;
	File homeDir;
	
	public SshTransportConfigCallback(File sshPath,File homeDir) { 
		this.sshPath = sshPath;
		this.homeDir = homeDir;
	}



    @Override
    public void configure(Transport transport) {
        SshTransport sshTransport = (SshTransport) transport;
        
        SshdSessionFactory sshSessionFactory = new SshdSessionFactory();
        sshSessionFactory.setSshDirectory(sshPath.getAbsoluteFile());
        sshSessionFactory.setHomeDirectory(homeDir);
        
        sshTransport.setSshSessionFactory(sshSessionFactory);
    }

}
