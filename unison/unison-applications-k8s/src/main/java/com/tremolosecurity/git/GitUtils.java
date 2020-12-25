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
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.TransportConfigCallback;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.api.errors.InvalidRemoteException;
import org.eclipse.jgit.api.errors.NoFilepatternException;
import org.eclipse.jgit.api.errors.TransportException;
import org.eclipse.jgit.revwalk.RevCommit;
import org.eclipse.jgit.transport.CredentialsProvider;

import org.eclipse.jgit.transport.SshSessionFactory;
import org.eclipse.jgit.transport.SshTransport;
import org.eclipse.jgit.transport.Transport;
import org.eclipse.jgit.util.FS;

import com.google.common.io.Files;
import com.tremolosecurity.provisioning.tasks.dataobj.GitFile;


public class GitUtils {
	
	static Logger logger;
	
	String gitUrl;
	String privateKey;
	File tmpdir;
	Git git;
	
	SshTransportConfigCallback sshCallBack;
	
	static File userHome;
	
	static {
		logger = Logger.getLogger(GitUtils.class);
		userHome = Files.createTempDir();
		try {
			PrintWriter out = new PrintWriter(new OutputStreamWriter(new FileOutputStream(userHome.getAbsolutePath() + File.separator + ".gitconfig")));
			out.println("[user]");
			out.println("\tname = " + System.getProperty("GIT_USERNAME"));
			out.println("\temail = " + System.getProperty("GIT_EMAIL"));
			out.flush();
			out.close();
		} catch (FileNotFoundException e) {
			logger.warn("Couldn't generate git config",e);
		}
	}
	
	public GitUtils(String gitUrl,String privateKey) {
		this.gitUrl = gitUrl;
		this.privateKey = privateKey;
		tmpdir = Files.createTempDir();
	}
	
	public void checkOut() throws FileNotFoundException, InvalidRemoteException, TransportException, GitAPIException {
		File sshKeyDir = new File(tmpdir.getAbsolutePath() + File.separator + "ssh");
		sshKeyDir.mkdir();
		
		File gitRepo = new File(tmpdir.getAbsolutePath() + File.separator + "gitrepo");
		gitRepo.mkdir();
		
		File sshKeyFile = new File(sshKeyDir.getAbsolutePath() + File.separator + "id_rsa");
		PrintWriter out = new PrintWriter(new OutputStreamWriter(new FileOutputStream(sshKeyFile)));
		out.println(this.privateKey);
		out.flush();
		out.close();
		
		File sshConfigFile = new File(sshKeyDir.getAbsolutePath() + File.separator + "config");
		out = new PrintWriter(new OutputStreamWriter(new FileOutputStream(sshConfigFile)));
		out.println("Host *");
		out.println("  StrictHostKeyChecking no");
		out.println("  UserKnownHostsFile=" + sshKeyDir.getAbsolutePath() + File.separator + "known_hosts" );
		out.flush();
		out.close();
		
		
		FS fs = FS.detect();
		fs.setUserHome(userHome);
		
		CredentialsProvider x;

		sshCallBack = new SshTransportConfigCallback(sshKeyDir,tmpdir);
		
		git = Git.cloneRepository()
				.setFs(fs)
		        .setDirectory(gitRepo)
		        .setTransportConfigCallback(sshCallBack)
		        .setURI(this.gitUrl)
		        .call();
	}
	
	public void cleanup() {
		try {
			FileUtils.deleteDirectory(tmpdir);
		} catch (IOException e) {
			logger.warn("Could not delete files",e);
		}
	}

	public void applyFiles(List<GitFile> files) throws IOException {
		
		for (GitFile file : files) {
			File targetFile = new File(this.tmpdir.getAbsolutePath() + File.separator + "gitrepo" + file.getDirName() + File.separator + file.getFileName());
			logger.info("Creating '" + targetFile.getAbsolutePath() + "'");
			Files.createParentDirs(targetFile);
			FileOutputStream out = new FileOutputStream(targetFile);
			out.write(file.getData().getBytes("UTF-8"));
			out.flush();
			out.close();
		}
		
	}

	public void commitAndPush(String wfMessage) throws NoFilepatternException, GitAPIException {
		
		git.add().addFilepattern(".").call();
		
		RevCommit rev = git.commit().setAuthor(System.getProperty("GIT_USERNAME"), System.getProperty("GIT_EMAIL"))
		            .setCommitter(System.getProperty("GIT_USERNAME"), System.getProperty("GIT_EMAIL"))
		            .setMessage(wfMessage)
		            .call();
		
		git.push().setTransportConfigCallback(this.sshCallBack).call();
	}

}




