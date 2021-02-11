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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.util.List;
import java.util.Map;

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
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.yaml.snakeyaml.Yaml;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.fge.jsonpatch.JsonPatchException;
import com.github.fge.jsonpatch.mergepatch.JsonMergePatch;
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

	public void applyFiles(List<GitFile> files) throws IOException, NoFilepatternException, GitAPIException, JsonPatchException, ParseException {
		
		for (GitFile file : files) {
			File targetFile = new File(this.tmpdir.getAbsolutePath() + File.separator + "gitrepo" + file.getDirName() + File.separator + file.getFileName());
			if (file.isDelete()) {
				logger.info("Deleting '" + targetFile.getAbsolutePath() + "'");
				
				FileUtils.forceDelete(targetFile);
				git.rm().addFilepattern(file.getDirName().substring(1) + File.separator + file.getFileName()).call();
			} if (file.isPatch()) {
				logger.info("Patching '" + targetFile.getAbsolutePath() + "'");
				
				InputStream in = new FileInputStream(targetFile);
				Yaml yaml = new Yaml();
    			Map<String,Object> map= (Map<String, Object>) yaml.load(in);
    			JSONObject jsonObject=new JSONObject(map);
    			
				
				
				ObjectMapper mapper = new ObjectMapper();
				
				JsonNode toBePatched = mapper.readValue(jsonObject.toJSONString(), JsonNode.class);
				JsonMergePatch patch = mapper.readValue(file.getData(), JsonMergePatch.class);
				
				JsonNode patched = patch.apply(toBePatched);
				
				String patchedJson = patched.toString();
				String newYaml = yaml.dump(new JSONParser().parse(patchedJson));
				
				
				FileOutputStream out = new FileOutputStream(targetFile);
				out.write(newYaml.getBytes("UTF-8"));
				out.flush();
				out.close();
				
				
			} else {
				logger.info("Creating '" + targetFile.getAbsolutePath() + "'");
				Files.createParentDirs(targetFile);
				FileOutputStream out = new FileOutputStream(targetFile);
				out.write(file.getData().getBytes("UTF-8"));
				out.flush();
				out.close();
			}
			
		}
		
		for (GitFile file : files) {
			File targetFile = new File(this.tmpdir.getAbsolutePath() + File.separator + "gitrepo" + file.getDirName() + File.separator + file.getFileName());
			if (file.isDelete()) {
				if (file.isNamespace()) {
					logger.info("Deleting namespace, removing directory '" + file.getDirName() + "'");
					//git.rm().addFilepattern("." + file.getDirName()).call();
					FileUtils.forceDelete(new File(this.tmpdir.getAbsolutePath() + File.separator + "gitrepo" + file.getDirName()));
					git.rm().addFilepattern(file.getDirName().substring(1)).call();
				}
			} 
			
		}
		
	}

	public void commitAndPush(String wfMessage) throws NoFilepatternException, GitAPIException {
		
		git.add().addFilepattern(".").call();
		
		
		
		
		RevCommit rev = git.commit().setAuthor(System.getProperty("GIT_USERNAME"), System.getProperty("GIT_EMAIL"))
		            .setCommitter(System.getProperty("GIT_USERNAME"), System.getProperty("GIT_EMAIL"))
		            .setMessage(wfMessage)
		            .call();
		
		logger.info(rev);
		
		git.push().setTransportConfigCallback(this.sshCallBack).call();
	}

}




