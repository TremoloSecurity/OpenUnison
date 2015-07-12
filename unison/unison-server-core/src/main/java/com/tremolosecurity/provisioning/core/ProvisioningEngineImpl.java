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


package com.tremolosecurity.provisioning.core;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URLEncoder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.Queue;
import java.util.Stack;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.jms.ConnectionFactory;
import javax.jms.JMSException;
import javax.jms.MessageConsumer;
import javax.jms.MessageListener;
import javax.jms.MessageProducer;
import javax.jms.ObjectMessage;
import javax.jms.TextMessage;
import javax.mail.Authenticator;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.sql.DataSource;

import org.apache.activemq.ActiveMQConnectionFactory;
import org.apache.commons.dbcp.cpdsadapter.DriverAdapterCPDS;
import org.apache.commons.dbcp.datasources.SharedPoolDataSource;
import org.apache.commons.pool2.impl.GenericObjectPool;
import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.quartz.CronScheduleBuilder;
import org.quartz.CronTrigger;
import org.quartz.Job;
import org.quartz.JobBuilder;
import org.quartz.JobDetail;
import org.quartz.JobKey;
import org.quartz.Scheduler;
import org.quartz.SchedulerException;
import org.quartz.Trigger;
import org.quartz.TriggerBuilder;
import org.quartz.impl.StdSchedulerFactory;
import org.quartz.impl.matchers.GroupMatcher;

import com.cedarsoftware.util.io.JsonReader;
import com.cedarsoftware.util.io.JsonWriter;
import com.google.gson.Gson;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.ApprovalDBType;
import com.tremolosecurity.config.xml.JobType;
import com.tremolosecurity.config.xml.MessageListenerType;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.config.xml.SchedulingType;
import com.tremolosecurity.config.xml.TargetType;
import com.tremolosecurity.config.xml.TargetsType;
import com.tremolosecurity.config.xml.TremoloType;
import com.tremolosecurity.config.xml.WorkflowTaskType;
import com.tremolosecurity.config.xml.WorkflowType;
import com.tremolosecurity.json.Token;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.mapping.MapIdentity;
import com.tremolosecurity.provisioning.scheduler.StopScheduler;
import com.tremolosecurity.provisioning.tasks.Approval;
import com.tremolosecurity.provisioning.util.EncryptedMessage;
import com.tremolosecurity.provisioning.util.MessageProducerHolder;
import com.tremolosecurity.provisioning.util.PooledMessageProducerFactory;
import com.tremolosecurity.provisioning.util.TaskHolder;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.AzSys;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.StopableThread;


/**
 * 
 * @author Tremolo Security Inc.
 *
 */
public class ProvisioningEngineImpl implements ProvisioningEngine {
	
	ConfigManager cfgMgr;
	
	

	HashSet<String> maskedAttributes;

	HashMap<String,ProvisioningTargetImpl> userStores;
	HashMap<String,WorkflowImpl> workflows;
	HashMap<String,Integer> targetIDs;
	
	String userIDAttributeName;
	
	private DataSource approvalConPool;
	
	ArrayList<String> approverAttributes;
	ArrayList<String> userAttrbiutes;
	
	String smtpHost;
	int smtpPort;
	String smtpUser;
	String smtpPassword;
	String smtpSubject;
	String smtpFrom;
	boolean smtpTLS;
	
	boolean useSOCKSProxy;
	String socksProxyHost;
	
	String localhost;
	

	private int socksProxyPort;

	private Object broker;





	private SendMessageThread st;





	private javax.jms.Connection qcon;





	private javax.jms.Session taskSession;





	private javax.jms.Queue taskQueue;



	private GenericObjectPool<MessageProducerHolder> mpPool;
	

	private MessageProducer taskMP;





	private Scheduler scheduler;
	
	static Logger logger = Logger.getLogger(ProvisioningEngineImpl.class.getName());
	
	/**
	 * Default constructor
	 * @param cfgMgr
	 * @throws ProvisioningException
	 */
	public ProvisioningEngineImpl(ConfigManager cfgMgr) throws ProvisioningException {
		
		this.cfgMgr = cfgMgr;
		
		
		
		
		
		
		
		
		this.userStores = new HashMap<String,ProvisioningTargetImpl>();
		generateTargets(cfgMgr);
		
		this.workflows = new HashMap<String,WorkflowImpl>();
		
		approverAttributes = new ArrayList<String>();
		
		generateWorkflows();
		
		if (cfgMgr.getCfg().getProvisioning() != null && cfgMgr.getCfg().getProvisioning().getApprovalDB() != null ) {
			this.initLocalBroker();
			
			ApprovalDBType adbt = cfgMgr.getCfg().getProvisioning().getApprovalDB();
			this.smtpHost = adbt.getSmtpHost();
	        this.smtpPort = adbt.getSmtpPort();
	        this.smtpUser = adbt.getSmtpUser();
	        this.smtpPassword = adbt.getSmtpPassword();
	        this.smtpSubject = adbt.getSmtpSubject();
	        this.smtpFrom = adbt.getSmtpFrom();
	        this.smtpTLS = adbt.isSmtpTLS();
	        this.useSOCKSProxy = adbt.isSmtpUseSOCKSProxy();
	        if (this.useSOCKSProxy) {
	        	this.socksProxyHost = adbt.getSmtpSOCKSProxyHost();
	        	this.socksProxyPort = adbt.getSmtpSOCKSProxyPort(); 
	        }
	        
	        if (adbt.getSmtpLocalhost() != null && ! adbt.getSmtpLocalhost().isEmpty()) {
	        	this.localhost = adbt.getSmtpLocalhost();
	        } else {
	        	this.localhost = null;
	        }
	        
	        this.st = new SendMessageThread(this);
			this.st.lazyInit(cfgMgr);
			
			
			
			
		}
		
		
		
		if (cfgMgr.getCfg().getProvisioning() != null && cfgMgr.getCfg().getProvisioning().getApprovalDB() != null && cfgMgr.getCfg().getProvisioning().getApprovalDB().isEnabled()) {
			ApprovalDBType adbt = cfgMgr.getCfg().getProvisioning().getApprovalDB();
			this.userIDAttributeName = adbt.getUserIdAttribute();
			String driver = adbt.getDriver();
			logger.info("Driver : '" + driver + "'");
			
			String url = adbt.getUrl();
			logger.info("URL : " + url);
			String user = adbt.getUser();
			logger.info("User : " + user);
			String pwd = adbt.getPassword();
			logger.info("Password : **********");
			
			
			int maxCons = adbt.getMaxConns();
			logger.info("Max Cons : " + maxCons);
			int maxIdleCons = adbt.getMaxIdleConns();
			logger.info("maxIdleCons : " + maxIdleCons);
			
			
			DriverAdapterCPDS pool = new DriverAdapterCPDS();
			
			try {
				pool.setDriver(driver);
			} catch (ClassNotFoundException e) {
				throw new ProvisioningException("Could not load JDBC Driver",e);
			}
			pool.setUrl(url);
			pool.setUser(user);
			pool.setPassword(pwd);
			pool.setMaxActive(maxCons);
			pool.setMaxIdle(maxIdleCons);
			
			SharedPoolDataSource tds = new SharedPoolDataSource();
	        tds.setConnectionPoolDataSource(pool);
	        tds.setMaxActive(maxCons);
	        tds.setMaxWait(50);
	        
	        this.approvalConPool = tds;
	        
	        this.approverAttributes.addAll(cfgMgr.getCfg().getProvisioning().getApprovalDB().getApproverAttributes().getValue());
	        this.userAttrbiutes = new ArrayList<String>();
	        this.userAttrbiutes.addAll(cfgMgr.getCfg().getProvisioning().getApprovalDB().getUserAttributes().getValue());
	        
	        for (TargetType targetCfg : cfgMgr.getCfg().getProvisioning().getTargets().getTarget()) {
	        	try {
					Connection con = this.approvalConPool.getConnection();
					PreparedStatement ps = con.prepareStatement("SELECT id FROM targets WHERE name=?");
					ps.setString(1, targetCfg.getName());
					ResultSet rs = ps.executeQuery();
					if (rs.next()) {
						this.targetIDs.put(targetCfg.getName(), rs.getInt("id"));
					} else {
						PreparedStatement ps1 = con.prepareStatement("INSERT INTO targets (name) VALUES (?)",Statement.RETURN_GENERATED_KEYS);
						ps1.setString(1, targetCfg.getName());
						ps1.executeUpdate();
						ResultSet keys = ps1.getGeneratedKeys();
						keys.next();
						this.targetIDs.put(targetCfg.getName(), keys.getInt(1));
						ps1.close();
						keys.close();
					}
					rs.close();
					ps.close();
					con.close();
				} catch (SQLException e) {
					throw new ProvisioningException("Could not generate target id list",e);
				}
	        }
	        
	        
	        this.maskedAttributes = new HashSet<String>();
	        if (cfgMgr.getCfg().getProvisioning().getApprovalDB().getMaskAttribute() != null) {
	        	this.maskedAttributes.addAll(cfgMgr.getCfg().getProvisioning().getApprovalDB().getMaskAttribute());
	        }
	        
	        
		}
		
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.ProvisioningEngine#initWorkFlows()
	 */
	@Override
	public void initWorkFlows() throws ProvisioningException {
		Iterator<String> wfNames = this.workflows.keySet().iterator();
		while (wfNames.hasNext()) {
			String name = wfNames.next();
			this.workflows.get(name).init();
		}
		
		
		
		
		
		
	}

	private List<WorkflowTaskType> getWFTasks(String name) {
		for (WorkflowType wt : this.cfgMgr.getCfg().getProvisioning().getWorkflows().getWorkflow() ) {
			if (wt.getName().equalsIgnoreCase(name)) {
				return wt.getWorkflowTasksGroup();
			}
		}
		
		return null;
	}
	
	private void processCallWf(WorkflowType wft) {
		int i = 0;
		while (i < wft.getWorkflowTasksGroup().size()) {
			WorkflowTaskType wtt = wft.getWorkflowTasksGroup().get(i);
			
			
			if (wtt instanceof com.tremolosecurity.config.xml.CallWorkflowType) {
				List<WorkflowTaskType> tasks = this.getWFTasks(((com.tremolosecurity.config.xml.CallWorkflowType) wtt).getName()  );
				//remove call wf
				wft.getWorkflowTasksGroup().remove(i);
				//add tasks
				wft.getWorkflowTasksGroup().addAll(i, tasks);
				
				wtt = wft.getWorkflowTasksGroup().get(i);
			}
			
			this.processCallTask(wtt);
			
			i++;
			
		}
	}
	
	private void processCallTask(WorkflowTaskType wtt) {
		int i = 0;
		while (i<wtt.getWorkflowTasksGroup().size()) {
			WorkflowTaskType wttc = wtt.getWorkflowTasksGroup().get(i);
			
			
			if (wttc instanceof com.tremolosecurity.config.xml.CallWorkflowType) {
				List<WorkflowTaskType> tasks = this.getWFTasks(((com.tremolosecurity.config.xml.CallWorkflowType) wttc).getName()  );
				//remove call wf
				wtt.getWorkflowTasksGroup().remove(i);
				//add tasks
				wtt.getWorkflowTasksGroup().addAll(i, tasks);
				
				wttc = wtt.getWorkflowTasksGroup().get(i);
			}
			
			i++;
			
			this.processCallTask(wttc);
		}
	}
	
	private void generateWorkflows() throws ProvisioningException {
		if (cfgMgr.getCfg().getProvisioning() == null) {
			return;
		}
		
		for (WorkflowType wt : this.cfgMgr.getCfg().getProvisioning().getWorkflows().getWorkflow() ) {
			this.processCallWf(wt);
		}
		
		
		Iterator<WorkflowType> it = this.cfgMgr.getCfg().getProvisioning().getWorkflows().getWorkflow().iterator();
		while (it.hasNext()) {
			WorkflowType wft = it.next();
			String name = wft.getName();
			WorkflowImpl wf = new WorkflowImpl(this.cfgMgr,wft);
			this.workflows.put(name, wf);
		}
		
		
	}
	
	

	private void generateTargets(ConfigManager cfgMgr)
			throws ProvisioningException {
		
		
		if (cfgMgr.getCfg().getProvisioning() == null) {
			return;
		}
		
		this.targetIDs = new HashMap<String,Integer>();
		
		Iterator<TargetType> it = cfgMgr.getCfg().getProvisioning().getTargets().getTarget().iterator();
		
		while (it.hasNext()) {
			TargetType targetCfg = it.next();
			HashMap<String,Attribute> cfg = new HashMap<String,Attribute>();
			Iterator<ParamType> params =  targetCfg.getParams().getParam().iterator();
			while (params.hasNext()) {
				ParamType param = params.next();
				Attribute attr = cfg.get(param.getName());
				
				if (attr == null) {
					attr = new Attribute(param.getName());
					cfg.put(attr.getName(), attr);
				}
				
				attr.getValues().add(param.getValue());
			}
			
			
			UserStoreProvider provider = null;
			
			try {
				provider = (UserStoreProvider) Class.forName(targetCfg.getClassName()).newInstance();
			} catch (Exception e) {
				throw new ProvisioningException("Could not initialize target " + targetCfg.getName(),e);
			}
			
			MapIdentity mapper = new MapIdentity(targetCfg);
			this.userStores.put(targetCfg.getName(), new ProvisioningTargetImpl(targetCfg.getName(),provider,mapper));
			provider.init(cfg,cfgMgr,targetCfg.getName());
			
			
		}
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.ProvisioningEngine#getTarget(java.lang.String)
	 */
	@Override
	public ProvisioningTarget getTarget(String name) throws ProvisioningException {
		ProvisioningTarget target = this.userStores.get(name);
		
		if (target == null) {
			throw new ProvisioningException("Target " + name + " does not exist");
		}
		
		return target;
		
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.ProvisioningEngine#getWorkFlow(java.lang.String, com.tremolosecurity.provisioning.core.User)
	 */
	@Override
	public Workflow getWorkFlow(String name,User user) throws ProvisioningException {
		Connection con = null;
		try {
			con = this.getApprovalDBConn();
			int userid = WorkflowImpl.getUserNum(user, con, cfgMgr);
			if (user.isJitAddToAuditDB()) {
				return this.getWorkFlow(name);
			} else {
				return null;
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not load workflow",e);
		} finally {
			try {
				if (con != null) {
					con.close();
				}
			} catch (SQLException e) {
				
			}
			
		}
		
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.ProvisioningEngine#getWorkFlow(java.lang.String)
	 */
	@Override
	public Workflow getWorkFlow(String name) throws ProvisioningException {
		WorkflowImpl wf = this.workflows.get(name);
		
		if (wf == null) {
			throw new ProvisioningException("WorkflowImpl " + name + " does not exist");
		}
		
		
		

		
		
		wf = (WorkflowImpl) JsonReader.jsonToJava(JsonWriter.objectToJson(wf));
		
		wf.reInit(this.cfgMgr);
		
		
		if (this.approvalConPool != null) {
			Connection con = null;
			try {
				con = this.approvalConPool.getConnection();
				PreparedStatement ps = con.prepareStatement("INSERT INTO workflows (name,startTS) VALUES (?,?)",Statement.RETURN_GENERATED_KEYS);
				DateTime now = new DateTime();
				ps.setString(1, wf.name);
				ps.setTimestamp(2, new Timestamp(now.getMillis()));
				ps.executeUpdate();
				
				ResultSet rs = ps.getGeneratedKeys();
				rs.next();
				int id = rs.getInt(1);
				rs.close();
				ps.close();
				
				wf.setId(id);
				
			} catch (SQLException e) {
				throw new ProvisioningException("Could not generate workflow",e);
			} finally {
				if (con != null) {
					
					try {
						con.rollback();
					} catch (SQLException e1) {
						
					}
					
					try {
						con.close();
					} catch (SQLException e) {
						
					}
				}
			}
		}
		
		
		return wf;
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.ProvisioningEngine#getApprovalDBConn()
	 */
	@Override
	public Connection getApprovalDBConn() throws SQLException {
		if (this.approvalConPool != null) {
			return this.approvalConPool.getConnection();
		} else {
			return null;
		}
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.ProvisioningEngine#doApproval(int, java.lang.String, boolean, java.lang.String)
	 */
	@Override
	public void doApproval(int id,String userID,boolean approved,String reason) throws ProvisioningException {
		
		Connection con = null;
		try {
			
			StringBuffer b = new StringBuffer();
			b.append("(").append(this.userIDAttributeName).append("=").append(userID).append(")");
			LDAPSearchResults res = this.cfgMgr.getMyVD().search("o=Tremolo", 2, b.toString(), new ArrayList<String>());
			if (! res.hasMore()) {
				throw new ProvisioningException("Could not locate approver '" + userID + "'");
			}
			
			LDAPEntry approver = res.next();
			
			AuthInfo auinfo = new AuthInfo();
			auinfo.setUserDN(approver.getDN());
			LDAPAttributeSet attrs = approver.getAttributeSet();
			for (Object obj : attrs) {
				LDAPAttribute attr = (LDAPAttribute) obj;
				
			
				
				Attribute attrib = new Attribute(attr.getName());
				String[] vals = attr.getStringValueArray();
				for (String val : vals) {
					attrib.getValues().add(val);
				}
				
				auinfo.getAttribs().put(attrib.getName(), attrib);
			}
			
			while (res.hasMore()) res.next();
			
			con = this.approvalConPool.getConnection();
			
			PreparedStatement ps = con.prepareStatement("SELECT id FROM approvers WHERE userKey=?");
			ps.setString(1, userID);
			ResultSet rs = ps.executeQuery();
			
			if (logger.isDebugEnabled()) {
				logger.debug("Approver UserID : " + userID);
			}
			
			
			int approverID;
			
			if (! rs.next()) {
				
				PreparedStatement psi = con.prepareStatement("INSERT INTO approvers (userKey) VALUES (?)",Statement.RETURN_GENERATED_KEYS);
				psi.setString(1, userID);
				psi.executeUpdate();
				ResultSet keys = psi.getGeneratedKeys();
				keys.next();
				approverID = keys.getInt(1);
				keys.close();
				psi.close();
			} else {
				
				approverID = rs.getInt("id");
			}
			
			
			
			rs.close();
			
			con.setAutoCommit(false);
			
			for (String attrName : this.getApproverAttributes()) {
				StringBuffer sb = new StringBuffer("UPDATE approvers SET ").append(attrName).append("=? WHERE id=?");
				PreparedStatement psUpdate = con.prepareStatement(sb.toString());
				psUpdate.setString(
						1, approver.getAttribute(attrName).getStringValue());
				psUpdate.setInt(2, approverID);
				psUpdate.executeUpdate();
			}
			
			con.commit();
			
			
			ps = con.prepareStatement("SELECT workflowObj FROM approvals WHERE id=?");
			ps.setInt(1, id);
			rs = ps.executeQuery();
			
			if (! rs.next()) {
				throw new ProvisioningException("Approval not found");
			}
			
			Gson gson = new Gson();
			String json = rs.getString("workflowObj");
			Token token = gson.fromJson(json, Token.class);
			
			byte[] iv = org.bouncycastle.util.encoders.Base64.decode(token.getIv());
			
			
		    IvParameterSpec spec =  new IvParameterSpec(iv);
		    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, this.cfgMgr.getSecretKey(this.cfgMgr.getCfg().getProvisioning().getApprovalDB().getEncryptionKey()),spec);
		    
			byte[] encBytes = org.bouncycastle.util.encoders.Base64.decode(token.getEncryptedRequest());
			
			
			String jsonDecr = new String(cipher.doFinal(encBytes));
			
			
			Workflow wf = (Workflow) JsonReader.jsonToJava(jsonDecr);
			
			Approval approval = (Approval) wf.findCurrentApprovalTask();
			
			
			if (approval == null) {
				throw new ProvisioningException("Could not locate approval step");
			}
			
			AzSys az = new AzSys();
			
			
			if (! az.checkRules(auinfo, this.cfgMgr, approval.getAzRules())) {
				throw new ProvisioningException("Az of approval failed");
			}
			
			rs.close();
			ps.close();
			
			DateTime now = new DateTime();
			
			ps = con.prepareStatement("UPDATE approvals SET workflowObj=NULL ,approvedTS=?, approver=?, approved=?,reason=? WHERE id=?");
			ps.setTimestamp(1, new Timestamp(now.getMillis()));
			ps.setInt(2, approverID);
			ps.setInt(3, approved ? 1 : 0);
			ps.setString(4, reason);
			ps.setInt(5, id);
			
			ps.executeUpdate();
			
			con.commit();
			con.setAutoCommit(true);
			
			if (approved) {
				wf.reInit(cfgMgr);
				wf.restart();
			} else {
				wf.getUser().getAttribs().put("reason", new Attribute("reason",reason));
				
				if (! wf.getUser().getAttribs().containsKey(approval.getMailAttr())) {
					logger.warn("Can not send failure notification to " + wf.getUser().getUserID() + ", no mail found");
				} else {
					this.sendNotification(wf.getUser().getAttribs().get(approval.getMailAttr()).getValues().get(0),  approval.getFailureEmailMsg(),approval.getFailureEmailSubject(), wf.getUser());
				}
				
				
			}
			
		} catch (LDAPException e) {
			throw new ProvisioningException("Could not load approver",e);
		} catch (SQLException e) {
			throw new ProvisioningException("Could not load saved workflow",e);
		} catch (IOException e) {
			throw new ProvisioningException("Could not load saved workflow",e);
		} catch (ClassNotFoundException e) {
			throw new ProvisioningException("Could not load saved workflow",e);
		} catch (NoSuchAlgorithmException e) {
			throw new ProvisioningException("Could not decrypt workflow object",e);
		} catch (NoSuchPaddingException e) {
			throw new ProvisioningException("Could not decrypt workflow object",e);
		} catch (InvalidKeyException e) {
			throw new ProvisioningException("Could not decrypt workflow object",e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new ProvisioningException("Could not decrypt workflow object",e);
		} catch (IllegalBlockSizeException e) {
			throw new ProvisioningException("Could not decrypt workflow object",e);
		} catch (BadPaddingException e) {
			throw new ProvisioningException("Could not decrypt workflow object",e);
		} catch (ProvisioningException e) {
			throw e;
		} catch (Exception e) {
			throw new ProvisioningException("Could not send notification",e);
		} finally {
			if (con != null) {
				
				try {
					con.rollback();
				} catch (SQLException e1) {
					
				}
				
				try {
					con.close();
				} catch (SQLException e) {
					
				}
			}
		}
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.ProvisioningEngine#getUserIDAttribute()
	 */
	@Override
	public String getUserIDAttribute() {
		return this.userIDAttributeName;
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.ProvisioningEngine#getApproverAttributes()
	 */
	@Override
	public ArrayList<String> getApproverAttributes() {
		return this.approverAttributes;
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.ProvisioningEngine#getUserAttrbiutes()
	 */
	@Override
	public ArrayList<String> getUserAttrbiutes() {
		return userAttrbiutes;
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.ProvisioningEngine#logAction(java.lang.String, boolean, com.tremolosecurity.provisioning.core.ProvisioningEngineImpl.ActionType, int, com.tremolosecurity.provisioning.core.WorkflowImpl, java.lang.String, java.lang.String)
	 */
	@Override
	public void logAction(String target,boolean isEntry,ActionType actionType,int approval,Workflow wf,String attribute,String val) throws ProvisioningException {
		Connection con = null;
		
		if (this.maskedAttributes != null && this.maskedAttributes.contains(attribute)) {
			val = "##########";
		}
		
		if (this.approvalConPool == null) {
			StringBuffer line = new StringBuffer();
			line.append("target=").append(target);
			line.append(" entry=").append(isEntry);
			line.append(" ");
			switch (actionType) {
				case Add : line.append("Add"); break;
				case Delete : line.append("Delete"); break;
				case Replace : line.append("Replace"); break;
			}
			
			line.append(" user=").append(wf.getUser().getUserID()).append(" workflow=").append(wf.getName()).append(" approval=").append(approval).append(" ").append(attribute).append("='").append(val).append("'");
			logger.info(line);
		} else {
			try {
				con = this.getApprovalDBConn();
				PreparedStatement ps = con.prepareStatement("INSERT INTO auditLogs (isEntry,actionType,userid,approval,attribute,val,workflow,target) VALUES (?,?,?,?,?,?,?,?)");
				if (isEntry) {
					ps.setInt(1, 1);
				} else {
					ps.setInt(1, 0);
				}
			
				switch (actionType) {
					case Add : ps.setInt(2, 1); break;
					case Delete : ps.setInt(2, 2); break;
					case Replace : ps.setInt(2, 3); break;
				}
				
				ps.setInt(3, wf.getUserNum());
				ps.setInt(4, approval);
				ps.setString(5, attribute);
				ps.setString(6, val);
				ps.setInt(7, wf.getId());
				ps.setInt(8, this.targetIDs.get(target));
				
				ps.executeUpdate();
				ps.close();
				
			} catch (Exception e) {
				logger.error("Could not create audit record",e);
			} finally {
				if (con != null) {
					try {
						con.rollback();
					} catch (SQLException e) {

					}
					
					try {
						con.close();
					} catch (SQLException e) {
						
					}
				}
			}
			
		}
		
		
		
	}
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.ProvisioningEngine#sendNotification(java.lang.String, java.lang.String, com.tremolosecurity.provisioning.core.User)
	 */
	@Override
	public void sendNotification(String email,String msgTxt,User user) throws Exception {
		this.sendNotification(email, msgTxt, this.smtpSubject,user);
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.ProvisioningEngine#sendNotification(java.lang.String, java.lang.String, java.lang.String, com.tremolosecurity.provisioning.core.User)
	 */
	@Override
	public void sendNotification(String email,String msgTxt,String subject,User user) throws Exception {
		
		
		StringBuffer msgToSend = new StringBuffer();
		int begin,end;
		begin = msgTxt.indexOf("${");
		
		
		if (begin == -1) {
			msgToSend.append(msgTxt);
		} else {
			end = 0;
			do {
				msgToSend.append(msgTxt.substring(end,begin));
				end = msgTxt.indexOf('}',begin);
				String attrName = msgTxt.substring(begin + 2,end);
				if (user.getAttribs().containsKey(attrName)) {
					msgToSend.append(user.getAttribs().get(attrName).getValues().get(0));
				} 
				
				begin = msgTxt.indexOf("${",end);
				end++;
			} while (begin != -1);
			
			if (end > 0) {
				msgToSend.append(msgTxt.substring(end));
			}
			
		}
		
		SmtpMessage msg = new SmtpMessage();
		msg.to = email;
		msg.from = this.smtpFrom;
		msg.subject = subject;
		msg.msg = msgToSend.toString();
		
		this.st.enqEmail(msg);
		
		
	}
	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.ProvisioningEngine#getSmtpHost()
	 */
	@Override
	public String getSmtpHost() {
		return smtpHost;
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.ProvisioningEngine#getSmtpPort()
	 */
	@Override
	public int getSmtpPort() {
		return smtpPort;
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.ProvisioningEngine#getSmtpUser()
	 */
	@Override
	public String getSmtpUser() {
		return smtpUser;
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.ProvisioningEngine#getSmtpPassword()
	 */
	@Override
	public String getSmtpPassword() {
		return smtpPassword;
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.ProvisioningEngine#getSmtpSubject()
	 */
	@Override
	public String getSmtpSubject() {
		return smtpSubject;
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.ProvisioningEngine#getSmtpFrom()
	 */
	@Override
	public String getSmtpFrom() {
		return smtpFrom;
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.ProvisioningEngine#isSmtpTLS()
	 */
	@Override
	public boolean isSmtpTLS() {
		return smtpTLS;
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.ProvisioningEngine#isUseSOCKSProxy()
	 */
	@Override
	public boolean isUseSOCKSProxy() {
		return useSOCKSProxy;
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.ProvisioningEngine#getSocksProxyHost()
	 */
	@Override
	public String getSocksProxyHost() {
		return socksProxyHost;
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.ProvisioningEngine#getLocalhost()
	 */
	@Override
	public String getLocalhost() {
		return localhost;
	}

	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.ProvisioningEngine#getSocksProxyPort()
	 */
	@Override
	public int getSocksProxyPort() {
		return socksProxyPort;
	}
	

	
	
	
	private void initLocalBroker() throws ProvisioningException {
		if (this.isInternalQueue()) {
			this.broker = BrokerHolder.getInstance( cfgMgr, "local",this);
			try {
				BrokerHolder.doClearDLQ();
			} catch (Exception e) {
				throw new ProvisioningException("Could not process deal letter queue",e);
			}
		} else {
			this.mpPool = new GenericObjectPool<MessageProducerHolder>(new PooledMessageProducerFactory(this.cfgMgr,this));
			this.mpPool.setMaxTotal(this.cfgMgr.getCfg().getProvisioning().getQueueConfig().getMaxProducers());
			this.cfgMgr.addThread(new StopableThread() {

				@Override
				public void run() {
					// TODO Auto-generated method stub
					
				}

				@Override
				public void stop() {
					mpPool.close();
					mpPool.clear();
					
				}
				
			});
		}
	}

	@Override
	public javax.jms.Connection getQueueConnection() throws ProvisioningException, JMSException {
		if (this.isInternalQueue()) {
			if (this.qcon == null) {
				ActiveMQConnectionFactory cf = new ActiveMQConnectionFactory("vm://localhost/localhost");
				this.qcon = cf.createConnection();
				this.qcon.start();
			}
			
			return qcon; 
		} else {
			try {
				ConnectionFactory cf = (ConnectionFactory) Class.forName(this.cfgMgr.getCfg().getProvisioning().getQueueConfig().getConnectionFactory()).newInstance();
				for (ParamType pt : this.cfgMgr.getCfg().getProvisioning().getQueueConfig().getParam()) {
					String methodName = "set" + pt.getName().toUpperCase().charAt(0) + pt.getName().substring(1);
					Method m = Class.forName(this.cfgMgr.getCfg().getProvisioning().getQueueConfig().getConnectionFactory()).getMethod(methodName, String.class);
					m.invoke(cf, pt.getValue());
				}
				
				javax.jms.Connection con = cf.createConnection();
				con.start();
				return con;
			} catch (InstantiationException | IllegalAccessException
					| ClassNotFoundException | NoSuchMethodException | SecurityException | IllegalArgumentException | InvocationTargetException e) {
				throw new ProvisioningException("Could not generate connection",e);
			}
			
		}
		
	}

	public void endBroker() {
		if (this.isInternalQueue()) {
			if (this.qcon != null) {
				try {
					javax.jms.Connection con = qcon;
					this.qcon = null;
					con.close();
				} catch (JMSException e) {
					logger.warn("Could not close connection",e);
				}
				
			}
		}
		else {
			//TODO stop connections?
		}
		
	}
	
	
	public void enqueue(WorkflowHolder wfHolder) throws ProvisioningException {
		
		
		TextMessage bm;
		try {
			
			
			
			MessageProducer mp;
			MessageProducerHolder mph = null;
			
			if (this.isInternalQueue()) {
				mp = this.taskMP;
				bm = taskSession.createTextMessage();
				bm.setStringProperty("OriginalQueue", this.taskQueue.getQueueName());
			} else {
				mph = this.getTaskMessageProducer();
				mp = mph.getProducer();
				bm = mph.getSession().createTextMessage();
				bm.setStringProperty("OriginalQueue", ((javax.jms.Queue) mph.getProducer().getDestination()).getQueueName());
			}
			
			bm.setStringProperty("WorkflowName", wfHolder.getWorkflow().getName());
			bm.setStringProperty("WorkflowSubject", wfHolder.getUser().getUserID());
			
			TaskHolder holder = wfHolder.getWfStack().peek();
			WorkflowTask task = holder.getParent().get(holder.getPosition());
		
			
			bm.setStringProperty("WorkflowCurrentTask", task.getLabel());
			
			EncryptedMessage encMsg = this.encryptObject(wfHolder);
			
			String json = JsonWriter.objectToJson(encMsg);
			bm.setText(json);
			
			
			try {
				mp.send(bm);
			} finally {
				if (! this.isInternalQueue()) {
					this.returnMessageProducer(mph);
				}
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not enqueue message",e);
		}
		
	}
	
	public void execute() {
		
	}

	@Override
	public void returnQueueConnection(javax.jms.Connection con) {
		// TODO Auto-generated method stub
		
	}


	public MessageProducerHolder getTaskMessageProducer() throws Exception {
		return this.mpPool.borrowObject();
	}


	public void returnMessageProducer(MessageProducerHolder mph) {
		this.mpPool.returnObject(mph);
		
	}

	@Override
	public boolean isInternalQueue() {
		if (this.cfgMgr.getCfg().getProvisioning() != null && this.cfgMgr.getCfg().getProvisioning().getQueueConfig() != null && ! this.cfgMgr.getCfg().getProvisioning().getQueueConfig().isIsUseInternalQueue()) {
			return false;
		} else {
			return true;
		}
	}

	@Override
	public void initMessageConsumers() throws ProvisioningException {
		try {
			
			if (cfgMgr.getCfg().getProvisioning() == null) {
				return;
			}
			
			String taskQueueName = "TremoloUnisonTaskQueue";
			if (this.cfgMgr.getCfg().getProvisioning() != null && this.cfgMgr.getCfg().getProvisioning().getQueueConfig() != null) {
				taskQueueName = this.cfgMgr.getCfg().getProvisioning().getQueueConfig().getTaskQueueName();
			}
			
        	if (this.isInternalQueue()) {
	        	javax.jms.Connection con = this.getQueueConnection();
				TaskConsumer taskConsumer = new TaskConsumer(this,this.cfgMgr);
				this.taskSession = con.createSession(false, javax.jms.Session.AUTO_ACKNOWLEDGE);
				this.taskQueue = taskSession.createQueue(taskQueueName);
				this.taskMP = taskSession.createProducer(taskQueue);
				MessageConsumer mc = taskSession.createConsumer(taskQueue);
				
				mc.setMessageListener(taskConsumer);
				
				cfgMgr.addThread(new JMSMessageCloser(taskSession,mc));
        	} else {
        		
        		for (int i=0;i<this.cfgMgr.getCfg().getProvisioning().getQueueConfig().getMaxConsumers();i++) {
        			javax.jms.Connection con = this.getQueueConnection();
        			TaskConsumer taskConsumer = new TaskConsumer(this,this.cfgMgr);
					javax.jms.Session taskSession = con.createSession(false, javax.jms.Session.AUTO_ACKNOWLEDGE);
					javax.jms.Queue taskQueue = taskSession.createQueue(taskQueueName);
					MessageConsumer mc = taskSession.createConsumer(taskQueue);
					
					mc.setMessageListener(taskConsumer);
					
					cfgMgr.addThread(new JMSMessageCloser(con,taskSession,mc));
        		}
        	}
		} catch (JMSException e) {
			throw new ProvisioningException("Could not initialize task message system",e);
		}
		
	}

	@Override
	public EncryptedMessage encryptObject(Object o) throws ProvisioningException {
		SecretKey key = this.cfgMgr.getSecretKey(this.cfgMgr.getCfg().getProvisioning().getQueueConfig().getEncryptionKeyName());
		if (key == null) {
			throw new ProvisioningException("Queue message encryption key not found");
		}
		
		
		try {
			String json = JsonWriter.objectToJson(o);
			
			EncryptedMessage msg = new EncryptedMessage();
			
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			msg.setMsg(cipher.doFinal(json.getBytes("UTF-8")));
			msg.setIv(cipher.getIV());
			return msg;
		} catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			throw new ProvisioningException("Could not encrypt message",e);
		}
		
	}

	@Override
	public Object decryptObject(EncryptedMessage msg) throws ProvisioningException {
		SecretKey key = this.cfgMgr.getSecretKey(this.cfgMgr.getCfg().getProvisioning().getQueueConfig().getEncryptionKeyName());
		if (key == null) {
			throw new ProvisioningException("Queue message encryption key not found");
		}
		
		IvParameterSpec spec =  new IvParameterSpec(msg.getIv());
	    Cipher cipher;
		try {
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, key,spec);
			
			
			byte[] bytes = cipher.doFinal(msg.getMsg());
			
			return JsonReader.jsonToJava(new String(bytes));
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException  e) {
			throw new ProvisioningException("Could not decrypt message",e);
		}
		
	}

	@Override
	public void initScheduler() throws ProvisioningException {
		if (this.cfgMgr.getCfg().getProvisioning() == null || this.cfgMgr.getCfg().getProvisioning().getScheduler() == null) {
			logger.warn("Scheduler not defined");
			return;
		}
		
		SchedulingType sct = this.cfgMgr.getCfg().getProvisioning().getScheduler();
		
		Properties scheduleProps = new Properties();
		
		scheduleProps.setProperty("org.quartz.scheduler.instanceName", sct.getInstanceLabel());
		
		String instanceLabel = null;
		try {
			Enumeration<NetworkInterface> enumer = NetworkInterface.getNetworkInterfaces();
			while (enumer.hasMoreElements()) {
				NetworkInterface ni = enumer.nextElement();
				Enumeration<InetAddress> enumeri = ni.getInetAddresses();
				while (enumeri.hasMoreElements()) {
					InetAddress addr = enumeri.nextElement();
					if (addr.getHostAddress().startsWith(sct.getInstanceIPMask())) {
						instanceLabel = addr.getHostAddress();
					}
				}
			}
		} catch (SocketException e) {
			throw new ProvisioningException("Could not read network addresses",e);
		}
		
		if (instanceLabel == null) {
			logger.warn("No IP starts with '" + sct.getInstanceIPMask() + "'");
			instanceLabel = "AUTO";
		}
		
		scheduleProps.setProperty("org.quartz.scheduler.instanceId", instanceLabel);
		scheduleProps.setProperty("org.quartz.threadPool.threadCount", Integer.toString(sct.getThreadCount()));
		
		if (sct.isUseDB()) {
			scheduleProps.setProperty("org.quartz.jobStore.class", "org.quartz.impl.jdbcjobstore.JobStoreTX");
			scheduleProps.setProperty("org.quartz.jobStore.driverDelegateClass", sct.getScheduleDB().getDelegateClassName());
			scheduleProps.setProperty("org.quartz.jobStore.dataSource", "scheduleDB");
			scheduleProps.setProperty("org.quartz.dataSource.scheduleDB.driver", sct.getScheduleDB().getDriver());
			scheduleProps.setProperty("org.quartz.dataSource.scheduleDB.URL", sct.getScheduleDB().getUrl());
			scheduleProps.setProperty("org.quartz.dataSource.scheduleDB.user", sct.getScheduleDB().getUser());
			scheduleProps.setProperty("org.quartz.dataSource.scheduleDB.password", sct.getScheduleDB().getPassword());
			scheduleProps.setProperty("org.quartz.dataSource.scheduleDB.maxConnections", Integer.toString(sct.getScheduleDB().getMaxConnections()));
			scheduleProps.setProperty("org.quartz.dataSource.scheduleDB.validationQuery", sct.getScheduleDB().getValidationQuery());
			scheduleProps.setProperty("org.quartz.jobStore.useProperties", "true");
			scheduleProps.setProperty("org.quartz.jobStore.isClustered", "true");
		} else {
			scheduleProps.setProperty("org.quartz.jobStore.class", "org.quartz.simpl.RAMJobStore");
		}
		
		try {
			
			/*String classpath = System.getProperty("java.class.path");
			String[] classpathEntries = classpath.split(File.pathSeparator);
			for (String cp : classpathEntries) {
				System.out.println(cp);
			}*/
			
			
			PrintStream out = new PrintStream(new FileOutputStream(System.getenv("TREMOLO_QUARTZ_DIR") + "/quartz.properties"));
			scheduleProps.store(out, "Unison internal scheduler properties");
			out.flush();
			out.close();
		} catch (IOException e) {
			throw new ProvisioningException("Could not write to quartz.properties",e);
		}
		
		try {
			this.scheduler = StdSchedulerFactory.getDefaultScheduler();
			this.scheduler.start();
			this.cfgMgr.addThread(new StopScheduler(this.scheduler));
			HashSet<String> jobKeys = new HashSet<String>();
			
			for (JobType jobType : sct.getJob()) {
				jobKeys.add(jobType.getName() + "-" + jobType.getGroup());
				JobKey jk = new JobKey(jobType.getName(),jobType.getGroup());
				JobDetail jd = this.scheduler.getJobDetail(jk);
				if (jd == null) {
					logger.info("Adding new job '" + jobType.getName() + "' / '" + jobType.getGroup() + "'");
					try {
						addJob(jobType, jk);
						
					} catch (ClassNotFoundException e) {
						throw new ProvisioningException("Could not initialize job",e);
					}
					
				} else {
					//check to see if we need to modify
					StringBuffer cron = new StringBuffer();
					cron.append(jobType.getCronSchedule().getSeconds()).append(' ')
					    .append(jobType.getCronSchedule().getMinutes()).append(' ')
					    .append(jobType.getCronSchedule().getHours()).append(' ')
					    .append(jobType.getCronSchedule().getDayOfMonth()).append(' ')
					    .append(jobType.getCronSchedule().getMonth()).append(' ')
					    .append(jobType.getCronSchedule().getDayOfWeek()).append(' ')
					    .append(jobType.getCronSchedule().getYear());
					
					Properties configProps = new Properties();
					for (ParamType pt : jobType.getParam()) {
						configProps.setProperty(pt.getName(), pt.getValue());
					}
					
					Properties jobProps = new Properties();
					for (String key : jd.getJobDataMap().getKeys()) {
						jobProps.setProperty(key, (String) jd.getJobDataMap().getString(key));
					}
					
					List<Trigger> triggers = (List<Trigger>) scheduler.getTriggersOfJob(jd.getKey());
					CronTrigger trigger = (CronTrigger) triggers.get(0);
					
					if (! jobType.getClassName().equals(jd.getJobClass().getName())) {
						logger.info("Reloading job '" + jobType.getName() + "' / '" + jobType.getGroup() + "' - change in class name");
						reloadJob(jobType,jd);
					} else if (! cron.toString().equalsIgnoreCase(trigger.getCronExpression())) {
						logger.info("Reloading job '" + jobType.getName() + "' / '" + jobType.getGroup() + "' - change in schedule");
						reloadJob(jobType,jd);
					} else if (! configProps.equals(jobProps)) {
						logger.info("Reloading job '" + jobType.getName() + "' / '" + jobType.getGroup() + "' - change in properties");
						reloadJob(jobType,jd);
					}
				}
			}
			
			
			for (String groupName : scheduler.getJobGroupNames()) {
				 
			     for (JobKey jobKey : scheduler.getJobKeys(GroupMatcher.jobGroupEquals(groupName))) {
			 
				  String jobName = jobKey.getName();
				  String jobGroup = jobKey.getGroup();
			 
				  //get job's trigger
				  List<Trigger> triggers = (List<Trigger>) scheduler.getTriggersOfJob(jobKey);
				  
				  if (! jobKeys.contains(jobName + "-" + jobGroup)) {
					  logger.info("Removing jab '" + jobName + "' / '" + jobGroup + "'");
					  scheduler.deleteJob(jobKey);
				  }
		 
			  }
		 
		    }
		
			
			
		} catch (SchedulerException e) {
			throw new ProvisioningException("Could not initialize scheduler",e);
		} catch (ClassNotFoundException e) {
			throw new ProvisioningException("Could not initialize scheduler",e);
		}
		
		
		
	}

	private void addJob(JobType jobType, JobKey jk)
			throws ClassNotFoundException, SchedulerException {
		JobDetail jd;
		JobBuilder jb = JobBuilder.newJob((Class<? extends Job>) Class.forName(jobType.getClassName()));
		for (ParamType pt : jobType.getParam()) {
			jb.usingJobData(pt.getName(), pt.getValue());
		}
		jb.withIdentity(jk);
		
		jd = jb.build();
		
		StringBuffer cron = new StringBuffer();
		cron.append(jobType.getCronSchedule().getSeconds()).append(' ')
		    .append(jobType.getCronSchedule().getMinutes()).append(' ')
		    .append(jobType.getCronSchedule().getHours()).append(' ')
		    .append(jobType.getCronSchedule().getDayOfMonth()).append(' ')
		    .append(jobType.getCronSchedule().getMonth()).append(' ')
		    .append(jobType.getCronSchedule().getDayOfWeek()).append(' ')
		    .append(jobType.getCronSchedule().getYear());
		
		TriggerBuilder tb = TriggerBuilder.newTrigger()
				                           .withIdentity("trigger_" + jobType.getName(),jobType.getGroup())
				                           .withSchedule(CronScheduleBuilder.cronSchedule(cron.toString()).withMisfireHandlingInstructionFireAndProceed());;
				                        		
		this.scheduler.scheduleJob(jd, tb.build());
	}

	private void reloadJob(JobType jobType, JobDetail jd) throws SchedulerException, ClassNotFoundException {
		this.scheduler.deleteJob(jd.getKey());
		addJob(jobType, jd.getKey());
		
	}

	@Override
	public void initListeners() throws ProvisioningException {
		if (this.cfgMgr.getCfg().getProvisioning() == null || this.cfgMgr.getCfg().getProvisioning().getListeners() == null) {
			logger.warn("No listeners defined");
			return;
		}
		
		try {
			javax.jms.Connection con = this.getQueueConnection();
			
			
			
			for (MessageListenerType mlt : this.cfgMgr.getCfg().getProvisioning().getListeners().getListener()) {
				UnisonMessageListener uml = (UnisonMessageListener) Class.forName(mlt.getClassName()).newInstance();
				
				HashMap<String,Attribute> attrs = new HashMap<String,Attribute>();
				for (ParamType pt : mlt.getParams()) {
					Attribute attr = attrs.get(pt.getName());
					if (attr == null) {
						attr = new Attribute(pt.getName());
						attrs.put(pt.getName(), attr);
					}
					attr.getValues().add(pt.getValue());
				}
				
				uml.init(this.cfgMgr,attrs);
				
				javax.jms.Session listenerSession = con.createSession(false, javax.jms.Session.AUTO_ACKNOWLEDGE);
				javax.jms.Queue taskQueue = listenerSession.createQueue(mlt.getQueueName());
				MessageConsumer mc = listenerSession.createConsumer(taskQueue);
				mc.setMessageListener(uml);
				
				cfgMgr.addThread(new JMSMessageCloser(con,listenerSession,mc));
			}
		} catch (Exception e) {
			
		}
	}
	
	
}

class SmtpAuthenticator extends Authenticator {
	String username;
	String password;
	
	public SmtpAuthenticator(String username,String password) {
		this.username = username;
		this.password = password;
	}
	
	@Override
	protected PasswordAuthentication getPasswordAuthentication() {
		
		return new PasswordAuthentication(username,password);
	}
	
	
	
	
}

class SendMessageThread implements MessageListener {
	static Logger logger = Logger.getLogger(SendMessageThread.class.getName());
	
	
	
	boolean running = true;

	private ProvisioningEngine prov;



	private MessageProducer mp;



	private javax.jms.Session session;



	private String smtpQueue;
	
	public SendMessageThread(ProvisioningEngine prov) throws ProvisioningException {
		this.prov = prov;
		
		
	}
	
	public void lazyInit(ConfigManager cfgMgr) throws ProvisioningException {
		try {
			javax.jms.Connection connection = prov.getQueueConnection();
			//((ActiveMQConnection)connection ).getRedeliveryPolicy().setMaximumRedeliveries(3);
			//connection.start();
			this.session = connection.createSession(false, javax.jms.Session.AUTO_ACKNOWLEDGE);
			
			smtpQueue = "TremoloUnisonSMTPQueue";
			if (cfgMgr.getCfg().getProvisioning() != null && cfgMgr.getCfg().getProvisioning().getQueueConfig() != null) {
				smtpQueue = cfgMgr.getCfg().getProvisioning().getQueueConfig().getSmtpQueueName();
			}
			
			javax.jms.Queue queue = session.createQueue(smtpQueue);
			this.mp = session.createProducer(queue);
			MessageConsumer mc = session.createConsumer(queue);
			
			mc.setMessageListener(this);
			
			cfgMgr.addThread(new JMSMessageCloser(session,mc));
			
			
			
		} catch (JMSException e) {
			throw new ProvisioningException("Could not initialize JMS",e);
		}
	}
	
	public void enqEmail(SmtpMessage msg) throws IOException, JMSException {

		
		ObjectMessage bm = session.createObjectMessage();
		bm.setObject(msg);
		bm.setStringProperty("OriginalQueue", this.smtpQueue);
		mp.send(bm);
		//session.commit();
		
	}
	
	private void sendEmail(SmtpMessage msg) throws MessagingException {
		Properties props = new Properties();
		
		props.setProperty("mail.smtp.host", prov.getSmtpHost());
		props.setProperty("mail.smtp.port", Integer.toString(prov.getSmtpPort()));
		props.setProperty("mail.smtp.user", prov.getSmtpUser());
		props.setProperty("mail.smtp.auth", "true");
		props.setProperty("mail.transport.protocol", "smtp");
		props.setProperty("mail.smtp.starttls.enable", Boolean.toString(prov.isSmtpTLS()));
		//props.setProperty("mail.debug", "true");
		//props.setProperty("mail.socket.debug", "true");
		
		if (prov.getLocalhost() != null) {
			props.setProperty("mail.smtp.localhost", prov.getLocalhost());
		}
		
		if (prov.isUseSOCKSProxy()) {
			
			
			props.setProperty("mail.smtp.socks.host", prov.getSocksProxyHost());
			
			props.setProperty("mail.smtp.socks.port", Integer.toString(prov.getSocksProxyPort()));
			props.setProperty("mail.smtps.socks.host", prov.getSocksProxyHost());
			
			props.setProperty("mail.smtps.socks.port", Integer.toString(prov.getSocksProxyPort()));
		}
		
		
		
		
		//Session session = Session.getInstance(props, new SmtpAuthenticator(this.smtpUser,this.smtpPassword));
		
		Session session = Session.getInstance(props, 
                new Authenticator(){
            protected PasswordAuthentication getPasswordAuthentication() {
               return new PasswordAuthentication(prov.getSmtpUser(), prov.getSmtpPassword());
            }});
		//Session session = Session.getInstance(props, null);
		session.setDebugOut(System.out);
		//session.setDebug(true);
		//Transport tr = session.getTransport("smtp");
		//tr.connect();
		
		//tr.connect(this.smtpHost,this.smtpPort, this.smtpUser, this.smtpPassword);

		Message msgToSend = new MimeMessage(session);
		msgToSend.setFrom(new InternetAddress(msg.from));
		msgToSend.addRecipient( Message.RecipientType.TO, new InternetAddress(msg.to));
		msgToSend.setSubject(msg.subject);
		msgToSend.setText(msg.msg);
		
		msgToSend.saveChanges();
		Transport.send(msgToSend);
		
		//tr.sendMessage(msg, msg.getAllRecipients());
		//tr.close();
	}



	@Override
	public void onMessage(javax.jms.Message msg) {
		ObjectMessage fromq = (ObjectMessage) msg;
		
		try {
			this.sendEmail((SmtpMessage) fromq.getObject());
			fromq.acknowledge();
			//session.commit();
		} catch (MessagingException | JMSException e) {
			logger.error("Could not send email",e);
			
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			PrintWriter baout = new PrintWriter(baos);
			e.printStackTrace(baout);
			baout.flush();
			baout.close();
			StringBuffer b = new StringBuffer();
			b.append("Could not send email\n").append(new String(baos.toByteArray()));
			throw new RuntimeException(b.toString(),e);
			
		}
		
	}
	
}