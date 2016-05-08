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

import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;

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
import org.apache.commons.net.smtp.SMTP;
import org.apache.commons.pool2.impl.GenericObjectPool;
import org.apache.log4j.Logger;
import org.hibernate.Query;
import org.hibernate.SessionFactory;
import org.hibernate.boot.MetadataSources;
import org.hibernate.boot.cfgxml.spi.LoadedConfig;
import org.hibernate.boot.jaxb.cfg.spi.JaxbCfgHibernateConfiguration;
import org.hibernate.boot.jaxb.cfg.spi.JaxbCfgMappingReferenceType;
import org.hibernate.boot.jaxb.cfg.spi.JaxbCfgHibernateConfiguration.JaxbCfgSessionFactory;
import org.hibernate.boot.registry.StandardServiceRegistry;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.hibernate.cfg.Configuration;
import org.hibernate.resource.transaction.spi.TransactionStatus;
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
import com.tremolosecurity.config.xml.WorkflowChoiceTaskType;
import com.tremolosecurity.config.xml.WorkflowTaskType;
import com.tremolosecurity.config.xml.WorkflowType;
import com.tremolosecurity.json.Token;
import com.tremolosecurity.openunison.OpenUnisonConstants;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.mapping.MapIdentity;
import com.tremolosecurity.provisioning.objects.AllowedApprovers;
import com.tremolosecurity.provisioning.objects.Approvals;
import com.tremolosecurity.provisioning.objects.ApproverAttributes;
import com.tremolosecurity.provisioning.objects.Approvers;
import com.tremolosecurity.provisioning.objects.AuditLogType;
import com.tremolosecurity.provisioning.objects.AuditLogs;
import com.tremolosecurity.provisioning.objects.Escalation;
import com.tremolosecurity.provisioning.objects.Targets;
import com.tremolosecurity.provisioning.objects.UserAttributes;
import com.tremolosecurity.provisioning.objects.Users;
import com.tremolosecurity.provisioning.objects.WorkflowParameters;
import com.tremolosecurity.provisioning.objects.Workflows;
import com.tremolosecurity.provisioning.scheduler.StopScheduler;
import com.tremolosecurity.provisioning.tasks.Approval;
import com.tremolosecurity.provisioning.util.EncryptedMessage;
import com.tremolosecurity.provisioning.util.MessageProducerHolder;
import com.tremolosecurity.provisioning.util.PooledMessageProducerFactory;
import com.tremolosecurity.provisioning.util.TaskHolder;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.AzSys;
import com.tremolosecurity.proxy.az.AzRule;
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
	HashMap<String,Targets> targetIDs;
	
	HashMap<String,AuditLogType> auditLogTypes;
	
	String userIDAttributeName;
	
	
	
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



	private SessionFactory sessionFactory;
	
	
	private void initializeHibernate(ApprovalDBType adbt) {
		StandardServiceRegistryBuilder builder = new StandardServiceRegistryBuilder();
		
		
		Configuration config = new Configuration();
		config.setProperty("hibernate.connection.driver_class", adbt.getDriver());
		config.setProperty("hibernate.connection.password", adbt.getPassword());
		config.setProperty("hibernate.connection.url", adbt.getUrl());
		config.setProperty("hibernate.connection.username", adbt.getUser());
		config.setProperty("hibernate.dialect", adbt.getHibernateDialect());
		config.setProperty("hibernate.hbm2ddl.auto", "update");
		config.setProperty("show_sql", "true");
		config.setProperty("hibernate.current_session_context_class", "thread");
		
		config.setProperty("hibernate.c3p0.max_size", Integer.toString(adbt.getMaxConns()));
		config.setProperty("hibernate.c3p0.maxIdleTimeExcessConnections", Integer.toString(adbt.getMaxIdleConns()));
		config.setProperty("hibernate.c3p0.testConnectionOnCheckout", "true");
		config.setProperty("hibernate.c3p0.autoCommitOnClose", "true");
		
		if (adbt.getHibernateProperty() != null) {
			for (ParamType pt : adbt.getHibernateProperty()) {
				config.setProperty(pt.getName(), pt.getValue());
			}
		}
		
		//config.setProperty("hibernate.c3p0.debugUnreturnedConnectionStackTraces", "true");
		//config.setProperty("hibernate.c3p0.unreturnedConnectionTimeout", "30");
		
		
		String validationQuery = adbt.getValidationQuery();
		if (validationQuery == null) {
			validationQuery = "SELECT 1";
		}
		config.setProperty("hibernate.c3p0.preferredTestQuery", validationQuery);
		
		

		
		JaxbCfgHibernateConfiguration jaxbCfg = new JaxbCfgHibernateConfiguration();
		jaxbCfg.setSessionFactory(new JaxbCfgSessionFactory());
		
		JaxbCfgMappingReferenceType mrt = new JaxbCfgMappingReferenceType();
		mrt.setClazz(AllowedApprovers.class.getName());
		jaxbCfg.getSessionFactory().getMapping().add(mrt);
		
		mrt = new JaxbCfgMappingReferenceType();
		mrt.setClazz(Approvals.class.getName());
		jaxbCfg.getSessionFactory().getMapping().add(mrt);
		
		mrt = new JaxbCfgMappingReferenceType();
		mrt.setClazz(ApproverAttributes.class.getName());
		jaxbCfg.getSessionFactory().getMapping().add(mrt);
		
		mrt = new JaxbCfgMappingReferenceType();
		mrt.setClazz(Approvers.class.getName());
		jaxbCfg.getSessionFactory().getMapping().add(mrt);
		
		mrt = new JaxbCfgMappingReferenceType();
		mrt.setClazz(AuditLogs.class.getName());
		jaxbCfg.getSessionFactory().getMapping().add(mrt);
		
		mrt = new JaxbCfgMappingReferenceType();
		mrt.setClazz(AuditLogType.class.getName());
		jaxbCfg.getSessionFactory().getMapping().add(mrt);
		
		mrt = new JaxbCfgMappingReferenceType();
		mrt.setClazz(Escalation.class.getName());
		jaxbCfg.getSessionFactory().getMapping().add(mrt);
		
		mrt = new JaxbCfgMappingReferenceType();
		mrt.setClazz(Targets.class.getName());
		jaxbCfg.getSessionFactory().getMapping().add(mrt);
		
		mrt = new JaxbCfgMappingReferenceType();
		mrt.setClazz(UserAttributes.class.getName());
		jaxbCfg.getSessionFactory().getMapping().add(mrt);
		
		mrt = new JaxbCfgMappingReferenceType();
		mrt.setClazz(Users.class.getName());
		jaxbCfg.getSessionFactory().getMapping().add(mrt);
		
		mrt = new JaxbCfgMappingReferenceType();
		mrt.setClazz(WorkflowParameters.class.getName());
		jaxbCfg.getSessionFactory().getMapping().add(mrt);
		
		mrt = new JaxbCfgMappingReferenceType();
		mrt.setClazz(Workflows.class.getName());
		jaxbCfg.getSessionFactory().getMapping().add(mrt);
		
		LoadedConfig lc = LoadedConfig.consume(jaxbCfg);
		
		
		
		StandardServiceRegistry registry = builder.configure(lc).applySettings(config.getProperties()).build();
		try {
			sessionFactory = new MetadataSources( registry ).buildMetadata().buildSessionFactory();
			
			this.cfgMgr.addThread(new StopableThread() {

				@Override
				public void run() {
					// TODO Auto-generated method stub
					
				}

				@Override
				public void stop() {
					logger.info("Stopping hibernate");
					sessionFactory.close();
					
				}
				
			});
			
			org.hibernate.Session session = sessionFactory.openSession();
			
			
			
			this.auditLogTypes = new HashMap<String,AuditLogType>();
			
			
			List<AuditLogType> alts = session.createCriteria(AuditLogType.class).list();
			if ( alts.size() == 0 ) {
				session.beginTransaction();
				AuditLogType alt = new AuditLogType();
				alt.setName("Add");
				session.save(alt);
				
				this.auditLogTypes.put("add", alt);
				
				alt = new AuditLogType();
				alt.setName("Delete");
				session.save(alt);
				
				this.auditLogTypes.put("delete", alt);
				
				alt = new AuditLogType();
				alt.setName("Replace");
				session.save(alt);
				
				this.auditLogTypes.put("replace", alt);
				
				session.getTransaction().commit();
			} else {
				for (AuditLogType alt : alts) {
					this.auditLogTypes.put(alt.getName().toLowerCase(), alt);
				}
			}
			
			
			
			session.close();
			
		}
		catch (Exception e) {
			e.printStackTrace();
			// The registry would be destroyed by the SessionFactory, but we had trouble building the SessionFactory
			// so destroy it manually.
			StandardServiceRegistryBuilder.destroy( registry );
		}
	}
	
	
	/**
	 * Default constructor
	 * @param cfgMgr
	 * @throws ProvisioningException
	 */
	public ProvisioningEngineImpl(ConfigManager cfgMgr) throws ProvisioningException {
		
		this.cfgMgr = cfgMgr;
		
		
		
		this.initLocalBroker();
		
		
		
		
		this.userStores = new HashMap<String,ProvisioningTargetImpl>();
		generateTargets(cfgMgr);
		
		this.workflows = new HashMap<String,WorkflowImpl>();
		
		approverAttributes = new ArrayList<String>();
		
		generateWorkflows();
		
		if (cfgMgr.getCfg().getProvisioning() != null && cfgMgr.getCfg().getProvisioning().getApprovalDB() != null ) {
			
			
			ApprovalDBType adbt = cfgMgr.getCfg().getProvisioning().getApprovalDB();
			
			this.initializeHibernate(adbt);
			
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
			
			
			
	        
	        logger.info("Validation Query : '" + adbt.getValidationQuery() + "'");
	        
	        
	        
	        
	        this.approverAttributes.addAll(cfgMgr.getCfg().getProvisioning().getApprovalDB().getApproverAttributes().getValue());
	        this.userAttrbiutes = new ArrayList<String>();
	        this.userAttrbiutes.addAll(cfgMgr.getCfg().getProvisioning().getApprovalDB().getUserAttributes().getValue());
	        
	        org.hibernate.Session session = sessionFactory.openSession();
	        
	        try {
		        List<Targets> targets = session.createCriteria(Targets.class).list();
		        for (Targets target : targets) {
		        	this.targetIDs.put(target.getName(), target);
		        }
		        
		        
		        session.beginTransaction();
		        
		        for (TargetType targetCfg : cfgMgr.getCfg().getProvisioning().getTargets().getTarget()) {
		        	if (! this.targetIDs.containsKey(targetCfg.getName())) {
						Targets target = new Targets();
						target.setName(targetCfg.getName());
						session.save(target);
						this.targetIDs.put(target.getName(), target);
					}
		        }
		        
		        session.getTransaction().commit();
	        } finally {
	        	session.close();
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
			
			
			if (wtt instanceof com.tremolosecurity.config.xml.WorkflowChoiceTaskType) {
				this.processCallTask((WorkflowChoiceTaskType) wtt);
			}
			
			i++;
			
		}
	}
	
	private void processCallTask(WorkflowChoiceTaskType wtt) {
		int i = 0;
		
		
		if (wtt.getOnSuccess() != null) {
			while (i < wtt.getOnSuccess().getWorkflowTasksGroup().size()) {
				WorkflowTaskType wttc = wtt.getOnSuccess().getWorkflowTasksGroup().get(i);
				if (wttc instanceof com.tremolosecurity.config.xml.CallWorkflowType) {
					com.tremolosecurity.config.xml.CallWorkflowType callTask = (com.tremolosecurity.config.xml.CallWorkflowType) wttc;
					
					List<WorkflowTaskType> tasks = this.getWFTasks(callTask.getName()  );
					//remove call wf
					wtt.getOnSuccess().getWorkflowTasksGroup().remove(i);
					//add tasks
					wtt.getOnSuccess().getWorkflowTasksGroup().addAll(i, tasks);
					
					wttc = wtt.getOnSuccess().getWorkflowTasksGroup().get(i);
				}
				
				i++;
				
				if (wttc instanceof WorkflowChoiceTaskType) {
					this.processCallTask((WorkflowChoiceTaskType) wttc);
				}
			}
			
		}
		
		if (wtt.getOnFailure() != null) {
			while (i < wtt.getOnFailure().getWorkflowTasksGroup().size()) {
				WorkflowTaskType wttc = wtt.getOnFailure().getWorkflowTasksGroup().get(i);
				if (wttc instanceof com.tremolosecurity.config.xml.CallWorkflowType) {
					com.tremolosecurity.config.xml.CallWorkflowType callTask = (com.tremolosecurity.config.xml.CallWorkflowType) wttc;
					
					List<WorkflowTaskType> tasks = this.getWFTasks(callTask.getName()  );
					//remove call wf
					wtt.getOnFailure().getWorkflowTasksGroup().remove(i);
					//add tasks
					wtt.getOnFailure().getWorkflowTasksGroup().addAll(i, tasks);
					
					wttc = wtt.getOnFailure().getWorkflowTasksGroup().get(i);
				}
				
				i++;
				
				if (wttc instanceof WorkflowChoiceTaskType) {
					this.processCallTask((WorkflowChoiceTaskType) wttc);
				}
			}
			
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
		
		this.targetIDs = new HashMap<String,Targets>();
		
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
		org.hibernate.Session session = sessionFactory.openSession();
		try {
			
			int userid = WorkflowImpl.getUserNum(user, session, cfgMgr);
			//if (user.isJitAddToAuditDB()) {
				return this.getWorkFlow(name);
			//} else {
			//	return null;
			//}
		} catch (Exception e) {
			throw new ProvisioningException("Could not load workflow",e);
		} finally {
			
			if (session != null) {
				session.close();
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
		
		
		if (this.sessionFactory != null) {
			Connection con = null;
			org.hibernate.Session session = sessionFactory.openSession();
			
			try {
				session.beginTransaction();
				DateTime now = new DateTime();
				Workflows workflow = new Workflows();
				workflow.setName(wf.getName());
				workflow.setStartTs(new Timestamp(now.getMillis()));
				
				session.save(workflow);
				
				
				wf.setId(workflow.getId());
				wf.setFromDB(workflow);
				session.getTransaction().commit();
				
			}  finally {
				if (session != null) {
					session.close();
					
					
					
				}
			}
		}
		
		
		return wf;
	}


	
	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.ProvisioningEngine#doApproval(int, java.lang.String, boolean, java.lang.String)
	 */
	@Override
	public void doApproval(int id,String userID,boolean approved,String reason) throws ProvisioningException {
		
		
		org.hibernate.Session session = this.sessionFactory.openSession();
		try {
			
			StringBuffer b = new StringBuffer();
			
			
			
			
			LDAPSearchResults res = this.cfgMgr.getMyVD().search("o=Tremolo", 2, equal(this.userIDAttributeName,userID).toString(), new ArrayList<String>());
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
			
			
			
			
			
			
			Query query = session.createQuery("FROM Approvers WHERE userKey = :user_key");
			query.setParameter("user_key", userID);
			List<Approvers> approvers = query.list();
			Approvers approverObj = null;
			
			
			
			
			if (logger.isDebugEnabled()) {
				logger.debug("Approver UserID : " + userID);
			}
			
			
			int approverID;
			
			if (approvers.size() == 0) {
				
				approverObj = new Approvers();
				approverObj.setUserKey(userID);
				session.save(approverObj);
				
				
				approverID = approverObj.getId();
			} else {
				approverObj = approvers.get(0);
				approverID = approverObj.getId();
			}
			
			
			
			
			
			session.beginTransaction();
			
			
			boolean changed = false;
			
			for (String attrName : this.getApproverAttributes()) {
				
				boolean found = false;
				
				for (ApproverAttributes appAttr : approverObj.getApproverAttributeses()) {
					if (attrName.equalsIgnoreCase(appAttr.getName())) {
						found = true;
						LDAPAttribute approverAttr = approver.getAttribute(attrName);
						if (approverAttr != null) {
							if (! approverAttr.getStringValue().equals(appAttr.getValue())) {
								appAttr.setValue(approverAttr.getStringValue());
								session.save(appAttr);
							}
						}
						
					}
				}
				
				if (! found) {
					ApproverAttributes attr = new ApproverAttributes();
					attr.setName(attrName);
					LDAPAttribute approverAttr = approver.getAttribute(attrName);
					if (approverAttr != null) {
						attr.setValue(approverAttr.getStringValue());
					}
					attr.setApprovers(approverObj);
					approverObj.getApproverAttributeses().add(attr);
					session.save(attr);
					changed = true;
				}
				
			}
			
			
			
			Approvals approvals = session.load(Approvals.class, id);
			
			
			
			if (approvals == null) {
				throw new ProvisioningException("Approval not found");
			}
			
			Gson gson = new Gson();
			String json = approvals.getWorkflowObj();
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
			
			for (AzRule rule : approval.getAzRules()) {
				if (rule.getCustomAuthorization() != null) {
					rule.getCustomAuthorization().loadConfigManager(cfgMgr);
					rule.getCustomAuthorization().setWorkflow(wf);
				}
			}
			
			if (! az.checkRules(auinfo, this.cfgMgr, approval.getAzRules(),wf.getRequest())) {
				throw new ProvisioningException("Az of approval failed");
			}
			
			
			
			DateTime now = new DateTime();
			
			
			approvals.setWorkflowObj(null);
			approvals.setApprovedTs(new Timestamp(now.getMillis()));
			approvals.setApprovers(approverObj);
			approvals.setApproved(approved ? 1 : 0);
			approvals.setReason(reason);
			
			session.save(approvals);
			
			
			
			wf.getRequest().put(Approval.APPROVAL_RESULT, new Boolean(approved));
			
			if (approved) {
				wf.reInit(cfgMgr);
				wf.restart();
			} else {
				
				if (wf.getUserNum() != wf.getRequesterNum()) {
					wf.getRequester().getAttribs().put("reason", new Attribute("reason",reason));
					
					if (! wf.getRequester().getAttribs().containsKey(approval.getMailAttr())) {
						logger.warn("Can not send failure notification to " + wf.getRequester().getUserID() + ", no mail found");
					} else {
						this.sendNotification(wf.getRequester().getAttribs().get(approval.getMailAttr()).getValues().get(0),  approval.getFailureEmailMsg(),approval.getFailureEmailSubject(), wf.getRequester());
					}
				}
				
				
				wf.getUser().getAttribs().put("reason", new Attribute("reason",reason));
				
				if (! wf.getUser().getAttribs().containsKey(approval.getMailAttr())) {
					logger.warn("Can not send failure notification to " + wf.getUser().getUserID() + ", no mail found");
				} else {
					this.sendNotification(wf.getUser().getAttribs().get(approval.getMailAttr()).getValues().get(0),  approval.getFailureEmailMsg(),approval.getFailureEmailSubject(), wf.getUser());
				}
				
				wf.reInit(cfgMgr);
				wf.restart();
				
			}
			
			session.getTransaction().commit();
			
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
			logger.error("Exception running workflow",e);
			throw new ProvisioningException("Exception running workflow",e);
		} finally {
			if (session != null) {
				
				
				
				session.close();
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
		
		if (this.sessionFactory == null) {
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
			
			org.hibernate.Session session = sessionFactory.openSession();
			
			try {
				
				
				AuditLogs auditLog = new AuditLogs();
				
				if (isEntry) {
					auditLog.setIsEntry(1);
				} else {
					auditLog.setIsEntry(0);
				}
				
				switch (actionType) {
					case Add : auditLog.setAuditLogType(this.auditLogTypes.get("add")); break;
					case Delete : auditLog.setAuditLogType(this.auditLogTypes.get("delete")); break;
					case Replace : auditLog.setAuditLogType(this.auditLogTypes.get("replace")); break;
				}
				
				auditLog.setUser(session.load(Users.class,wf.getUserNum()));
				if (approval > 0) {
					auditLog.setApprovals(session.load(Approvals.class, approval));
				} else {
					auditLog.setApprovals(null);
				}
				
				auditLog.setAttribute(attribute);
				auditLog.setVal(val);
				
				auditLog.setWorkflows(session.load(Workflows.class, wf.getId()));
				auditLog.setTargets(this.targetIDs.get(target));
				
				session.save(auditLog);
			} catch (Exception e) {
				logger.error("Could not create audit record",e);
			} finally {
				session.close();
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
	

	public void clearDLQ() throws ProvisioningException {
		try {
			BrokerHolder.doClearDLQ();
		} catch (Exception e) {
			throw new ProvisioningException("Could not process deal letter queue",e);
		}
	}
	
	
	private void initLocalBroker() throws ProvisioningException {
		if (this.isInternalQueue()) {
			this.broker = BrokerHolder.getInstance( cfgMgr, "local",this);
			
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
				
				if (this.broker == null) {
					this.initLocalBroker();
				}
				
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
			
			
			PrintStream out = new PrintStream(new FileOutputStream(System.getProperty(OpenUnisonConstants.UNISON_CONFIG_QUARTZDIR) + "/quartz.properties"));
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


	@Override
	public SessionFactory getHibernateSessionFactory() throws ProvisioningException {
		return this.sessionFactory;
	}


	@Override
	public void rebuildHibernate() {
		this.initializeHibernate(this.cfgMgr.getCfg().getProvisioning().getApprovalDB());
		
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

		
		TextMessage bm = session.createTextMessage();
		Gson gson = new Gson();
		bm.setText(gson.toJson(msg));
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
		TextMessage fromq = (TextMessage) msg;
		
		try {
			
			Gson gson = new Gson();
			SmtpMessage email = gson.fromJson(fromq.getText(), SmtpMessage.class);
			
			this.sendEmail(email);
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