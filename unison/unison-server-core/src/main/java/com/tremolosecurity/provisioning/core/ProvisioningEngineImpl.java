/*
Copyright 2015, 2018 Tremolo Security, Inc.

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
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
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
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import com.novell.ldap.util.ByteArray;
import jakarta.jms.ConnectionFactory;
import jakarta.jms.JMSException;
import jakarta.jms.MessageConsumer;
import jakarta.jms.MessageListener;
import jakarta.jms.MessageProducer;
import jakarta.jms.ObjectMessage;
import jakarta.jms.TextMessage;
import javax.mail.Authenticator;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.sql.DataSource;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;
import javax.xml.namespace.QName;

import org.apache.activemq.ActiveMQConnectionFactory;
import org.apache.commons.dbcp.cpdsadapter.DriverAdapterCPDS;
import org.apache.commons.dbcp.datasources.SharedPoolDataSource;
import org.apache.commons.net.smtp.SMTP;
import org.apache.commons.pool2.impl.GenericObjectPool;
import org.apache.logging.log4j.Logger;
import org.apache.qpid.jms.message.JmsMessage;
import org.hibernate.query.Query;
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
import org.quartz.impl.SchedulerRepository;
import org.quartz.impl.StdSchedulerFactory;
import org.quartz.impl.matchers.GroupMatcher;



import com.google.gson.Gson;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.xml.ApprovalDBType;
import com.tremolosecurity.config.xml.DynamicPortalUrlsType;
import com.tremolosecurity.config.xml.JobType;
import com.tremolosecurity.config.xml.MessageListenerType;
import com.tremolosecurity.config.xml.NameValue;
import com.tremolosecurity.config.xml.OrgType;
import com.tremolosecurity.config.xml.ParamType;
import com.tremolosecurity.config.xml.ParamWithValueType;
import com.tremolosecurity.config.xml.PortalUrlsType;
import com.tremolosecurity.config.xml.SchedulingType;
import com.tremolosecurity.config.xml.TargetType;
import com.tremolosecurity.config.xml.TargetsType;
import com.tremolosecurity.config.xml.TremoloType;
import com.tremolosecurity.config.xml.WorkflowChoiceTaskType;
import com.tremolosecurity.config.xml.WorkflowTaskType;
import com.tremolosecurity.config.xml.WorkflowType;
import com.tremolosecurity.json.Token;
import com.tremolosecurity.openunison.OpenUnisonConstants;
import com.tremolosecurity.openunison.notifications.NotificationSystem;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.provisioning.jms.JMSConnectionFactory;
import com.tremolosecurity.provisioning.jms.JMSSessionHolder;
import com.tremolosecurity.provisioning.jobs.DynamicJobs;
import com.tremolosecurity.provisioning.listeners.DynamicQueueListeners;
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
import com.tremolosecurity.provisioning.orgs.DynamicOrgs;
import com.tremolosecurity.provisioning.portal.DynamicPortalUrls;
import com.tremolosecurity.provisioning.reports.DynamicReports;
import com.tremolosecurity.provisioning.scheduler.StopScheduler;
import com.tremolosecurity.provisioning.targets.DynamicTargets;
import com.tremolosecurity.provisioning.tasks.Approval;
import com.tremolosecurity.provisioning.util.EncryptedMessage;

import com.tremolosecurity.provisioning.util.TaskHolder;
import com.tremolosecurity.provisioning.workflows.DynamicWorkflows;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.AzSys;
import com.tremolosecurity.proxy.az.AzRule;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.server.StopableThread;
import com.tremolosecurity.util.JsonTools;


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





	private jakarta.jms.Connection qcon;





	private jakarta.jms.Session taskSession;





	private jakarta.jms.Queue taskQueue;



	private ArrayList<JMSSessionHolder> mpPools;
	

	private MessageProducer taskMP;





	private Scheduler scheduler;
	private Scheduler localScheduler;
	private Set<String> localJobs;
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(ProvisioningEngineImpl.class.getName());



	private SessionFactory sessionFactory;



	private HashMap<String, JMSSessionHolder> listenerSessions;



	private JMSSessionHolder dlqProducer;
	
	
	
	
	private void initializeHibernate(ApprovalDBType adbt) {
		StandardServiceRegistryBuilder builder = new StandardServiceRegistryBuilder();
		
		
		Configuration config = new Configuration();
		config.setProperty("hibernate.connection.driver_class", adbt.getDriver());
		config.setProperty("hibernate.connection.password", adbt.getPassword());
		config.setProperty("hibernate.connection.url", adbt.getUrl());
		config.setProperty("hibernate.connection.username", adbt.getUser());
		config.setProperty("hibernate.dialect", adbt.getHibernateDialect());
		
		if (adbt.isHibernateCreateSchema() == null || adbt.isHibernateCreateSchema()) {
			config.setProperty("hibernate.hbm2ddl.auto", "update");
		}
		config.setProperty("show_sql", "true");
		config.setProperty("hibernate.current_session_context_class", "thread");
		
		config.setProperty("hibernate.c3p0.max_size", Integer.toString(adbt.getMaxConns()));
		config.setProperty("hibernate.c3p0.maxIdleTimeExcessConnections", Integer.toString(adbt.getMaxIdleConns()));
		
		if (adbt.getValidationQuery() != null && ! adbt.getValidationQuery().isEmpty()) {
			config.setProperty("hibernate.c3p0.testConnectionOnCheckout", "true");
		}
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
		
		LoadedConfig lc = null;

		if (adbt.getHibernateConfig() == null || adbt.getHibernateConfig().trim().isEmpty()) {
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
		
		
		
		lc = LoadedConfig.consume(jaxbCfg);
		} else {
			lc = LoadedConfig.baseline();
		}
		
		
		
		StandardServiceRegistry registry = builder.configure(lc).applySettings(config.getProperties()).build();
		try {
			sessionFactory = null;
			
			if (adbt.getHibernateConfig() == null || adbt.getHibernateConfig().trim().isEmpty()) {
				sessionFactory = new MetadataSources( registry ).buildMetadata().buildSessionFactory();
			} else {
				
				
				sessionFactory = new MetadataSources( registry ).addResource(adbt.getHibernateConfig()).buildMetadata().buildSessionFactory();
			}
			
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
			
			
			List<AuditLogType> alts = session.createQuery("FROM AuditLogType",AuditLogType.class).list();
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
		
		
		if (GlobalEntries.getGlobalEntries().getConfigManager() == null) { 
			GlobalEntries.getGlobalEntries().set(ProxyConstants.CONFIG_MANAGER, cfgMgr);
		}
		
		this.initLocalBroker();
		
		
		
		
		this.userStores = new HashMap<String,ProvisioningTargetImpl>();
		generateTargets(cfgMgr);
		
		this.workflows = new HashMap<String,WorkflowImpl>();
		
		approverAttributes = new ArrayList<String>();
		
		generateWorkflows();
		
		if (cfgMgr.getCfg().getProvisioning() != null && cfgMgr.getCfg().getProvisioning().getApprovalDB() != null ) {
			
			
			ApprovalDBType adbt = cfgMgr.getCfg().getProvisioning().getApprovalDB();
			
			if (cfgMgr.getCfg().getProvisioning().getApprovalDB().isEnabled()) {
				this.initializeHibernate(adbt);
			}
			
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
		        List<Targets> targets = session.createQuery("FROM Targets",Targets.class).list();
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
		
		if (cfgMgr.getCfg().getProvisioning() != null && cfgMgr.getCfg().getProvisioning().getPortal() != null) {
			PortalUrlsType portal = cfgMgr.getCfg().getProvisioning().getPortal();
				if (portal.getDynamicUrls() != null) {
					String className = portal.getDynamicUrls().getClassName();
					HashMap<String,Attribute> cfgAttrs = new HashMap<String,Attribute>();
					for (ParamType pt : portal.getDynamicUrls().getParams()) {
						Attribute attr = cfgAttrs.get(pt.getName());
						if (attr == null) {
							attr = new Attribute(pt.getName());
							cfgAttrs.put(pt.getName(), attr);
						}
						
						attr.getValues().add(pt.getValue());
					}
					
					try {
						DynamicPortalUrls dynPortalUrls = (DynamicPortalUrls) Class.forName(className).newInstance();
						dynPortalUrls.loadDynamicPortalUrls(cfgMgr, this,cfgAttrs);
					} catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
						throw new ProvisioningException("Could not initialize dynamic portal urls",e);
					}
				}
		}
		
		if (cfgMgr.getCfg().getProvisioning() != null && cfgMgr.getCfg().getProvisioning().getOrg() != null) {
			OrgType ot = cfgMgr.getCfg().getProvisioning().getOrg();
			if (ot.getDynamicOrgs() != null) {
				String className = ot.getDynamicOrgs().getClassName();
				HashMap<String,Attribute> cfgAttrs = new HashMap<String,Attribute>();
				for (ParamType pt : ot.getDynamicOrgs().getParams()) {
					Attribute attr = cfgAttrs.get(pt.getName());
					if (attr == null) {
						attr = new Attribute(pt.getName());
						cfgAttrs.put(pt.getName(), attr);
					}
					
					attr.getValues().add(pt.getValue());
				}
				
				try {
					DynamicOrgs dynOrgs = (DynamicOrgs) Class.forName(className).newInstance();
					dynOrgs.loadDynamicOrgs(cfgMgr, this,cfgAttrs);
				} catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
					throw new ProvisioningException("Could not initialize dynamic portal urls",e);
				}
			}
		}
	}
	
	@Override
	public void initReports() throws ProvisioningException {
		try {
			
			if (cfgMgr.getCfg().getProvisioning() != null && cfgMgr.getCfg().getProvisioning().getReports() != null && cfgMgr.getCfg().getProvisioning().getReports().getDynamicReports() != null && cfgMgr.getCfg().getProvisioning().getReports().getDynamicReports().isEnabled() ) {
				DynamicPortalUrlsType dynamicReports = cfgMgr.getCfg().getProvisioning().getReports().getDynamicReports();
				String className = dynamicReports.getClassName();
				HashMap<String,Attribute> cfgAttrs = new HashMap<String,Attribute>();
				for (ParamType pt : dynamicReports.getParams()) {
					Attribute attr = cfgAttrs.get(pt.getName());
					if (attr == null) {
						attr = new Attribute(pt.getName());
						cfgAttrs.put(pt.getName(), attr);
					}
					
					attr.getValues().add(pt.getValue());
				}
			
				DynamicReports dynamicReport= (DynamicReports) Class.forName(className).newInstance();
				dynamicReport.loadDynamicReports(cfgMgr, this,cfgAttrs);
			}
			
		} catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
			throw new ProvisioningException("Could not initialize dynamic targets",e);
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
		
		
		try {
			
			if (cfgMgr.getCfg().getProvisioning() != null && cfgMgr.getCfg().getProvisioning().getWorkflows() != null && cfgMgr.getCfg().getProvisioning().getWorkflows().getDynamicWorkflows() != null && cfgMgr.getCfg().getProvisioning().getWorkflows().getDynamicWorkflows().isEnabled() ) {
				DynamicPortalUrlsType dynamicWorkflows = cfgMgr.getCfg().getProvisioning().getWorkflows().getDynamicWorkflows();
				String className = dynamicWorkflows.getClassName();
				HashMap<String,Attribute> cfgAttrs = new HashMap<String,Attribute>();
				for (ParamType pt : dynamicWorkflows.getParams()) {
					Attribute attr = cfgAttrs.get(pt.getName());
					if (attr == null) {
						attr = new Attribute(pt.getName());
						cfgAttrs.put(pt.getName(), attr);
					}
					
					attr.getValues().add(pt.getValue());
				}
			
				DynamicWorkflows dynWorkflows = (DynamicWorkflows) Class.forName(className).newInstance();
				dynWorkflows.loadDynamicWorkflows(cfgMgr, this,cfgAttrs);
			}
			
		} catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
			throw new ProvisioningException("Could not initialize dynamic targets",e);
		}
		
		
		
	}

	private List<WorkflowTaskType> getWFTasks(String name) {
		for (WorkflowType wt : this.cfgMgr.getCfg().getProvisioning().getWorkflows().getWorkflow() ) {
			if (wt.getName().equalsIgnoreCase(name)) {
				return wt.getTasks().getWorkflowTasksGroup();
			}
		}
		
		return null;
	}
	
	
	
	
	
	private void generateWorkflows() throws ProvisioningException {
		if (cfgMgr.getCfg().getProvisioning() == null) {
			return;
		}
		
		for (WorkflowType wt : this.cfgMgr.getCfg().getProvisioning().getWorkflows().getWorkflow() ) {
			
			if (logger.isDebugEnabled()) {
				logger.debug("Processing call workflow - '" + wt.getName() + "'");
			}
			
			
			//while (this.processCallWf(wt));
			
			if (logger.isDebugEnabled()) {
				logger.debug(jaxbObjectToXML(wt));
			}
		}
		
		
		Iterator<WorkflowType> it = this.cfgMgr.getCfg().getProvisioning().getWorkflows().getWorkflow().iterator();
		while (it.hasNext()) {
			WorkflowType wft = it.next();
			String name = wft.getName();
			logger.info("Processing workflow - '" + name + "'");
			WorkflowImpl wf = new WorkflowImpl(this.cfgMgr,wft);
			this.workflows.put(name, wf);
		}
		
		
	}
	
	@Override
	public void addDynamicWorkflow(WorkflowType wft) throws ProvisioningException {
		synchronized (this.workflows) {
			if (logger.isDebugEnabled()) {
				logger.debug("Processing add workflow - '" + wft.getName() + "'");
			}
			
			if (logger.isDebugEnabled()) {
				logger.debug(jaxbObjectToXML(wft));
			}
			
			String name = wft.getName();
			logger.info("Processing workflow - '" + name + "'");
			WorkflowImpl wf = new WorkflowImpl(this.cfgMgr,wft);
			this.workflows.put(name, wf);
			wf.init();
		}
		
	}
	
	
	
	@Override
	public void replaceDynamicWorkflow(WorkflowType wft) throws ProvisioningException {
		synchronized (this.workflows) {
			if (logger.isDebugEnabled()) {
				logger.debug("Processing replace workflow - '" + wft.getName() + "'");
			}
			
			if (logger.isDebugEnabled()) {
				logger.debug(jaxbObjectToXML(wft));
			}
			
			String name = wft.getName();
			logger.info("Processing workflow - '" + name + "'");
			WorkflowImpl wf = new WorkflowImpl(this.cfgMgr,wft);
			this.workflows.remove(name);
			this.workflows.put(name, wf);
			wf.init();
		}
	}
	
	
	@Override
	public void removeDynamicWorkflow(String name) throws ProvisioningException {
		synchronized (this.workflows) {
			if (logger.isDebugEnabled()) {
				logger.debug("Processing remove workflow - '" + name + "'");
			}
			
			
			logger.info("Removing workflow - '" + name + "'");
			
			this.workflows.remove(name);
		}
	}
	
	
	private static String jaxbObjectToXML(WorkflowType wft)
    {
        try
        {
            //Create JAXB Context
            JAXBContext jaxbContext = JAXBContext.newInstance(WorkflowType.class);
             
            //Create Marshaller
            Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
 
            //Required formatting??
            jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
 
            //Print XML String to Console
            StringWriter sw = new StringWriter();
            
            JAXBElement<WorkflowType> jaxbElement =
                    new JAXBElement<WorkflowType>( new QName("", "workflow"),
                    		WorkflowType.class,
                    		wft);
             
            //Write XML to StringWriter
            jaxbMarshaller.marshal(jaxbElement, sw);
             
            //Verify XML Content
            String xmlContent = sw.toString();
            return xmlContent;
 
        } catch (JAXBException e) {
            e.printStackTrace();
            return "";
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
			addTarget(cfgMgr, targetCfg);
			
			
		}
		
		
		if (cfgMgr.getCfg().getProvisioning().getTargets().getDynamicTargets() != null && cfgMgr.getCfg().getProvisioning().getTargets().getDynamicTargets().isEnabled() ) {
			DynamicPortalUrlsType dynamicTargets = cfgMgr.getCfg().getProvisioning().getTargets().getDynamicTargets();
			String className = dynamicTargets.getClassName();
			HashMap<String,Attribute> cfgAttrs = new HashMap<String,Attribute>();
			for (ParamType pt : dynamicTargets.getParams()) {
				Attribute attr = cfgAttrs.get(pt.getName());
				if (attr == null) {
					attr = new Attribute(pt.getName());
					cfgAttrs.put(pt.getName(), attr);
				}
				
				attr.getValues().add(pt.getValue());
			}
			
			try {
				DynamicTargets dynTargets = (DynamicTargets) Class.forName(className).newInstance();
				dynTargets.loadDynamicTargets(cfgMgr, this,cfgAttrs);
				
			} catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
				throw new ProvisioningException("Could not initialize dynamic targets",e);
			}
		}
		
	}

	
	private void addTarget(ConfigManager cfgMgr, TargetType targetCfg) throws ProvisioningException {
		
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
		
		synchronized (this.userStores) {
			try {
				provider = (UserStoreProvider) Class.forName(targetCfg.getClassName()).newInstance();
			} catch (Exception e) {
				throw new ProvisioningException("Could not initialize target " + targetCfg.getName(),e);
			}
			
			MapIdentity mapper = new MapIdentity(targetCfg);
			this.userStores.put(targetCfg.getName(), new ProvisioningTargetImpl(targetCfg.getName(),provider,mapper));
			
			if (provider instanceof UserStoreProviderWithMetadata) {
				UserStoreProviderWithMetadata providerWithMetaData = (UserStoreProviderWithMetadata) provider;
				if (targetCfg.getAnnotation() != null && providerWithMetaData.getAnnotations() != null) {
					for (NameValue nv : targetCfg.getAnnotation()) {
						providerWithMetaData.getAnnotations().put(nv.getName(), nv.getValue());
					}
				}
				
				if (targetCfg.getLabel() != null && providerWithMetaData.getLabels() != null) {
					for (NameValue nv : targetCfg.getLabel()) {
						providerWithMetaData.getLabels().put(nv.getName(), nv.getValue());
					}
				}
			}
			
			
			provider.init(cfg,cfgMgr,targetCfg.getName());
		}
	}
	
	
	private void addTargetToDb(TargetType targetCfg) {
		if (sessionFactory != null && this.cfgMgr.getCfg().getProvisioning() != null && this.cfgMgr.getCfg().getProvisioning().getApprovalDB() != null && this.cfgMgr.getCfg().getProvisioning().getApprovalDB().isEnabled()) {
			org.hibernate.Session session = sessionFactory.openSession();
	        
	        try {
		        List<Targets> targets = session.createQuery("FROM Targets",Targets.class).list();
		        for (Targets target : targets) {
		        	this.targetIDs.put(target.getName(), target);
		        }
		        
		        
		        session.beginTransaction();
		        
		        
	        	if (! this.targetIDs.containsKey(targetCfg.getName())) {
					Targets target = new Targets();
					target.setName(targetCfg.getName());
					session.save(target);
					this.targetIDs.put(target.getName(), target);
				}
		        
		        
		        session.getTransaction().commit();
	        } finally {
	        	session.close();
	        }
		}
	}
	
	@Override
	public void addDynamicTarget(ConfigManager cfgMgr, TargetType targetCfg) throws ProvisioningException {
		synchronized (this.userStores) {
			this.addTarget(cfgMgr, targetCfg);
			this.addTargetToDb(targetCfg);
		}
	}
	
	@Override
	public void removeTarget(String name) throws ProvisioningException {
		synchronized (this.userStores) {
			ProvisioningTarget target = this.userStores.get(name);
			if (target != null) {
				this.userStores.remove(name);
				target.getProvider().shutdown();
			}
		}
	}
	
	@Override
	public void replaceTarget(ConfigManager cfgMgr, TargetType targetCfg) throws ProvisioningException {
		synchronized (this.userStores) {
			this.removeTarget(targetCfg.getName());
			this.addTarget(cfgMgr, targetCfg);
			this.addTargetToDb(targetCfg);
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
		WorkflowImpl wf = (WorkflowImpl) getWorkflowCopy(name);
		
		
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

	@Override
	public Workflow getWorkflowCopy(String name) throws ProvisioningException {
		WorkflowImpl wf = this.workflows.get(name);
		
		if (wf == null) {
			throw new ProvisioningException("WorkflowImpl " + name + " does not exist");
		}
		
		
		

		/*String json = JsonWriter.toJson(wf, new WriteOptionsBuilder().build());
		
		
		wf = (WorkflowImpl) JsonReader.toObjects(json);*/
		
		String json = JsonTools.writeObjectToJson(wf);
		wf = (WorkflowImpl) JsonTools.readObjectFromJson(json);
		
		wf.reInit(this.cfgMgr);
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
			
			
			
			
			LDAPSearchResults res = this.cfgMgr.getMyVD().search(this.cfgMgr.getCfg().getLdapRoot(), 2, equal(this.userIDAttributeName,userID).toString(), new ArrayList<String>());
			if (! res.hasMore()) {
				throw new ProvisioningException("Could not locate approver '" + userID + "'");
			}
			
			LDAPEntry approver = res.next();
			while (res.hasMore()) res.next();
			
			AuthInfo auinfo = new AuthInfo();
			auinfo.setUserDN(approver.getDN(),null);
			LDAPAttributeSet attrs = approver.getAttributeSet();
			for (Object obj : attrs) {
				LDAPAttribute attr = (LDAPAttribute) obj;
				
			
				
				Attribute attrib = new Attribute(attr.getName());
				LinkedList<ByteArray> vals = attr.getAllValues();
				for (ByteArray val: vals) {
					attrib.getValues().add(new String(val.getValue()));
				}
				
				auinfo.getAttribs().put(attrib.getName(), attrib);
			}
			
			while (res.hasMore()) res.next();
			
			
			
			
			
			
			Query query = session.createQuery("FROM Approvers WHERE userKey = :user_key", Approvers.class);
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
			
			session.getTransaction().commit();
			
			
			
			
			
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
			
			
			Workflow wf = (Workflow)  JsonTools.readObjectFromJson(jsonDecr);
			
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
			
			
			session.beginTransaction();
			
			approvals.setWorkflowObj(null);
			approvals.setApprovedTs(new Timestamp(now.getMillis()));
			approvals.setApprovers(approverObj);
			approvals.setApproved(approved ? 1 : 0);
			approvals.setReason(reason);
			
			session.save(approvals);
			
			
			
			wf.getRequest().put(Approval.APPROVAL_RESULT, new Boolean(approved));
			
			approval.markComplete(approved);
			
			boolean restartWorkflow = false;
			
			if (approved) {
				restartWorkflow = true;
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
				
				restartWorkflow = true;
				
			}
			
			session.getTransaction().commit();
			if (restartWorkflow) {
				wf.reInit(cfgMgr);
				wf.restart();
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
			logger.error("Exception running workflow",e);
			throw new ProvisioningException("Exception running workflow",e);
		} finally {
			if (session != null) {
				
				if (session.getTransaction() != null && session.getTransaction().isActive()) {
					session.getTransaction().rollback();
				}
				
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

		if (this.sessionFactory != null) {
			
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
		this.sendNotification(email, msgTxt, this.smtpSubject,user,null);
	}

	@Override
	public void sendNotification(String email,String msgTxt,User user,String contentType) throws Exception {
		this.sendNotification(email, msgTxt, this.smtpSubject,user,contentType);
	}
	
	@Override
	public void sendNotification(String email,String msgTxt,String subject,User user) throws Exception {
		this.sendNotification(email,msgTxt,subject,user,null);
	}


	/* (non-Javadoc)
	 * @see com.tremolosecurity.provisioning.core.ProvisioningEngine#sendNotification(java.lang.String, java.lang.String, java.lang.String, com.tremolosecurity.provisioning.core.User)
	 */
	@Override
	public void sendNotification(String email,String msgTxt,String subject,User user,String contentType) throws Exception {
		
		
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
		
		if (this.cfgMgr.getCfg().getProvisioning() != null && this.cfgMgr.getCfg().getProvisioning().getApprovalDB() != null) {
			msg.setNotifier(this.cfgMgr.getCfg().getProvisioning().getApprovalDB().getNotifier());
		}
		
		msg.to = email;
		msg.from = this.smtpFrom;
		msg.subject = subject;
		msg.msg = msgToSend.toString();
		msg.contentType = contentType;
		
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
			this.mpPools = new ArrayList<JMSSessionHolder>();
			
			String taskQueueName = "unison-tasks";
			
			if (this.cfgMgr.getCfg().getProvisioning() != null && this.cfgMgr.getCfg().getProvisioning().getQueueConfig() != null) {
				taskQueueName = this.cfgMgr.getCfg().getProvisioning().getQueueConfig().getTaskQueueName();
			}
			
			try {
				
				JMSSessionHolder sessionHolder = JMSConnectionFactory.getConnectionFactory().getSession(taskQueueName);
				this.mpPools.add(sessionHolder);
			} catch (Throwable t) {
				logger.warn("Could not create internal queue " + taskQueueName);
			}
			
		} else {
			
			this.mpPools = new ArrayList<JMSSessionHolder>();
			
			if (this.cfgMgr.getCfg().getProvisioning().getQueueConfig().isMultiTaskQueues()) {
				for (int j = 1;j<=this.cfgMgr.getCfg().getProvisioning().getQueueConfig().getNumQueues();j++) {
					String name = this.cfgMgr.getCfg().getProvisioning().getQueueConfig().getTaskQueueName().replace("{x}", Integer.toString(j));
					JMSSessionHolder sessionHolder = JMSConnectionFactory.getConnectionFactory().getSession(name);
					
					this.mpPools.add(sessionHolder);
				}
			} else {
				this.mpPools = new ArrayList<JMSSessionHolder>();
				JMSSessionHolder sessionHolder = JMSConnectionFactory.getConnectionFactory().getSession(this.cfgMgr.getCfg().getProvisioning().getQueueConfig().getTaskQueueName());
				this.mpPools.add(sessionHolder);
			}
			
			if (this.cfgMgr.getCfg().getProvisioning().getQueueConfig().isManualDlq()) {
				this.dlqProducer = JMSConnectionFactory.getConnectionFactory().getSession(this.cfgMgr.getCfg().getProvisioning().getQueueConfig().getManualDlqName());
			}
			
			
			
			
		}
		
		
	}
	
	@Override
	public void dlqMessage(jakarta.jms.TextMessage m) {
		TextMessage newMessage = null;
		try {
			synchronized (this.dlqProducer.getSession()) {
				newMessage = this.dlqProducer.getSession().createTextMessage();	
			}
			
			newMessage.setText(m.getText());
			
			Enumeration enumer = m.getPropertyNames();
			while (enumer.hasMoreElements()) {
				String propertyName = (String) enumer.nextElement();
				if (propertyName.equals("TremoloNumTries")) {
					newMessage.setIntProperty("TremoloNumTries", 0);
				} else {
					try {
						newMessage.setObjectProperty(propertyName,m.getObjectProperty(propertyName));
					} catch (JMSException e) {
						logger.warn(String.format("could not set %s",propertyName),e);
					}
				}
			}
			
			synchronized (this.dlqProducer.getMessageProduceer()) {
				this.dlqProducer.getMessageProduceer().send(newMessage);
			}
		
		} catch (JMSException e) {
			logger.error("could not enqueue to DLQ",e);
		}
	}

	

	public void endBroker() {
		if (this.isInternalQueue()) {
			if (this.qcon != null) {
				try {
					jakarta.jms.Connection con = qcon;
					this.qcon = null;
					con.close();
				} catch (JMSException e) {
					logger.debug("Could not close connection",e);
				}
				
			}
		}
		else {
			//TODO stop connections?
		}
		
	}
	
	
	public void enqueue(WorkflowHolder wfHolder) throws ProvisioningException {
		this.enqueue(wfHolder,1);
	}
	
	public void enqueue(WorkflowHolder wfHolder,int num) throws ProvisioningException {
		
		
		TextMessage bm;
		try {
			
			
			
			JMSSessionHolder session;
			String originalQueue;
			
			
			session = this.getTaskMessageProducer();
			
			
			bm = session.getSession().createTextMessage();
			originalQueue = session.getQueueName();
			
			synchronized (session) {
			
			
				bm.setStringProperty("OriginalQueue", originalQueue);
				bm.setStringProperty("WorkflowName", wfHolder.getWorkflow().getName());
				bm.setStringProperty("WorkflowSubject", wfHolder.getUser().getUserID());
				bm.setStringProperty("JMSXGroupID", "unison");
				bm.setStringProperty("nonce", UUID.randomUUID().toString());
				bm.setIntProperty("TremoloNumTries", num);
				
				
				TaskHolder holder = wfHolder.getWfStack().peek();
				WorkflowTask task = holder.getParent().get(holder.getPosition());
			
				
				bm.setStringProperty("WorkflowCurrentTask", task.getLabel());
				
				EncryptedMessage encMsg = this.encryptObject(wfHolder);
				
				String json = JsonTools.writeObjectToJson(encMsg);
				
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				DeflaterOutputStream compressor  = new DeflaterOutputStream(baos,new Deflater(Deflater.BEST_COMPRESSION,true));
				
				compressor.write(json.getBytes("UTF-8"));
				compressor.flush();
				compressor.close();
				
				String b64 = new String( org.bouncycastle.util.encoders.Base64.encode(baos.toByteArray()));
				
				
				bm.setText(b64);
				session.getMessageProduceer().send(bm);
				
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not enqueue message",e);
		}
		
	}
	
	
	
	public void execute() {
		
	}

	@Override
	public void returnQueueConnection(jakarta.jms.Connection con) {
		// TODO Auto-generated method stub
		
	}


	public JMSSessionHolder getTaskMessageProducer() throws Exception {
		
		int index = ThreadLocalRandom.current().nextInt(0,this.mpPools.size());
		
		return this.mpPools.get(index);
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
	        	
        		
        		TaskConsumer taskConsumer = new TaskConsumer(this,this.cfgMgr);
    			
    			JMSSessionHolder sessionHolder = JMSConnectionFactory.getConnectionFactory().getSession(taskQueueName);
				sessionHolder.setMessageListener(taskConsumer);
        	} else {
        		
        		
        		if (this.cfgMgr.getCfg().getProvisioning().getQueueConfig().isMultiTaskQueues()) {
        			for (int j=1;j<=this.cfgMgr.getCfg().getProvisioning().getQueueConfig().getNumQueues();j++) {
        				String name = this.cfgMgr.getCfg().getProvisioning().getQueueConfig().getTaskQueueName().replace("{x}", Integer.toString(j));
        				for (int i=0;i<this.cfgMgr.getCfg().getProvisioning().getQueueConfig().getMaxConsumers();i++) {
                			
                			TaskConsumer taskConsumer = new TaskConsumer(this,this.cfgMgr);
                			
                			JMSSessionHolder sessionHolder = JMSConnectionFactory.getConnectionFactory().getSession(name);
        					sessionHolder.setMessageListener(taskConsumer);
                		}
        			}
        		} else {
        			for (int i=0;i<this.cfgMgr.getCfg().getProvisioning().getQueueConfig().getMaxConsumers();i++) {
            			
            			
    					
            			TaskConsumer taskConsumer = new TaskConsumer(this,this.cfgMgr);
            			
            			JMSSessionHolder sessionHolder = JMSConnectionFactory.getConnectionFactory().getSession(taskQueueName);
    					sessionHolder.setMessageListener(taskConsumer);
            		}
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
			String json = JsonTools.writeObjectToJson(o);
			
			byte[] encoded = json.getBytes("UTF-8");
			EncryptedMessage msg = new EncryptedMessage();
			
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			msg.setMsg(cipher.doFinal(encoded));
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
			
			
			return JsonTools.readObjectFromJson(new String(bytes,"UTF-8"));
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException  e) {
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
		
		/*String instanceLabel = null;
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
		}*/
		
	
		
		scheduleProps.setProperty("org.quartz.scheduler.instanceId", UUID.randomUUID().toString());
		scheduleProps.setProperty("org.quartz.threadPool.threadCount", Integer.toString(sct.getThreadCount()));
		scheduleProps.setProperty("org.quartz.scheduler.instanceName", "global");
		if (sct.isUseDB()) {
			scheduleProps.setProperty("org.quartz.jobStore.class", "org.quartz.impl.jdbcjobstore.JobStoreTX");
			scheduleProps.setProperty("org.quartz.jobStore.driverDelegateClass", sct.getScheduleDB().getDelegateClassName());
			scheduleProps.setProperty("org.quartz.jobStore.dataSource", "scheduleDB");
			scheduleProps.setProperty("org.quartz.dataSource.scheduleDB.driver", sct.getScheduleDB().getDriver());
			scheduleProps.setProperty("org.quartz.dataSource.scheduleDB.URL", sct.getScheduleDB().getUrl());
			scheduleProps.setProperty("org.quartz.dataSource.scheduleDB.user", sct.getScheduleDB().getUser());
			scheduleProps.setProperty("org.quartz.dataSource.scheduleDB.password", sct.getScheduleDB().getPassword());
			scheduleProps.setProperty("org.quartz.dataSource.scheduleDB.maxCachedStatementsPerConnection", "0");
			scheduleProps.setProperty("org.quartz.dataSource.scheduleDB.maxConnections", Integer.toString(sct.getScheduleDB().getMaxConnections()));
			scheduleProps.setProperty("org.quartz.dataSource.scheduleDB.validationQuery", sct.getScheduleDB().getValidationQuery());
			scheduleProps.setProperty("org.quartz.jobStore.useProperties", "true");
			scheduleProps.setProperty("org.quartz.jobStore.isClustered", "true");
			

			
		} else {
			scheduleProps.setProperty("org.quartz.jobStore.class", "org.quartz.simpl.RAMJobStore");
		}
		
		
		
		if (sct.isUseDB() && System.getProperties().get("tremolo.io/localscheduler.table.prefix") != null) {
			logger.info("Local scheduler with table prefix '" + System.getProperties().get("tremolo.io/localscheduler.table.prefix") + "'");
			Properties localScheduleProps = new Properties();
			localScheduleProps.putAll(scheduleProps);
			localScheduleProps.setProperty("org.quartz.jobStore.tablePrefix", System.getProperty("tremolo.io/localscheduler.table.prefix"));
			localScheduleProps.setProperty("org.quartz.scheduler.instanceId", UUID.randomUUID().toString());
			localScheduleProps.setProperty("org.quartz.threadPool.threadCount", Integer.toString(sct.getThreadCount()));
			localScheduleProps.setProperty("org.quartz.jobStore.class", "org.quartz.impl.jdbcjobstore.JobStoreTX");
			localScheduleProps.setProperty("org.quartz.jobStore.driverDelegateClass", sct.getScheduleDB().getDelegateClassName());
			localScheduleProps.setProperty("org.quartz.jobStore.dataSource", "scheduleDB");
			localScheduleProps.setProperty("org.quartz.dataSource.scheduleDB.driver", sct.getScheduleDB().getDriver());
			localScheduleProps.setProperty("org.quartz.dataSource.scheduleDB.URL", sct.getScheduleDB().getUrl());
			localScheduleProps.setProperty("org.quartz.dataSource.scheduleDB.user", sct.getScheduleDB().getUser());
			localScheduleProps.setProperty("org.quartz.dataSource.scheduleDB.password", sct.getScheduleDB().getPassword());
			localScheduleProps.setProperty("org.quartz.dataSource.scheduleDB.maxCachedStatementsPerConnection", "0");
			localScheduleProps.setProperty("org.quartz.dataSource.scheduleDB.maxConnections", Integer.toString(sct.getScheduleDB().getMaxConnections()));
			localScheduleProps.setProperty("org.quartz.dataSource.scheduleDB.validationQuery", sct.getScheduleDB().getValidationQuery());
			localScheduleProps.setProperty("org.quartz.jobStore.useProperties", "true");
			localScheduleProps.setProperty("org.quartz.jobStore.isClustered", "true");
			localScheduleProps.setProperty("org.quartz.scheduler.instanceName", "local");
			
			try {
				
				/*String classpath = System.getProperty("java.class.path");
				String[] classpathEntries = classpath.split(File.pathSeparator);
				for (String cp : classpathEntries) {
					System.out.println(cp);
				}*/
				
				
				
				StdSchedulerFactory fact = new StdSchedulerFactory();
				fact.initialize(localScheduleProps);
				
				Collection<Scheduler> schedulers = SchedulerRepository.getInstance().lookupAll();
				for (Scheduler sched : schedulers) {
					logger.info("Scheduler: " + sched.getSchedulerName());
				}
				
				this.localScheduler = fact.getScheduler();
				this.localScheduler.start();
				this.cfgMgr.addThread(new StopScheduler(this.localScheduler));
				
				
				this.localJobs = new HashSet<String>();
				String localJobsNames = System.getProperty("tremolo.io/localscheduler.jobs");
				if (localJobsNames != null) {
					StringTokenizer toker = new StringTokenizer(localJobsNames,",",false);
					while (toker.hasMoreTokens()) {
						this.localJobs.add(toker.nextToken().toLowerCase());
					}
				}
			} catch (SchedulerException e1) {
				throw new ProvisioningException("Could not initialize local scheduler", e1);
			}
			
		}
		
		try {
			StdSchedulerFactory fact = new StdSchedulerFactory();
			fact.initialize(scheduleProps);
			this.scheduler = fact.getScheduler();
			this.scheduler.start();
			this.cfgMgr.addThread(new StopScheduler(this.scheduler));
			HashSet<String> jobKeys = new HashSet<String>();
			
			for (JobType jobType : sct.getJob()) {
				addNewJob(jobKeys, jobType);
			}
			
			
			DynamicPortalUrlsType dynamicJobs = cfgMgr.getCfg().getProvisioning().getScheduler().getDynamicJobs();
			if (dynamicJobs != null && dynamicJobs.isEnabled()) {
				String className = dynamicJobs.getClassName();
				HashMap<String,Attribute> cfgAttrs = new HashMap<String,Attribute>();
				for (ParamType pt : dynamicJobs.getParams()) {
					Attribute attr = cfgAttrs.get(pt.getName());
					if (attr == null) {
						attr = new Attribute(pt.getName());
						cfgAttrs.put(pt.getName(), attr);
					}
					
					attr.getValues().add(pt.getValue());
				}
			
				DynamicJobs dynJobs = null;
				try {
					dynJobs = (DynamicJobs) Class.forName(className).newInstance();
				} catch (InstantiationException | IllegalAccessException e) {
					throw new ProvisioningException("Could not create dynmaic job",e);
				}
				dynJobs.loadDynamicJobs(cfgMgr, this,cfgAttrs,jobKeys);
			}
			
			
			for (String groupName : scheduler.getJobGroupNames()) {
				this.deleteRemovedJobs(jobKeys, groupName);
			}
			
			if (this.localScheduler != null) {
				for (String groupName : this.localScheduler.getJobGroupNames()) {
					this.deleteRemovedLocalJobs(jobKeys, groupName);
				}
			}
		
			
			
		} catch (SchedulerException e) {
			throw new ProvisioningException("Could not initialize scheduler",e);
		} catch (ClassNotFoundException e) {
			throw new ProvisioningException("Could not initialize scheduler",e);
		}
		
		
		
	}


	
	public void deleteRemovedJobs(HashSet<String> jobKeys, String groupName)
			throws SchedulerException {
		//get job's trigger
			 
		
		
	     for (JobKey jobKey : scheduler.getJobKeys(GroupMatcher.jobGroupEquals(groupName))) {
	 
		  String jobName = jobKey.getName();
		  String jobGroup = jobKey.getGroup();
	 
		  
		  List<Trigger> triggers = (List<Trigger>) scheduler.getTriggersOfJob(jobKey);
		  
		  if (! jobKeys.contains(jobName + "-" + jobGroup)) {
			  logger.info("Removing job '" + jobName + "' / '" + jobGroup + "'");
			  
			  scheduler.deleteJob(jobKey);
			  
		  }
		  
	 
	    }
		  
	}
	
	public void deleteRemovedLocalJobs(HashSet<String> jobKeys, String groupName)
			throws SchedulerException {
		//get job's trigger
			 
		
		
	     for (JobKey jobKey : scheduler.getJobKeys(GroupMatcher.jobGroupEquals(groupName))) {
	 
		  String jobName = jobKey.getName();
		  String jobGroup = jobKey.getGroup();
	 
		  
		  List<Trigger> triggers = (List<Trigger>) scheduler.getTriggersOfJob(jobKey);
		  
		  if (! jobKeys.contains(jobName + "-" + jobGroup)) {
			  logger.info("Removing job '" + jobName + "' / '" + jobGroup + "'");
			  
			  localScheduler.deleteJob(jobKey);
			  
		  }
		  
	 
	    }
		  
	}


	@Override
	public void addNewJob(HashSet<String> jobKeys, JobType jobType)
			throws SchedulerException, ProvisioningException, ClassNotFoundException {
		jobKeys.add(jobType.getName() + "-" + jobType.getGroup());
		
		boolean localJob = this.localJobs != null && this.localJobs.contains(jobType.getName().toLowerCase());
		
		JobKey jk = new JobKey(jobType.getName(),jobType.getGroup());
		
		
		
		
		JobDetail jd = localJob ? this.localScheduler.getJobDetail(jk) : this.scheduler.getJobDetail(jk);
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
			for (ParamWithValueType pt : jobType.getParam()) {
				if (pt.getValue() != null && ! pt.getValue().isBlank()) {
					configProps.setProperty(pt.getName(), pt.getValue());
				} else {
					configProps.setProperty(pt.getName(), pt.getValueAttribute());
				}
				
			}
			
			Properties jobProps = new Properties();
			for (String key : jd.getJobDataMap().getKeys()) {
				jobProps.setProperty(key, (String) jd.getJobDataMap().getString(key));
			}
			
			List<Trigger> triggers = localJob ? (List<Trigger>) localScheduler.getTriggersOfJob(jd.getKey()) :  (List<Trigger>) scheduler.getTriggersOfJob(jd.getKey());
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

	private void addJob(JobType jobType, JobKey jk)
			throws ClassNotFoundException, SchedulerException {
		
		boolean localJob = this.localJobs != null && this.localJobs.contains(jobType.getName().toLowerCase());
		
		JobDetail jd;
		JobBuilder jb = JobBuilder.newJob((Class<? extends Job>) Class.forName(jobType.getClassName()));
		for (ParamWithValueType pt : jobType.getParam()) {
			if (pt.getValue() != null && ! pt.getValue().isBlank()) {
				jb.usingJobData(pt.getName(), pt.getValue());
			} else {
				jb.usingJobData(pt.getName(), pt.getValueAttribute());
			}
			
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
			
		if (localJob) {
			logger.info(String.format("Adding job %s to local scheduler",jobType.getName()));
			this.localScheduler.scheduleJob(jd, tb.build());
		} else {
			logger.info(String.format("Adding job %s to global scheduler",jobType.getName()));
			this.scheduler.scheduleJob(jd, tb.build());
		}
		
	}

	private void reloadJob(JobType jobType, JobDetail jd) throws SchedulerException, ClassNotFoundException {
		boolean localJob = this.localJobs != null && this.localJobs.contains(jobType.getName().toLowerCase());
		
		if (localJob) {
			this.localScheduler.deleteJob(jd.getKey());
		} else {
			this.scheduler.deleteJob(jd.getKey());
		}
		addJob(jobType, jd.getKey());
		
	}

	@Override
	public void initListeners() throws ProvisioningException {
		this.listenerSessions = new HashMap<String,JMSSessionHolder>();
		if (this.cfgMgr.getCfg().getProvisioning() == null || this.cfgMgr.getCfg().getProvisioning().getListeners() == null) {
			logger.warn("No listeners defined");
			return;
		}
		
		try {
			
			
			for (MessageListenerType mlt : this.cfgMgr.getCfg().getProvisioning().getListeners().getListener()) {
				addMessageListener(mlt);
				
				
			}
			
			
			if ( cfgMgr.getCfg().getProvisioning().getListeners().getDynamicListeners() != null && cfgMgr.getCfg().getProvisioning().getListeners().getDynamicListeners().isEnabled() ) {
				DynamicPortalUrlsType dynamicMessageListeners = cfgMgr.getCfg().getProvisioning().getListeners().getDynamicListeners();
				String className = dynamicMessageListeners.getClassName();
				HashMap<String,Attribute> cfgAttrs = new HashMap<String,Attribute>();
				for (ParamType pt : dynamicMessageListeners.getParams()) {
					Attribute attr = cfgAttrs.get(pt.getName());
					if (attr == null) {
						attr = new Attribute(pt.getName());
						cfgAttrs.put(pt.getName(), attr);
					}
					
					attr.getValues().add(pt.getValue());
				}
			
				DynamicQueueListeners dynamicQueueListener = (DynamicQueueListeners) Class.forName(className).newInstance();
				dynamicQueueListener.loadDynamicQueueListeners(cfgMgr, this,cfgAttrs);
			}
			
			
		} catch (Exception e) {
			logger.warn("Could not initialize listeners",e);
		}
	}


	@Override
	public void addMessageListener(MessageListenerType mlt) throws InstantiationException, IllegalAccessException,
			ClassNotFoundException, ProvisioningException, JMSException {
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
		
		
		JMSSessionHolder session = JMSConnectionFactory.getConnectionFactory().getSession(mlt.getQueueName());
		session.setMessageListener(uml);
		
		uml.setListenerSession(session, cfgMgr);
		
		this.listenerSessions.put(mlt.getQueueName(),session);
	}
	
	@Override
	public void removeMessageListener(String name) {
		JMSSessionHolder session = this.listenerSessions.get(name);
		
		if (session != null) {
			session.getJMSConnection().removeSession(name);
			try {
				session.getSession().close();
			} catch (Throwable t) {
				logger.warn("Could not shutdown queue '" + name + "'",t);
			}
			this.listenerSessions.remove(name);
		}
	}
	
	
	public void reEnQueueTask(TextMessage tm,int numOfTries) throws Exception {
		this.reEnQueue(tm, numOfTries, this.getTaskMessageProducer());
	}
	
	@Override
	public void reEnQueue(TextMessage tm, int numOfTries, JMSSessionHolder session) {
		logger.info(String.format("Re-enqueueing %s",numOfTries));
		TextMessage newMessage = null;
		try {
			synchronized (session.getSession()) {
				newMessage = session.getSession().createTextMessage();	
			}
			
			newMessage.setText(tm.getText());
			
			Enumeration enumer = tm.getPropertyNames();
			boolean foundNumTries = false;
			while (enumer.hasMoreElements()) {
				String propertyName = (String) enumer.nextElement();
				if (propertyName.equals("TremoloNumTries")) {
					newMessage.setIntProperty("TremoloNumTries", numOfTries);
					foundNumTries = true;
				} else {
					try {
						newMessage.setObjectProperty(propertyName,tm.getObjectProperty(propertyName));
					} catch (JMSException e) {
						logger.warn(String.format("could not set %s",propertyName),e);
					}
				}
			}
			
			if (! foundNumTries) {
				newMessage.setIntProperty("TremoloNumTries", numOfTries);
			}
			
			synchronized (session.getMessageProduceer()) {
				session.getMessageProduceer().send(newMessage);
			}
		
		} catch (JMSException e) {
			logger.error("could not enqueue to DLQ",e);
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


	@Override
	public void deleteJob(String jobName, String groupName) throws SchedulerException {
		JobKey jobKey = new JobKey(jobName,groupName);
		this.scheduler.deleteJob(jobKey);
		
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
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(SendMessageThread.class.getName());
	
	
	
	boolean running = true;

	private ProvisioningEngine prov;



	




	private String smtpQueue;



	private JMSSessionHolder smtpSendSession;
	
	public SendMessageThread(ProvisioningEngine prov) throws ProvisioningException {
		this.prov = prov;
		
		
	}
	
	public void lazyInit(ConfigManager cfgMgr) throws ProvisioningException {
		try {
			
			
			smtpQueue = "TremoloUnisonSMTPQueue";
			if (cfgMgr.getCfg().getProvisioning() != null && cfgMgr.getCfg().getProvisioning().getQueueConfig() != null) {
				smtpQueue = cfgMgr.getCfg().getProvisioning().getQueueConfig().getSmtpQueueName();
			}
			
			
			
			this.smtpSendSession = JMSConnectionFactory.getConnectionFactory().getSession(smtpQueue);
			
			JMSSessionHolder smtpReceieve = JMSConnectionFactory.getConnectionFactory().getSession(smtpQueue);
			smtpReceieve.setMessageListener(this);
			
			
			
			
			
			
		} catch (JMSException e) {
			throw new ProvisioningException("Could not initialize JMS",e);
		}
	}
	
	public void enqEmail(SmtpMessage msg) throws IOException, JMSException {

		synchronized (this.smtpSendSession) {
			TextMessage bm = smtpSendSession.getSession().createTextMessage();
			Gson gson = new Gson();
			bm.setText(gson.toJson(msg));
			bm.setStringProperty("OriginalQueue", this.smtpQueue);
			bm.setStringProperty("nonce", UUID.randomUUID().toString());
			bm.setStringProperty("JMSXGroupID", "unison-email");
			bm.setIntProperty("TremoloNumTries", 0);
			smtpSendSession.getMessageProduceer().send(bm);
		}
		//session.commit();
		
	}
	
	private void sendEmail(SmtpMessage msg) throws MessagingException {
		NotificationSystem notifier = GlobalEntries.getGlobalEntries().getConfigManager().getNotificationsMananager().getNotificationSystem(msg.getNotifier());
		if (notifier == null) {
			throw new MessagingException(String.format("Notifier %s does not exist", msg.getNotifier()));
		} else {
			try {
				notifier.sendMessage(msg);
			} catch (Exception e) {
				throw new MessagingException(String.format("Could not send message to %s using notifier %s", msg.getTo(),msg.getNotifier()),e);
			}
		}
		
	}



	@Override
	public void onMessage(jakarta.jms.Message msg) {
		TextMessage fromq = (TextMessage) msg;
		
		
		
		try {
			
			if (fromq.getBooleanProperty("unisonignore")) {
				
				if (logger.isDebugEnabled()) {
					logger.debug("ignoring message");
				}
				fromq.acknowledge();
				return;
			}
			
			Gson gson = new Gson();
			SmtpMessage email = gson.fromJson(fromq.getText(), SmtpMessage.class);
			
			this.sendEmail(email);
			fromq.acknowledge();
			//session.commit();
		} catch (MessagingException | JMSException e) {
			
			
			
			logger.error("Could not send email",e);
			
			
			if (GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getQueueConfig().isManualDlq()) {
				// determine if too many retries
				int numberOfTries = 0;
				try {
					numberOfTries = msg.getIntProperty("TremoloNumTries");
				} catch (JMSException je) {
					numberOfTries = 0;
				}
				numberOfTries++;
				
				if (numberOfTries >= GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getProvisioning().getQueueConfig().getManualDlqMaxAttempts()) {
					GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().dlqMessage(fromq);
				} else {
					try {
						this.prov.reEnQueue(fromq, numberOfTries, smtpSendSession);
					} catch (Exception je) {
						logger.error("Could not re-enqueue workflow",je);
					}
				}
				
				try {
					// if this is from qpid, set the achnowledgement mode manually
					if (msg instanceof JmsMessage) {
						msg.setIntProperty("JMS_AMQP_ACK_TYPE", 1);
					}
					
					msg.acknowledge();
				} catch (JMSException je) {
					logger.error("Error handling failed message",je);
				}
			} else {
			
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
	
}