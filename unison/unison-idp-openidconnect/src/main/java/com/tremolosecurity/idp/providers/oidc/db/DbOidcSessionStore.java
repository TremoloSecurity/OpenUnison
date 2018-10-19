/*******************************************************************************
 * Copyright 2018 Tremolo Security, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.tremolosecurity.idp.providers.oidc.db;

import java.sql.Timestamp;
import java.util.HashMap;

import javax.servlet.ServletContext;

import org.hibernate.Query;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.boot.MetadataSources;
import org.hibernate.boot.cfgxml.spi.LoadedConfig;
import org.hibernate.boot.jaxb.cfg.spi.JaxbCfgHibernateConfiguration;
import org.hibernate.boot.jaxb.cfg.spi.JaxbCfgMappingReferenceType;
import org.hibernate.boot.jaxb.cfg.spi.JaxbCfgHibernateConfiguration.JaxbCfgSessionFactory;
import org.hibernate.boot.registry.StandardServiceRegistry;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.hibernate.cfg.Configuration;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

import com.tremolosecurity.idp.providers.OpenIDConnectIdP;
import com.tremolosecurity.idp.providers.oidc.model.OIDCSession;
import com.tremolosecurity.idp.providers.oidc.model.OidcSessionState;
import com.tremolosecurity.idp.providers.oidc.model.OidcSessionStore;
import com.tremolosecurity.provisioning.mapping.MapIdentity;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.server.StopableThread;

public class DbOidcSessionStore implements OidcSessionStore {
	
	static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(DbOidcSessionStore.class.getName());
	
	private SessionFactory sessionFactory;

	@Override
	public void saveUserSession(OidcSessionState session) throws Exception {
		Session db = null;
		try {
			db = this.sessionFactory.openSession();
			
			OidcDbSession dbSession = new OidcDbSession();
			dbSession.setSessionID(session.getSessionID());
			dbSession.setClientID(session.getClientID());
			dbSession.setEncryptedIdToken(session.getEncryptedIdToken());
			dbSession.setEncryptedAccessToken(session.getEncryptedAccessToken());
			dbSession.setExpires(new Timestamp(session.getExpires().toDateTime(DateTimeZone.UTC).getMillis()));
			dbSession.setUserDN(session.getUserDN());
			dbSession.setRefreshToken(session.getRefreshToken());
			
			db.beginTransaction();
			db.save(dbSession);
			db.getTransaction().commit();
			
		} finally {
			if (db != null) {
				if (db.getTransaction() != null && db.getTransaction().isActive()) {
					db.getTransaction().rollback();
				}
				db.close();
			}
		}

	}

	@Override
	public void deleteSession(String sessionId) throws Exception {
		Session db = null;
		try {
			db = this.sessionFactory.openSession();
			
			OidcDbSession dbSession = db.get(OidcDbSession.class, sessionId);
			
			db.beginTransaction();
			db.delete(dbSession);
			db.getTransaction().commit();
			
		} finally {
			if (db != null) {
				if (db.getTransaction() != null && db.getTransaction().isActive()) {
					db.getTransaction().rollback();
				}
				db.close();
			}
		}

	}

	@Override
	public OidcSessionState getSession(String sessionId) throws Exception {
		Session db = null;
		try {
			db = this.sessionFactory.openSession();
			
			OidcDbSession dbSession = db.get(OidcDbSession.class, sessionId);
			
			if (dbSession == null) {
				return null;
			}
			
			OidcSessionState session = new OidcSessionState();
			session.setClientID(dbSession.getClientID());
			session.setEncryptedIdToken(dbSession.getEncryptedIdToken());
			session.setEncryptedAccessToken(dbSession.getEncryptedAccessToken());
			session.setExpires(new DateTime(dbSession.getExpires()));
			session.setSessionID(dbSession.getSessionID());
			session.setUserDN(dbSession.getUserDN());
			session.setRefreshToken(dbSession.getRefreshToken());
			
			return session;
			
		} finally {
			if (db != null) {
				if (db.getTransaction() != null && db.getTransaction().isActive()) {
					db.getTransaction().rollback();
				}
				db.close();
			}
		}
	}

	@Override
	public void resetSession(OidcSessionState session) throws Exception {
		Session db = null;
		try {
			db = this.sessionFactory.openSession();
			
			OidcDbSession dbSession = db.get(OidcDbSession.class, session.getSessionID());
			
			dbSession.setEncryptedIdToken(session.getEncryptedIdToken());
			dbSession.setEncryptedAccessToken(session.getEncryptedAccessToken());
			dbSession.setExpires(new Timestamp(session.getExpires().toDateTime(DateTimeZone.UTC).getMillis()));
			dbSession.setRefreshToken(session.getRefreshToken());
			
			db.beginTransaction();
			db.save(dbSession);
			db.getTransaction().commit();
			
		} finally {
			if (db != null) {
				if (db.getTransaction() != null && db.getTransaction().isActive()) {
					db.getTransaction().rollback();
				}
				db.close();
			}
		}

	}

	@Override
	public void cleanOldSessions() throws Exception {
		Session db = null;
		try {
			db = this.sessionFactory.openSession();
			db.beginTransaction();
			String hql = "DELETE FROM OidcDbSession o WHERE o.expires <= :exp_ts";
			Query query = db.createQuery(hql);
			query.setParameter("exp_ts",new Timestamp(new DateTime().toDateTime(DateTimeZone.UTC).getMillis()));
			
			query.executeUpdate();
			db.getTransaction().commit();
		} finally {
			if (db != null) {
				if (db.getTransaction() != null && db.getTransaction().isActive()) {
					db.getTransaction().rollback();
				}
				db.close();
			}
		}

	}

	@Override
	public void init(String idpName, ServletContext ctx, HashMap<String, Attribute> init,
			HashMap<String, HashMap<String, Attribute>> trustCfg, MapIdentity mapper) throws Exception {
		
		
		String driver = init.get("driver").getValues().get(0);
		logger.info("Driver : '" + driver + "'");
		
		String url = init.get("url").getValues().get(0);;
		logger.info("URL : " + url);
		String user = init.get("user").getValues().get(0);;
		logger.info("User : " + user);
		String pwd = init.get("password").getValues().get(0);;
		logger.info("Password : **********");
		
		
		int maxCons = Integer.parseInt(init.get("maxCons").getValues().get(0));
		logger.info("Max Cons : " + maxCons);
		int maxIdleCons = Integer.parseInt(init.get("maxIdleCons").getValues().get(0));
		logger.info("maxIdleCons : " + maxIdleCons);
		
		String dialect = init.get("dialect").getValues().get(0);
		logger.info("Hibernate Dialect : '" + dialect + "'");
		
		String validationQuery = init.get("validationQuery").getValues().get(0);
		logger.info("Validation Query : '" + validationQuery + "'");
		
		String hibernateConfig = init.get("hibernateConfig") != null ? init.get("hibernateConfig").getValues().get(0) : null;
		logger.info("HIbernate mapping file : '" + hibernateConfig + "'");
		
		String hibernateCreateSchema = init.get("hibernateCreateSchema") != null ? init.get("hibernateCreateSchema").getValues().get(0) : null;
		logger.info("Can create schema : '" + hibernateCreateSchema + "'");
		
		this.initializeHibernate(driver, user, pwd, url, dialect, maxCons, maxIdleCons, validationQuery,hibernateConfig,hibernateCreateSchema);
		
	}
	
	private void initializeHibernate(String driver, String user,String password,String url,String dialect,int maxCons,int maxIdleCons,String validationQuery,String mappingFile,String createSchema) {
		StandardServiceRegistryBuilder builder = new StandardServiceRegistryBuilder();
		
		
		Configuration config = new Configuration();
		config.setProperty("hibernate.connection.driver_class", driver);
		config.setProperty("hibernate.connection.password", password);
		config.setProperty("hibernate.connection.url", url);
		config.setProperty("hibernate.connection.username", user);
		config.setProperty("hibernate.dialect", dialect);
		
		if (createSchema == null || createSchema.equalsIgnoreCase("true")) {
			config.setProperty("hibernate.hbm2ddl.auto", "update");
		}
		
		config.setProperty("show_sql", "true");
		config.setProperty("hibernate.current_session_context_class", "thread");
		
		config.setProperty("hibernate.c3p0.max_size", Integer.toString(maxCons));
		config.setProperty("hibernate.c3p0.maxIdleTimeExcessConnections", Integer.toString(maxIdleCons));
		
		if (validationQuery != null && ! validationQuery.isEmpty()) {
			config.setProperty("hibernate.c3p0.testConnectionOnCheckout", "true");
		}
		config.setProperty("hibernate.c3p0.autoCommitOnClose", "true");
		

		
		//config.setProperty("hibernate.c3p0.debugUnreturnedConnectionStackTraces", "true");
		//config.setProperty("hibernate.c3p0.unreturnedConnectionTimeout", "30");
		
		
		
		if (validationQuery == null) {
			validationQuery = "SELECT 1";
		}
		config.setProperty("hibernate.c3p0.preferredTestQuery", validationQuery);
		
		
		LoadedConfig lc = null;
		
		if (mappingFile == null || mappingFile.trim().isEmpty()) {
			JaxbCfgHibernateConfiguration jaxbCfg = new JaxbCfgHibernateConfiguration();
			jaxbCfg.setSessionFactory(new JaxbCfgSessionFactory());
			
			JaxbCfgMappingReferenceType mrt = new JaxbCfgMappingReferenceType();
			mrt.setClazz(OidcDbSession.class.getName());
			jaxbCfg.getSessionFactory().getMapping().add(mrt);
			
			lc = LoadedConfig.consume(jaxbCfg);
		} else {
			lc = LoadedConfig.baseline(); 
		}
		
		
		StandardServiceRegistry registry = builder.configure(lc).applySettings(config.getProperties()).build();
		try {
			if (mappingFile == null || mappingFile.trim().isEmpty()) {
				sessionFactory = new MetadataSources( registry ).buildMetadata().buildSessionFactory();
			} else {
				sessionFactory = new MetadataSources( registry ).addResource(mappingFile).buildMetadata().buildSessionFactory();
			}
			
			GlobalEntries.getGlobalEntries().getConfigManager().addThread(new StopableThread() {

				@Override
				public void run() {
					
					
				}

				@Override
				public void stop() {
					logger.info("Stopping hibernate");
					sessionFactory.close();
					
				}
				
			});
		}
		catch (Exception e) {
			e.printStackTrace();
			// The registry would be destroyed by the SessionFactory, but we had trouble building the SessionFactory
			// so destroy it manually.
			StandardServiceRegistryBuilder.destroy( registry );
		}
	}

	@Override
	public void shutdown() throws Exception {
		sessionFactory.close();
		
	}

}
