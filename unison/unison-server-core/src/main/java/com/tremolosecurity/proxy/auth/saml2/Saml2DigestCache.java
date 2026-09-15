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

import com.tremolosecurity.proxy.auth.passwordreset.PasswordResetRequest;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.server.StopableThread;
import jakarta.persistence.PersistenceException;
import jakarta.persistence.Query;
import org.apache.log4j.Logger;
import org.hibernate.SessionFactory;
import org.hibernate.boot.MetadataSources;
import org.hibernate.boot.cfgxml.spi.LoadedConfig;
import org.hibernate.boot.jaxb.cfg.spi.JaxbCfgHibernateConfiguration;
import org.hibernate.boot.jaxb.cfg.spi.JaxbCfgMappingReferenceType;
import org.hibernate.boot.registry.StandardServiceRegistry;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.hibernate.cfg.Configuration;
import org.hibernate.exception.ConstraintViolationException;
import org.opensaml.xmlsec.signature.P;

import java.time.Instant;

public class Saml2DigestCache {
    static Saml2DigestCache cache;

    private SessionFactory sessionFactory;
    static Logger logger = Logger.getLogger(Saml2DigestCache.class.getName());

    private Saml2DigestCache() {

    }

    public static synchronized void initialize(String driver, String user,String password,String url,String dialect,int maxCons,int maxIdleCons,String validationQuery,String mappingFile,String createSchema) {
        if (cache == null) {
            cache = new Saml2DigestCache();
            cache.init(driver, user, password, url, dialect, maxCons, maxIdleCons, validationQuery, mappingFile, createSchema);
        }
    }

    public synchronized void init(String driver, String user,String password,String url,String dialect,int maxCons,int maxIdleCons,String validationQuery,String mappingFile,String createSchema) {


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
            jaxbCfg.setSessionFactory(new JaxbCfgHibernateConfiguration.JaxbCfgSessionFactory());

            JaxbCfgMappingReferenceType mrt = new JaxbCfgMappingReferenceType();
            mrt.setClazz(Saml2SigDigest.class.getName());
            jaxbCfg.getSessionFactory().getMapping().add(mrt);

            lc = LoadedConfig.consume(jaxbCfg);
        } else {
            lc = LoadedConfig.baseline();
        }

        StandardServiceRegistry registry = builder.configure(lc).applySettings(config.getProperties()).build();
        try {
            sessionFactory = null;

            if (mappingFile == null || mappingFile.trim().isEmpty()) {
                sessionFactory = new MetadataSources( registry ).buildMetadata().buildSessionFactory();
            } else {
                sessionFactory = new MetadataSources( registry ).addResource(mappingFile).buildMetadata().buildSessionFactory();
            }



            GlobalEntries.getGlobalEntries().getConfigManager().addThread(new StopableThread() {

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
        }
        catch (Exception e) {
            e.printStackTrace();
            // The registry would be destroyed by the SessionFactory, but we had trouble building the SessionFactory
            // so destroy it manually.
            StandardServiceRegistryBuilder.destroy( registry );
        }

    }

    public synchronized static Saml2DigestCache getInstance() {
        return cache;
    }

    private static <T extends Throwable> T findCause(
            Throwable error,
            Class<T> type) {

        for (Throwable current = error;
             current != null;
             current = current.getCause()) {

            if (type.isInstance(current)) {
                return type.cast(current);
            }
        }

        return null;
    }

    public boolean saveDigest(String digest, Instant expires) {
        org.hibernate.Session con = this.sessionFactory.openSession();

        try {
            con.beginTransaction();
            Saml2SigDigest digestObj = new Saml2SigDigest();
            digestObj.setDigest(digest);
            digestObj.setExpires(expires);
            con.persist(digestObj);
            con.flush();
            con.getTransaction().commit();
        } catch (PersistenceException e) {
            con.getTransaction().rollback();
            ConstraintViolationException constraintError =
                    findCause(e, ConstraintViolationException.class);

            if (constraintError != null) {
                String constraintName = constraintError.getConstraintName();

                if (constraintName.endsWith(".digests")) {
                    return false;
                } else {
                    logger.error("Error while saving digest " + digest, e);
                    return false;
                }
            } else {
                logger.error("Error while saving digest " + digest, e);
                return false;
            }

        } finally {
            con.close();
        }

        return true;
    }

    public int clearExpiredDigests() {
        org.hibernate.Session con = this.sessionFactory.openSession();
        try {
            con.beginTransaction();
            String hql = "DELETE FROM Saml2SigDigest s WHERE s.expires < :now";
            Query query = con.createQuery(hql);
            query.setParameter("now", Instant.now());
            int deleted = query.executeUpdate();
            con.getTransaction().commit();
            return deleted;
        } catch (Throwable e) {
            logger.warn("Error while clearing expired digests", e);
            con.getTransaction().rollback();
            return 0;
        } finally {
            con.close();
        }


    }
}
