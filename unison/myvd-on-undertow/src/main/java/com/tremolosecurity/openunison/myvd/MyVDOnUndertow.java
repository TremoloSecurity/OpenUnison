/*******************************************************************************
 * Copyright 2021 Tremolo Security, Inc.
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
package com.tremolosecurity.openunison.myvd;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.StringTokenizer;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;

import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.registries.SchemaLoader;
import org.apache.directory.api.ldap.schema.extractor.SchemaLdifExtractor;
import org.apache.directory.api.ldap.schema.extractor.impl.DefaultSchemaLdifExtractor;
import org.apache.directory.api.ldap.schema.loader.LdifSchemaLoader;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.apache.directory.api.util.exception.Exceptions;
import org.apache.directory.server.constants.ServerDNConstants;
import org.apache.directory.server.core.DefaultDirectoryService;
import org.apache.directory.server.core.api.DnFactory;
import org.apache.directory.server.core.api.InstanceLayout;
import org.apache.directory.server.core.api.interceptor.Interceptor;
import org.apache.directory.server.core.api.schema.SchemaPartition;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmPartition;
import org.apache.directory.server.core.partition.ldif.LdifPartition;
import org.apache.directory.server.core.shared.DefaultDnFactory;
import org.apache.directory.server.i18n.I18n;
import org.apache.directory.server.ldap.handlers.request.ExtendedRequestHandler;
import org.apache.directory.server.protocol.shared.transport.TcpTransport;
import org.apache.directory.server.protocol.shared.transport.Transport;
import org.apache.log4j.Logger;

import com.google.common.io.Files;
import com.tremolosecurity.config.ssl.AliasX509KeyManager;
import com.tremolosecurity.config.xml.TremoloType;
import com.tremolosecurity.openunison.OpenUnisonConfigManager;
import com.tremolosecurity.openunison.undertow.OpenUnisonConfig;
import com.tremolosecurity.server.GlobalEntries;

import net.sf.ehcache.config.CacheConfiguration;
import net.sourceforge.myvd.core.InsertChain;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.server.ServerCore;
import net.sourceforge.myvd.server.apacheds.ApacheDSUtil;
import net.sourceforge.myvd.server.apacheds.MyVDInterceptor;
import net.sourceforge.myvd.server.apacheds.MyVDReferalManager;

public class MyVDOnUndertow implements MyVDWrapper {
	
	static Logger logger = Logger.getLogger(MyVDOnUndertow.class);
	
	private static DefaultDirectoryService directoryService;
	private static DnFactory dnFactory;
	private static String apachedsPath;
	private static MyVDOpenUnisonLDAPServer ldapServer;
	
	static Properties props;
	static ServerCore myvdServerCore;
	private static InsertChain globalChain;
	private static Router router;
	
	@Override
	public void startMyVD(OpenUnisonConfig config,TremoloType unisonConfiguration) throws LdapInvalidDnException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, LdapException, Exception {
		myvdServerCore = ((OpenUnisonConfigManager) GlobalEntries.getGlobalEntries().getConfigManager()).getMyVDServerCore();
		
		globalChain = myvdServerCore.getGlobalChain();
		router = myvdServerCore.getRouter();
		
		startMyVDListener(config,unisonConfiguration);
	}
	
	private static void startMyVDListener(final OpenUnisonConfig fconfig,TremoloType unisonConfiguration)
			throws Exception, IOException, LdapInvalidDnException, LdapException, KeyStoreException,
			NoSuchAlgorithmException, CertificateException, FileNotFoundException, UnrecoverableKeyException {
		apachedsPath = Files.createTempDir().getAbsolutePath();
		
		directoryService = new DefaultDirectoryService();
        directoryService.setShutdownHookEnabled(false);
        directoryService.setAccessControlEnabled(false);
        directoryService.setAllowAnonymousAccess(true);
        directoryService.setInstanceLayout(new InstanceLayout(new File(apachedsPath)));
        directoryService.setReferralManager(new MyVDReferalManager());
        
        
        
        
        // first load the schema
        initSchemaPartition();
        
     // then the system partition
        // this is a MANDATORY partition
        // DO NOT add this via addPartition() method, trunk code complains about duplicate partition
        // while initializing 
        JdbmPartition systemPartition = new JdbmPartition(directoryService.getSchemaManager(),dnFactory);
        systemPartition.setId( "system" );
        systemPartition.setPartitionPath( new File( directoryService.getInstanceLayout().getPartitionsDirectory(), systemPartition.getId() ).toURI() );
        systemPartition.setSuffixDn( new Dn( ServerDNConstants.SYSTEM_DN ) );
        systemPartition.setSchemaManager( directoryService.getSchemaManager() );
        
        // mandatory to call this method to set the system partition
        // Note: this system partition might be removed from trunk
        directoryService.setSystemPartition( systemPartition );
        
        // Disable the ChangeLog system
        directoryService.getChangeLog().setEnabled( false );
        directoryService.setDenormalizeOpAttrsEnabled( true );
        
        
        String extraAttribs = System.getProperty("myvd.schema.extraAttribs","");
        if (extraAttribs != null) {
			StringTokenizer toker = new StringTokenizer(extraAttribs);
			
			
			while (toker.hasMoreTokens()) {
				String token = toker.nextToken().toLowerCase();
				logger.info("Adding attribute '" + token + "' to schema");
				ApacheDSUtil.addAttributeToSchema(new DefaultAttribute(token), directoryService.getSchemaManager());
			}
        }
        
        
        String binaryAttributes = System.getProperty("myvd.schema.binaryAttribs","");
        HashSet<String> binaryAttrs = new HashSet<String>();
        if (binaryAttributes != null) {
        	StringTokenizer toker = new StringTokenizer(binaryAttributes);
			
			
			while (toker.hasMoreTokens()) {
				String token = toker.nextToken().toLowerCase();
				binaryAttrs.add(token);
				ApacheDSUtil.addBinaryAttributeToSchema(new DefaultAttribute(token), directoryService.getSchemaManager());
			}
        }
        
        List<Interceptor> newlist = new ArrayList<Interceptor>();
        newlist.add(new MyVDInterceptor(globalChain,router,directoryService.getSchemaManager(),binaryAttrs));
        
        directoryService.setInterceptors(newlist);
        
        directoryService.startup();
        
        
        ldapServer = new MyVDOpenUnisonLDAPServer();
        ldapServer.setDirectoryService(directoryService);
        
        ArrayList<TcpTransport> transports = new ArrayList<TcpTransport>();
        
        TcpTransport ldapTransport = null;
        
        if (fconfig.getLdapPort() > 0) {
        	ldapTransport = new TcpTransport(fconfig.getLdapPort());
        	transports.add(ldapTransport);
        }
        
        if (fconfig.getLdapsPort() > 0) {
        	String alias = fconfig.getLdapsKeyName();
        	
        	KeyStore keystore = KeyStore.getInstance("PKCS12");
    		try {
    			keystore.load(new FileInputStream(unisonConfiguration.getKeyStorePath()), unisonConfiguration.getKeyStorePassword().toCharArray());
    		} catch (Throwable t) {
    			keystore = KeyStore.getInstance("JCEKS");
    			keystore.load(new FileInputStream(unisonConfiguration.getKeyStorePath()), unisonConfiguration.getKeyStorePassword().toCharArray());
    		}
        	
        	KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			kmf.init(keystore, unisonConfiguration.getKeyStorePassword().toCharArray());
			
			X509ExtendedKeyManager keyMgr = (X509ExtendedKeyManager) kmf.getKeyManagers()[0];
			KeyManager[] keyManagers = new KeyManager[1];
			keyManagers[0] = new AliasX509KeyManager(alias,keyMgr,keystore);

			
			ArrayList<String> allowedNames = new ArrayList<String>();
			
			TcpTransport ldapsTransport = new TcpTransport(fconfig.getLdapsPort());
        	
			ldapsTransport.enableSSL(true);
			
			
			if (fconfig.getClientAuth() != null && fconfig.getClientAuth().equalsIgnoreCase("want")) {
				ldapsTransport.setWantClientAuth(true);
			}
			
			if (fconfig.getClientAuth() != null && fconfig.getClientAuth().equalsIgnoreCase("need")) {
				ldapsTransport.setNeedClientAuth(true);
			}
			
			if (fconfig.getAllowedTlsProtocols() != null && fconfig.getAllowedTlsProtocols().size() > 0) {
				ldapsTransport.setEnabledProtocols(fconfig.getAllowedTlsProtocols());
			}
			
			if (fconfig.getCiphers() != null && fconfig.getCiphers().size() > 0) {
				ldapsTransport.setEnabledCiphers(fconfig.getCiphers());
			}
			
			
			transports.add(ldapsTransport);
			
			
			
			ldapServer.setTlsParams(fconfig.getSecureKeyAlias(), keystore, keyMgr);
        }
        
        Transport[] t = new Transport[transports.size()];
		
		int i=0;
		for (Transport tt : transports) {
			t[i] = tt;
			i++;
		}
		
		ldapServer.setMaxSizeLimit(0);
		ldapServer.setMaxTimeLimit(0);
		
		ldapServer.setTransports(t);
        ldapServer.start();
        ((ExtendedRequestHandler) ldapServer.getExtendedRequestHandler()).init(globalChain, router);
	}
	
	/**
     * initialize the schema manager and add the schema partition to diectory service
     *
     * @throws Exception if the schema LDIF files are not found on the classpath
     */
    private static void initSchemaPartition() throws Exception
    {
        InstanceLayout instanceLayout = directoryService.getInstanceLayout();
        
        File schemaPartitionDirectory = new File( instanceLayout.getPartitionsDirectory(), "schema" );

        // Extract the schema on disk (a brand new one) and load the registries
        if ( schemaPartitionDirectory.exists() )
        {
            logger.info( "schema partition already exists, skipping schema extraction" );
        }
        else
        {
            SchemaLdifExtractor extractor = new DefaultSchemaLdifExtractor( instanceLayout.getPartitionsDirectory() );
            extractor.extractOrCopy();
        }

        SchemaLoader loader = new LdifSchemaLoader( schemaPartitionDirectory );
        SchemaManager schemaManager = new DefaultSchemaManager( loader );

        // We have to load the schema now, otherwise we won't be able
        // to initialize the Partitions, as we won't be able to parse
        // and normalize their suffix Dn
        schemaManager.loadAllEnabled();

        List<Throwable> errors = schemaManager.getErrors();

        if ( errors.size() != 0 )
        {
            throw new Exception( I18n.err( I18n.ERR_317, Exceptions.printErrors( errors ) ) );
        }

        directoryService.setSchemaManager( schemaManager );
        
        if (dnFactory == null) {
        	dnFactory = new DefaultDnFactory(schemaManager,new net.sf.ehcache.Cache(new CacheConfiguration("myvd-apacheds-dns",10000)));
        }
        
        // Init the LdifPartition with schema
        LdifPartition schemaLdifPartition = new LdifPartition( schemaManager, dnFactory );
        schemaLdifPartition.setPartitionPath( schemaPartitionDirectory.toURI() );

        // The schema partition
        SchemaPartition schemaPartition = new SchemaPartition( schemaManager );
        schemaPartition.setWrappedPartition( schemaLdifPartition );
        directoryService.setSchemaPartition( schemaPartition );
        
        
        
    }
	
    
    private void deleteDir(File d) {
    	if (d.isDirectory()) {
    		File[] subs = d.listFiles();
    		for (File f : subs) {
    			deleteDir(f);
    		}
    		
    		if (! d.delete()) {
    			logger.error("Could not delete directory : '" + d.getAbsolutePath() + "'");
    		}
    	} else {
    		if (! d.delete()) {
    			logger.error("Could not delete file : '" + d.getAbsolutePath() + "'");
    		}
    	}
    }

	@Override
	public void shutdown() throws Exception {
		this.directoryService.shutdown();
		
	}

}
