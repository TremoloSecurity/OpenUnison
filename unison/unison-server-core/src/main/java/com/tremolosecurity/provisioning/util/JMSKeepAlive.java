package com.tremolosecurity.provisioning.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

import javax.jms.Connection;
import javax.jms.JMSException;
import javax.jms.MessageProducer;
import javax.jms.Session;
import javax.jms.TextMessage;

import org.apache.logging.log4j.Logger;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.server.StopableThread;

public class JMSKeepAlive implements StopableThread {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(JMSKeepAlive.class.getName());
	
	long lastCheck;
	long timeToWait;
	List<ConnectionHolder> cons;
	boolean keepRunning;
	
	
	
	private static JMSKeepAlive keepAlive;
	
	
	public JMSKeepAlive(long timeToWait)  {
		cons = new ArrayList<ConnectionHolder>();
		this.timeToWait = timeToWait;
		this.keepRunning = true; 
	}
	
	
	public static synchronized JMSKeepAlive getKeepAlive(long timeToWait) {
		if (keepAlive == null) {
			keepAlive = new JMSKeepAlive(timeToWait);
			GlobalEntries.getGlobalEntries().getConfigManager().addThread(keepAlive);
			new Thread(keepAlive).start();
		}
		return keepAlive;
	}
	
	
	
	
	@Override
	public void run() {
		while (keepRunning) {
			long now = System.currentTimeMillis();
			if (lastCheck == 0 || (now-lastCheck >= timeToWait)) {
				for (ConnectionHolder ch : this.cons) {
					try {
						TextMessage tm = ch.session.createTextMessage(UUID.randomUUID().toString());
						tm.setStringProperty("JMSXGroupID", "unison-keepalive");
						tm.setBooleanProperty("unisonignore", true);
						
						
						if (logger.isDebugEnabled()) {
							logger.debug("Sending keepalive for " + ch.con);
						}
						
						ch.mp.send(tm);
					} catch (JMSException e) {
						logger.error("Could not send keepalive", e);
					}
					
				}
			
				lastCheck = now;
			} else {
				try {
					
					Thread.sleep(10000);
				} catch (InterruptedException e) {
					
				}
			}
			
			
		}

	}

	@Override
	public void stop() {
		keepRunning = false;
		for (ConnectionHolder ch : this.cons) {
			try {
				ch.mp.close();
			} catch (Throwable t) {}
			
			try {
				ch.session.close();
			} catch (Throwable t) {}
			
			try {
				ch.con.close();
			} catch (Throwable t) {}
			
		}
		
	}


	public void addConnection(Connection con) throws JMSException {
		ConnectionHolder ch = new ConnectionHolder();
		ch.con = con;
		ch.session = con.createSession(false, Session.AUTO_ACKNOWLEDGE);
		
		
		String queueName = "";
		ConfigManager cfgMgr = GlobalEntries.getGlobalEntries().getConfigManager();  
		if (cfgMgr.getCfg().getProvisioning().getQueueConfig().isMultiTaskQueues()) {
			queueName = cfgMgr.getCfg().getProvisioning().getQueueConfig().getTaskQueueName().replace("{x}", Integer.toString(ThreadLocalRandom.current().nextInt(0,cfgMgr.getCfg().getProvisioning().getQueueConfig().getNumQueues())));
		} else {
			queueName = cfgMgr.getCfg().getProvisioning().getQueueConfig().getTaskQueueName();
		}
		
		
		ch.mp = ch.session.createProducer(ch.session.createQueue(queueName));
		
		this.cons.add(ch);
		
	}
	
	

}

class ConnectionHolder {
	Connection con;
	Session session;
	MessageProducer mp;
}
