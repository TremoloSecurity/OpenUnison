package org.apache.qpid.jms.provider.amqp.message;

import org.apache.qpid.proton.amqp.Symbol;

public class AmqGetAnnotations {
	
	AmqpJmsMessageFacade msg;
	
	public AmqGetAnnotations(AmqpJmsMessageFacade msg) {
		this.msg = msg;
	}
	
	public String getMessageAnnotation(String name) {
		Symbol s = Symbol.valueOf(name);
		if (msg.messageAnnotationExists(s)) {
			return (String) msg.getMessageAnnotation(s);
		} else {
			return null;
		}
	}
}
