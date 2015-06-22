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



package com.tremolosecurity.proxy.myvd.log;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Properties;

import org.apache.log4j.AsyncAppender;
import org.apache.log4j.DailyRollingFileAppender;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.apache.log4j.PropertyConfigurator;
import org.apache.log4j.RollingFileAppender;

import net.sourceforge.myvd.chain.AddInterceptorChain;
import net.sourceforge.myvd.chain.BindInterceptorChain;
import net.sourceforge.myvd.chain.CompareInterceptorChain;
import net.sourceforge.myvd.chain.DeleteInterceptorChain;
import net.sourceforge.myvd.chain.ExetendedOperationInterceptorChain;
import net.sourceforge.myvd.chain.ModifyInterceptorChain;
import net.sourceforge.myvd.chain.PostSearchCompleteInterceptorChain;
import net.sourceforge.myvd.chain.PostSearchEntryInterceptorChain;
import net.sourceforge.myvd.chain.RenameInterceptorChain;
import net.sourceforge.myvd.chain.SearchInterceptorChain;
import net.sourceforge.myvd.core.NameSpace;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.types.Attribute;
import net.sourceforge.myvd.types.Bool;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.types.ExtendedOperation;
import net.sourceforge.myvd.types.Filter;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;

import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;

public class AccessLog implements Insert {

	public static final String ACCESS_LOG_OPNUM = "ACCESS_LOG_OPNUM_";
	public static final String ACCESS_LOG_CONNUM = "ACCESS_LOG_CONNUM_";

	public static final String ACCESS_LOG_SRCH_OP = "ACCESS_LOG_SRCH_OP_";
	public static final String ACCESS_LOG_SRCH_CON = "ACCESS_LOG_SRCH_CON_";
	public static final String ACCESS_LOG_SRCH_BEGIN = "ACCESS_LOG_SRCH_BEGIN_";
	public static final String ACCESS_LOG_SRCH_COUNT = "ACCESS_LOG_SRCH_COUNT_";
	
	
	static Logger logger = Logger.getLogger(AccessLog.class.getName());
	String name;
	Int con;
	
	private void getOpNum(HashMap<Object,Object> session,Int con,Int op) {
		StringBuffer b = new StringBuffer();
		b.append(AccessLog.ACCESS_LOG_CONNUM).append(this.name);
		
		Integer conNum = (Integer) session.get(b.toString());
		if (conNum == null) {
			synchronized (this.con) {
				this.con.setValue(this.con.getValue() + 1);
				
				session.put(b.toString(), new Integer(this.con.getValue()));
				con.setValue(this.con.getValue());
			}
		} else {
			con.setValue(conNum.intValue());
		}
		
		
		synchronized (session) {
			Integer opNum = (Integer) session.get(b.toString());
			if (opNum == null) {
				op.setValue(0);
				session.put(b.toString(), new Integer(op.getValue()));
			} else {
				op.setValue(opNum.intValue() + 1);
				session.put(b.toString(), new Integer(op.getValue()));
			}
		}
		
	}
	
	
	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		
		long start = System.currentTimeMillis();
		long end = 0;
		int result = -1;
		Int op = new Int(0);
		Int con = new Int(0);
		
		this.getOpNum(chain.getSession(), con, op);
		
		StringBuffer buf = new StringBuffer("ADD op=").append(op.getValue()).append(" con=").append(con.getValue()).append(" dn='").append(entry.getEntry().getDN()).append("'");
		
		logger.info(buf.toString());
		
		try {
			chain.nextAdd(entry, constraints);
			result = 0;
		} catch (LDAPException le) {
			result = le.getResultCode();
			throw le;
		} finally {
			end = System.currentTimeMillis();
			if (result == -1) {
				result = LDAPException.OPERATIONS_ERROR;
			}
			
			buf.setLength(0);
			buf.append("RESULT op=").append(op.getValue()).append(" con=").append(con.getValue()).append(" result=").append(result).append(" time=").append(end-start);
			logger.info(buf.toString());
			
		}

	}

	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		long start = System.currentTimeMillis();
		long end = 0;
		int result = -1;
		Int op = new Int(0);
		Int con = new Int(0);
		
		this.getOpNum(chain.getSession(), con, op);
		
		StringBuffer buf = new StringBuffer("BIND op=").append(op.getValue()).append(" con=").append(con.getValue()).append(" dn='").append(dn.getDN()).append("'");
		
		logger.info(buf.toString());
		
		try {
			chain.nextBind(dn, pwd, constraints);
			result = 0; 
		} catch (LDAPException le) {
			result = le.getResultCode();
			throw le;
		} finally {
			end = System.currentTimeMillis();
			if (result == -1) {
				result = LDAPException.OPERATIONS_ERROR;
			}
			
			buf.setLength(0);
			buf.append("RESULT op=").append(op.getValue()).append(" con=").append(con.getValue()).append(" result=").append(result).append(" time=").append(end-start);
			logger.info(buf.toString());
			
		}

	}

	public void compare(CompareInterceptorChain chain, DistinguishedName dn,
			Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		long start = System.currentTimeMillis();
		long end = 0;
		int result = -1;
		Int op = new Int(0);
		Int con = new Int(0);
		
		this.getOpNum(chain.getSession(), con, op);
		
		StringBuffer buf = new StringBuffer("COMPARE op=").append(op.getValue()).append(" con=").append(con.getValue()).append(" dn='").append(dn.getDN()).append("' attribute='").append(attrib.getAttribute().getName()).append("' value='").append(attrib.getAttribute().getName()).append("'");
		
		logger.info(buf.toString());
		
		try {
			chain.nextCompare(dn, attrib, constraints);
			result = 0;
		} catch (LDAPException le) {
			result = le.getResultCode();
			throw le;
		} finally {
			end = System.currentTimeMillis();
			if (result == -1) {
				result = LDAPException.OPERATIONS_ERROR;
			}
			
			buf.setLength(0);
			buf.append("RESULT op=").append(op.getValue()).append(" con=").append(con.getValue()).append(" result=").append(result).append(" time=").append(end-start);
			logger.info(buf.toString());
			
		}

	}

	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		this.con = new Int(0);
		
		
	}

	public void delete(DeleteInterceptorChain chain, DistinguishedName dn,
			LDAPConstraints constraints) throws LDAPException {
		long start = System.currentTimeMillis();
		long end = 0;
		int result = -1;
		Int op = new Int(0);
		Int con = new Int(0);
		
		this.getOpNum(chain.getSession(), con, op);
		
		StringBuffer buf = new StringBuffer("DELETE op=").append(op.getValue()).append(" con=").append(con.getValue()).append(" dn='").append(dn.getDN()).append("'");
		
		logger.info(buf.toString());
		
		try {
			chain.nextDelete(dn, constraints);
			result = 0; 
		} catch (LDAPException le) {
			result = le.getResultCode();
			throw le;
		} finally {
			end = System.currentTimeMillis();
			if (result == -1) {
				result = LDAPException.OPERATIONS_ERROR;
			}
			
			buf.setLength(0);
			buf.append("RESULT op=").append(op.getValue()).append(" con=").append(con.getValue()).append(" result=").append(result).append(" time=").append(end-start);
			logger.info(buf.toString());
			
		}

	}

	public void extendedOperation(ExetendedOperationInterceptorChain chain,
			ExtendedOperation op, LDAPConstraints constraints)
			throws LDAPException {
		long start = System.currentTimeMillis();
		long end = 0;
		int result = -1;
		Int opn = new Int(0);
		Int con = new Int(0);
		
		this.getOpNum(chain.getSession(), con, opn);
		
		StringBuffer buf = new StringBuffer("EXT op=").append(opn.getValue()).append(" con=").append(con.getValue());
		
		logger.info(buf.toString());
		
		try {
			chain.nextExtendedOperations(op, constraints);
			result = 0;
		} catch (LDAPException le) {
			result = le.getResultCode();
			throw le;
		} finally {
			end = System.currentTimeMillis();
			if (result == -1) {
				result = LDAPException.OPERATIONS_ERROR;
			}
			
			buf.setLength(0);
			buf.append("RESULT op=").append(opn.getValue()).append(" con=").append(con.getValue()).append(" result=").append(result).append(" time=").append(end-start);
			logger.info(buf.toString());
			
		}

	}

	public String getName() {
		return this.name;
	}

	public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
			ArrayList<LDAPModification> mods, LDAPConstraints constraints)
			throws LDAPException {
		long start = System.currentTimeMillis();
		long end = 0;
		int result = -1;
		Int op = new Int(0);
		Int con = new Int(0);
		
		this.getOpNum(chain.getSession(), con, op);
		
		StringBuffer buf = new StringBuffer("MOD op=").append(op.getValue()).append(" con=").append(con.getValue()).append(" dn='").append(dn.getDN()).append("'");
		
		logger.info(buf.toString());
		
		try {
			chain.nextModify(dn, mods, constraints);
			result = 0;
		} catch (LDAPException le) {
			result = le.getResultCode();
			throw le;
		} finally {
			end = System.currentTimeMillis();
			if (result == -1) {
				result = LDAPException.OPERATIONS_ERROR;
			}
			
			buf.setLength(0);
			buf.append("RESULT op=").append(op.getValue()).append(" con=").append(con.getValue()).append(" result=").append(result).append(" time=").append(end-start);
			logger.info(buf.toString());
			
		}

	}

	public void postSearchComplete(PostSearchCompleteInterceptorChain chain,
			DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		chain.nextPostSearchComplete(base, scope, filter, attributes, typesOnly, constraints);
		
		StringBuffer b = new StringBuffer();
		b.append(AccessLog.ACCESS_LOG_SRCH_BEGIN).append(this.name);
		long start = (Long) chain.getRequest().get(b.toString());
		
		
		b.setLength(0);
		b.append(AccessLog.ACCESS_LOG_SRCH_OP).append(this.name);
		Int op = (Int) chain.getRequest().get(b.toString());
		
		
		b.setLength(0);
		b.append(AccessLog.ACCESS_LOG_SRCH_CON).append(this.name);
		Int con = (Int) chain.getRequest().get(b.toString());
		
		
		b.setLength(0);
		b.append(AccessLog.ACCESS_LOG_SRCH_COUNT).append(this.name);
		Int nentries = (Int) chain.getRequest().get(b.toString());
		
		
		long end = System.currentTimeMillis();

		StringBuffer buf = new StringBuffer();
		buf.append("SRCH-RESULT op=").append(op.getValue()).append(" con=").append(con.getValue()).append(" entries=").append(nentries.getValue()).append(" time=").append(end-start);

		logger.info(buf);
	}

	public void postSearchEntry(PostSearchEntryInterceptorChain chain,
			Entry entry, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		
		StringBuffer b = new StringBuffer();
		b.append(AccessLog.ACCESS_LOG_SRCH_COUNT).append(this.name);
		Int nentries = (Int) chain.getRequest().get(b.toString());
		
		if (entry.isReturnEntry()) {
			nentries.setValue(nentries.getValue() + 1);
		}
		
		chain.nextPostSearchEntry(entry, base, scope, filter, attributes, typesOnly, constraints);

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, Bool deleteOldRdn,
			LDAPConstraints constraints) throws LDAPException {
		long start = System.currentTimeMillis();
		long end = 0;
		int result = -1;
		Int op = new Int(0);
		Int con = new Int(0);
		
		this.getOpNum(chain.getSession(), con, op);
		
		StringBuffer buf = new StringBuffer("RENAME op=").append(op.getValue()).append(" con=").append(con.getValue()).append(" dn='").append(dn.getDN()).append("'");
		
		logger.info(buf.toString());
		
		try {
			chain.nextRename(dn, newRdn, deleteOldRdn, constraints);
			result = 0;
		} catch (LDAPException le) {
			result = le.getResultCode();
			throw le;
		} finally {
			end = System.currentTimeMillis();
			if (result == -1) {
				result = LDAPException.OPERATIONS_ERROR;
			}
			
			buf.setLength(0);
			buf.append("RESULT op=").append(op.getValue()).append(" con=").append(con.getValue()).append(" result=").append(result).append(" time=").append(end-start);
			logger.info(buf.toString());
			
		}

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, DistinguishedName newParentDN,
			Bool deleteOldRdn, LDAPConstraints constraints)
			throws LDAPException {
		long start = System.currentTimeMillis();
		long end = 0;
		int result = -1;
		Int op = new Int(0);
		Int con = new Int(0);
		
		this.getOpNum(chain.getSession(), con, op);
		
		StringBuffer buf = new StringBuffer("RENAME op=").append(op.getValue()).append(" con=").append(con.getValue()).append(" dn='").append(dn.getDN()).append("'");
		
		logger.info(buf.toString());
		
		try {
			chain.nextRename(dn, newRdn, newParentDN, deleteOldRdn, constraints);
			result = 0;
		} catch (LDAPException le) {
			result = le.getResultCode();
			throw le;
		} finally {
			end = System.currentTimeMillis();
			if (result == -1) {
				result = LDAPException.OPERATIONS_ERROR;
			}
			
			buf.setLength(0);
			buf.append("RESULT op=").append(op.getValue()).append(" con=").append(con.getValue()).append(" result=").append(result).append(" time=").append(end-start);
			logger.info(buf.toString());
			
		}

	}

	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes,
			Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		long start = System.currentTimeMillis();
		long end = 0;
		int result = -1;
		Int op = new Int(0);
		Int con = new Int(0);
		Int nentries = new Int(0);
		
		this.getOpNum(chain.getSession(), con, op);
		
		StringBuffer buf = new StringBuffer();
		Iterator<Attribute> it = attributes.iterator();
		while (it.hasNext()) {
			buf.append(it.next().getAttribute().getName()).append(' ');
		}
		
		buf = new StringBuffer("SRCH op=").append(op.getValue()).append(" con=").append(con.getValue()).append(" base='").append(base.getDN()).append("' filter='").append(filter.getRoot().toString()).append("' scope='").append(scope.getValue()).append("' attribs='").append(buf).append("'");
		
		
		StringBuffer b = new StringBuffer();
		b.append(AccessLog.ACCESS_LOG_SRCH_BEGIN).append(this.name);
		chain.getRequest().put(b.toString(), start);
		
		b.setLength(0);
		b.append(AccessLog.ACCESS_LOG_SRCH_CON).append(this.name);
		chain.getRequest().put(b.toString(), con);
		
		b.setLength(0);
		b.append(AccessLog.ACCESS_LOG_SRCH_OP).append(this.name);
		chain.getRequest().put(b.toString(), op);
		
		b.setLength(0);
		b.append(AccessLog.ACCESS_LOG_SRCH_COUNT).append(this.name);
		chain.getRequest().put(b.toString(),nentries);
		
		logger.info(buf.toString());
		
		try {
			chain.nextSearch(base, scope, filter, attributes, typesOnly, results, constraints);
			result = 0; 
		} catch (LDAPException le) {
			result = le.getResultCode();
			throw le;
		} finally {
			end = System.currentTimeMillis();
			if (result == -1) {
				result = LDAPException.OPERATIONS_ERROR;
			}
			
			buf.setLength(0);
			buf.append("RESULT op=").append(op.getValue()).append(" con=").append(con.getValue()).append(" result=").append(result).append(" time=").append(end-start);
			logger.info(buf.toString());
			
		}

	}

	public void shutdown() {
		// TODO Auto-generated method stub

	}

}
