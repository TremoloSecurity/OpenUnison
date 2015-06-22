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


package com.tremolosecurity.proxy.util;

import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.DriverPropertyInfo;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.Properties;
import java.util.logging.Logger;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;

public class DataSourceDriver implements Driver {
	
	static {
	       try {
	           
	        DriverManager.registerDriver(new DataSourceDriver());
	       }
	       catch (SQLException e) {
	           
	        e.printStackTrace(System.out);
	       }
	        
	    }
	
	public DataSourceDriver() throws SQLException {
		//System.err.println("Registering");
		DriverManager.registerDriver(this);
		//System.err.println("Registered");
	}

	@Override
	public Connection connect(String url, Properties info) throws SQLException {
		String ctxLookup = url.substring("jdbc:datasource://".length());
		try {
			InitialContext ctx = new InitialContext();
			DataSource ds = (DataSource) ctx.lookup(ctxLookup);
			if (ds == null) {
				throw new SQLException("No context for '" + ctxLookup + "' found");
			}
			
			return ds.getConnection();
		} catch (NamingException e) {
			throw new SQLException("No context for '" + ctxLookup + "' found",e);
		}
		
	}

	@Override
	public boolean acceptsURL(String url) throws SQLException {
		//System.out.println(url + " / " + url.startsWith("jdbc:datasource://"));
		return url.startsWith("jdbc:datasource://");
	}

	@Override
	public DriverPropertyInfo[] getPropertyInfo(String url, Properties info)
			throws SQLException {
		return new DriverPropertyInfo[0];
	}

	@Override
	public int getMajorVersion() {
		return 4;
	}

	@Override
	public int getMinorVersion() {
		return 0;
	}

	@Override
	public boolean jdbcCompliant() {
		return false;
	}

	//@Override
	public Logger getParentLogger() throws SQLFeatureNotSupportedException {
		
		return null;
	}

}
