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


package com.tremolosecurity.certs;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import com.novell.ldap.util.RDN;

public class CertData {
	String alias = "";
	String type = "";
	

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	String serverName = "";
	String ou = "";
	String o = "";
	String l = "";
	String st = "";
	String c = "";

	int size = 2048;
	boolean rsa = true;

	String sigAlg = "SHA256withRSA";
	Date notBefore = new Date(System.currentTimeMillis());
	Date notAfter = new Date(System.currentTimeMillis() + 315360000000L);
	
	SimpleDateFormat sdf = new SimpleDateFormat("MM/dd/yyyy");

	boolean caCert;
	
	List<String> subjectAlternativeNames = new ArrayList<String>();

    public boolean isCaCert() {
		return this.caCert;
	}

	public void setCaCert(boolean caCert) {
		this.caCert = caCert;
	}

	public String getAlias() {
		return alias;
	}

	public void setAlias(String alias) {
		this.alias = alias;
	}
	
	public String getServerName() {
		return serverName;
	}

	public void setServerName(String serverName) {
		this.serverName = CertData.escpaeRDN(serverName);
	}

	public String getOu() {
		return ou;
	}

	public void setOu(String ou) {
		this.ou = CertData.escpaeRDN(ou);
	}

	public String getO() {
		return o;
	}

	public void setO(String o) {
		this.o = CertData.escpaeRDN(o);
	}

	public boolean isRsa() {
		return rsa;
	}

	public void setRsa(boolean rsa) {
		this.rsa = rsa;
	}

	public String getSigAlg() {
		return sigAlg;
	}

	public void setSigAlg(String sigAlg) {
		this.sigAlg = sigAlg;
	}

	public Date getNotBefore() {
		return notBefore;
	}

	public void setNotBefore(Date notBefore) {
		this.notBefore = notBefore;
	}
	
	public String getNotBeforeStr() {
		return sdf.format(notBefore);
	}

	public void setNotBeforeStr(String notBefore) throws Exception {
		this.notBefore = sdf.parse(notBefore);
	}

	public Date getNotAfter() {
		return notAfter;
	}

	public void setNotAfter(Date notAfter) {
		this.notAfter = notAfter;
	}
	
	public String getNotAfterStr() {
		return sdf.format(notAfter);
	}

	public void setNotAfterStr(String notAfter) throws Exception {
		
			this.notAfter = sdf.parse(notAfter);
		
	}

	public String getL() {
		return l;
	}

	public void setL(String l) {
		this.l = CertData.escpaeRDN(l);
	}

	public String getSt() {
		return st;
	}

	public void setSt(String st) {
		this.st = CertData.escpaeRDN(st);
	}

	public String getC() {
		return c;
	}

	public void setC(String c) {
		this.c = CertData.escpaeRDN(c);
	}

	public int getSize() {
		return size;
	}

	public void setSize(int size) {
		this.size = size;
	}
	
	public List<String> getSigAlgs() {
		ArrayList<String> algs = new ArrayList<String>();
		algs.add("SHA1withDSA");
		algs.add("MD2withRSA");
		algs.add("MD5withRSA");
		algs.add("SHA1withRSA");
		algs.add("SHA224withRSA");
		algs.add("SHA256withRSA");
		algs.add("SHA384withRSA");
		algs.add("SHA512withRSA");
		algs.add("RIPEMD160withRSA");
		algs.add("RIPEMD128withRSA");
		algs.add("RIPEMD256withRSA");
		
		return algs;
	}
	
	public static String escpaeRDN(String rdn) {
		return rdn.replaceAll("[,]", "\\\\,").replaceAll("[+]", "\\\\+").replaceAll("[=]", "\\\\=");
	}

	public List<String> getSubjectAlternativeNames() {
		return subjectAlternativeNames;
	}

	public void setSubjectAlternativeNames(List<String> subjectAlternativeNames) {
		this.subjectAlternativeNames = subjectAlternativeNames;
	}
	
	
}
