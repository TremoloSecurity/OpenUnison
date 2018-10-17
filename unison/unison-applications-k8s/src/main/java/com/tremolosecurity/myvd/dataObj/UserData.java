package com.tremolosecurity.myvd.dataObj;

public class UserData {
	
	String kind;
	K8sUser spec;
	public String getKind() {
		return kind;
	}
	public void setKind(String kind) {
		this.kind = kind;
	}
	public K8sUser getSpec() {
		return spec;
	}
	public void setSpec(K8sUser spec) {
		this.spec = spec;
	}
	
	
}
