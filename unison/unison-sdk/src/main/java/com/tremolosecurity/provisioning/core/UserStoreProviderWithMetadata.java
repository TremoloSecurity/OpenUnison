package com.tremolosecurity.provisioning.core;

import java.util.Map;

public interface UserStoreProviderWithMetadata {

	public abstract Map<String,String> getAnnotations();
	
	public abstract Map<String,String> getLabels();
}
