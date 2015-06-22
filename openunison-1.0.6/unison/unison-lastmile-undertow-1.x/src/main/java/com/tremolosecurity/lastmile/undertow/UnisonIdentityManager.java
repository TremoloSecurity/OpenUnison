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


package com.tremolosecurity.lastmile.undertow;

import io.undertow.security.idm.Account;
import io.undertow.security.idm.Credential;
import io.undertow.security.idm.IdentityManager;

public class UnisonIdentityManager implements IdentityManager {

	private UnisonAccount account;
	
	public UnisonIdentityManager(UnisonAccount account) {
		this.account = account;
	}
	
	@Override
	public Account verify(Account account) {
		if (this.account.equals(account)) {
			return this.account;
		} else {
			return null;
		}
	}

	@Override
	public Account verify(String id, Credential credential) {
		if (this.account.getPrincipal().getName().equals(id)) {
			return this.account;
		} else {
			return null;
		}
	}

	@Override
	public Account verify(Credential credential) {
		return this.account;
	}

}
