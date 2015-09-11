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


package com.tremolosecurity.server;

import net.sourceforge.myvd.core.InsertChain;
import net.sourceforge.myvd.router.Router;

public interface MyVDServer {

	public final static String VERSION = "0.9.0";

	public abstract InsertChain getGlobalChain();

	public abstract Router getRouter();

	public abstract void reload() throws Exception;

	public abstract void startServer() throws Exception;

	public abstract void stopServer() throws Exception;

}