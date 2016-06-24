/*******************************************************************************
 * Copyright 2016 Tremolo Security, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.tremolosecurity.unison.openstack.model;

import java.util.List;

public class RoleAssignmentResponse {
	List<KSRoleAssignment> role_assignments;

	public List<KSRoleAssignment> getRole_assignments() {
		return role_assignments;
	}

	public void setRole_assignments(List<KSRoleAssignment> role_assignments) {
		this.role_assignments = role_assignments;
	}
	
	
}
