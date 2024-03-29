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
package com.tremolosecurity.provisioning.objects;
// Generated Apr 7, 2016 3:31:46 PM by Hibernate Tools 4.3.1.Final

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

/**
 * AllowedApprovers generated by hbm2java
 */
@Entity
@Table(name = "allowedApprovers")
public class AllowedApprovers implements java.io.Serializable {

	private int id;
	private Approvals approvals;
	private Approvers approvers;

	public AllowedApprovers() {
	}

	public AllowedApprovers(int id, Approvals approvals, Approvers approvers) {
		this.id = id;
		this.approvals = approvals;
		this.approvers = approvers;
	}

	@Id
	@GeneratedValue(strategy=GenerationType.IDENTITY)
	@Column(name = "id", unique = true, nullable = false)
	public int getId() {
		return this.id;
	}

	public void setId(int id) {
		this.id = id;
	}

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "approval", nullable = false)
	public Approvals getApprovals() {
		return this.approvals;
	}

	public void setApprovals(Approvals approvals) {
		this.approvals = approvals;
	}

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "approver", nullable = false)
	public Approvers getApprovers() {
		return this.approvers;
	}

	public void setApprovers(Approvers approvers) {
		this.approvers = approvers;
	}

}
