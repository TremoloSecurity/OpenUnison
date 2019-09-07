/*******************************************************************************
 * Copyright 2019 Tremolo Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/

package com.tremolosecurity.k8s.model;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;
import org.apache.commons.lang.builder.ToStringBuilder;

public class UpdateController {

    @SerializedName("image")
    @Expose
    private String image;
    @SerializedName("schedule")
    @Expose
    private String schedule;
    @SerializedName("days_to_expire")
    @Expose
    private long daysToExpire;

    /**
     * No args constructor for use in serialization
     * 
     */
    public UpdateController() {
    }

    /**
     * 
     * @param schedule
     * @param daysToExpire
     * @param image
     */
    public UpdateController(String image, String schedule, long daysToExpire) {
        super();
        this.image = image;
        this.schedule = schedule;
        this.daysToExpire = daysToExpire;
    }

    public String getImage() {
        return image;
    }

    public void setImage(String image) {
        this.image = image;
    }

    public UpdateController withImage(String image) {
        this.image = image;
        return this;
    }

    public String getSchedule() {
        return schedule;
    }

    public void setSchedule(String schedule) {
        this.schedule = schedule;
    }

    public UpdateController withSchedule(String schedule) {
        this.schedule = schedule;
        return this;
    }

    public long getDaysToExpire() {
        return daysToExpire;
    }

    public void setDaysToExpire(long daysToExpire) {
        this.daysToExpire = daysToExpire;
    }

    public UpdateController withDaysToExpire(long daysToExpire) {
        this.daysToExpire = daysToExpire;
        return this;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this).append("image", image).append("schedule", schedule).append("daysToExpire", daysToExpire).toString();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(schedule).append(daysToExpire).append(image).toHashCode();
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof UpdateController) == false) {
            return false;
        }
        UpdateController rhs = ((UpdateController) other);
        return new EqualsBuilder().append(schedule, rhs.schedule).append(daysToExpire, rhs.daysToExpire).append(image, rhs.image).isEquals();
    }

}
