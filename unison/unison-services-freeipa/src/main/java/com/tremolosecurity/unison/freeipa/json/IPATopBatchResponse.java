/*******************************************************************************
 * Copyright 2018 Tremolo Security, Inc.
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
//    Copyright 2018 Tremolo Security, Inc.
// 
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
// 
//        http://www.apache.org/licenses/LICENSE-2.0
// 
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

package com.tremolosecurity.unison.freeipa.json;

import java.util.List;

/**
 * IPABatchResponse
 */
public class IPATopBatchResponse {

    int count;
    Object messages;
    List<IPATopResult> results;
    int id;
    IPAError error;

    public IPATopBatchResponse() {

    }

    /**
     * @return the count
     */
    public int getCount() {
        return count;
    }

    /**
     * @return the messages
     */
    public Object getMessages() {
        return messages;
    }

    /**
     * @return the results
     */
    public List<IPATopResult> getResults() {
        return results;
    }

    /**
     * @param count the count to set
     */
    public void setCount(int count) {
        this.count = count;
    }

    /**
     * @param messages the messages to set
     */
    public void setMessages(Object messages) {
        this.messages = messages;
    }

    /**
     * @param results the results to set
     */
    public void setResults(List<IPATopResult> results) {
        this.results = results;
    }

    /**
     * @param error the error to set
     */
    public void setError(IPAError error) {
        this.error = error;
    }

    /**
     * @param id the id to set
     */
    public void setId(int id) {
        this.id = id;
    }

    /**
     * @return the error
     */
    public IPAError getError() {
        return error;
    }
    /**
     * @return the id
     */
    public int getId() {
        return id;
    }

}
