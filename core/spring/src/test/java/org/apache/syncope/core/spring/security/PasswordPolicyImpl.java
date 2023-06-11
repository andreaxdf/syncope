/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.syncope.core.spring.security;

import org.apache.syncope.core.persistence.api.entity.Implementation;
import org.apache.syncope.core.persistence.api.entity.policy.PasswordPolicy;

import java.util.ArrayList;
import java.util.List;

public class PasswordPolicyImpl implements PasswordPolicy {


    public static final String TABLE = "PasswordPolicy";

    private Boolean allowNullPassword = false;

    private int historyLength;

    private final List<Implementation> rules = new ArrayList<>();

    @Override
    public boolean isAllowNullPassword() {
        return allowNullPassword;
    }

    @Override
    public void setAllowNullPassword(final boolean allowNullPassword) {
        this.allowNullPassword = allowNullPassword;
    }

    @Override
    public int getHistoryLength() {
        return historyLength;
    }

    @Override
    public void setHistoryLength(final int historyLength) {
        this.historyLength = historyLength;
    }

    @Override
    public boolean add(final Implementation rule) {
        return rules.contains(rule) || rules.add(rule);
    }

    @Override
    public List<? extends Implementation> getRules() {
        return rules;
    }

    @Override
    public String getKey() {
        return null;
    }

    @Override
    public String getName() {
        return null;
    }

    @Override
    public void setName(String name) {

    }
}
