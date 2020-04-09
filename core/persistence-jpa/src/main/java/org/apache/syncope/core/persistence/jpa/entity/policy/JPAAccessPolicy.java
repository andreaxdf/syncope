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
package org.apache.syncope.core.persistence.jpa.entity.policy;

import org.apache.syncope.common.lib.types.AMImplementationType;
import org.apache.syncope.core.persistence.api.entity.Implementation;
import org.apache.syncope.core.persistence.api.entity.policy.AccessPolicy;
import org.apache.syncope.core.persistence.jpa.entity.JPAImplementation;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Table;
import javax.persistence.ManyToOne;

@Entity
@Table(name = JPAAccessPolicy.TABLE)
public class JPAAccessPolicy extends AbstractPolicy implements AccessPolicy {

    public static final String TABLE = "AccessPolicy";

    private static final long serialVersionUID = -4190607009908888884L;

    @Column(unique = true, nullable = false)
    private String name;

    @ManyToOne(fetch = FetchType.EAGER)
    private JPAImplementation configuration;

    @Override
    public String getName() {
        return name;
    }

    @Override
    public void setName(final String name) {
        this.name = name;
    }

    @Override
    public Implementation getConfiguration() {
        return configuration;
    }

    @Override
    public void setConfiguration(final Implementation configuration) {
        checkType(configuration, JPAImplementation.class);
        checkImplementationType(configuration, AMImplementationType.ACCESS_POLICY_CONFIGURATIONS);
        this.configuration = (JPAImplementation) configuration;
    }

}
