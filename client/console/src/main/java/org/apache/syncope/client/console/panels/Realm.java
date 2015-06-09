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
package org.apache.syncope.client.console.panels;

import org.apache.syncope.common.lib.to.RealmTO;
import org.apache.wicket.markup.html.panel.Panel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Realm extends Panel {

    private static final long serialVersionUID = -1100228004207271270L;

    protected static final Logger LOG = LoggerFactory.getLogger(Realm.class);

    private final RealmTO realmTO;

    public Realm(final String id, final RealmTO realmTO) {
        super(id);
        this.realmTO = realmTO;

        add(new RealmDetails("details", realmTO));
        add(new Any("users"));
        add(new Any("groups"));
        add(new Any("services"));
        add(new Any("serviceRoles"));
        add(new Any("contexts"));
        add(new Any("enactmentEngine"));
        add(new AccountPolicy("accountPolicy"));
        add(new PasswordPolicy("passwordPolicy"));
    }

}
