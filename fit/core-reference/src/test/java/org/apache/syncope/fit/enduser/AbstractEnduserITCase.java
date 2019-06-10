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
package org.apache.syncope.fit.enduser;

import com.giffing.wicket.spring.boot.context.extensions.WicketApplicationInitConfiguration;
import com.giffing.wicket.spring.boot.context.extensions.boot.actuator.WicketEndpointRepository;
import com.giffing.wicket.spring.boot.starter.app.classscanner.candidates.WicketClassCandidatesHolder;
import com.giffing.wicket.spring.boot.starter.configuration.extensions.core.settings.general.GeneralSettingsProperties;
import com.giffing.wicket.spring.boot.starter.configuration.extensions.external.spring.boot.actuator.WicketEndpointRepositoryDefault;
import java.util.Collections;
import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.apache.syncope.client.enduser.SyncopeWebApplication;
import org.apache.syncope.client.enduser.commons.PreviewUtils;
import org.apache.syncope.client.enduser.init.ClassPathScanImplementationLookup;
import org.apache.syncope.client.enduser.init.MIMETypesLoader;
import org.apache.syncope.client.enduser.pages.Login;
import org.apache.syncope.client.lib.SyncopeClient;
import org.apache.syncope.client.lib.SyncopeClientFactoryBean;
import org.apache.syncope.common.rest.api.service.SyncopeService;
import org.apache.wicket.util.tester.WicketTester;
import org.junit.jupiter.api.BeforeAll;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.apache.syncope.common.keymaster.client.self.SelfKeymasterClientContext;
import org.apache.syncope.common.rest.api.service.UserService;
import org.apache.syncope.fit.ui.AbstractUITCase;
import org.apache.syncope.fit.ui.UtilityUIT;
import org.apache.wicket.util.tester.FormTester;

public abstract class AbstractEnduserITCase extends AbstractUITCase {

    protected static final String ENV_KEY_CONTENT_TYPE = "jaxrsContentType";

    protected static SyncopeClientFactoryBean clientFactory;

    protected static SyncopeClient adminClient;

    protected static UserService userService;

    protected static UtilityUIT UTILITY_UI;

    @ImportAutoConfiguration(classes = { SelfKeymasterClientContext.class })
    @Configuration
    public static class SyncopeEnduserWebApplicationTestConfig {

        @Bean
        public GeneralSettingsProperties generalSettingsProperties() {
            return new GeneralSettingsProperties();
        }

        @Bean
        public List<WicketApplicationInitConfiguration> configurations() {
            return Collections.emptyList();
        }

        @Bean
        public WicketClassCandidatesHolder wicketClassCandidatesHolder() {
            return new WicketClassCandidatesHolder();
        }

        @Bean
        public WicketEndpointRepository wicketEndpointRepository() {
            return new WicketEndpointRepositoryDefault();
        }

        @Bean
        public ClassPathScanImplementationLookup classPathScanImplementationLookup() {
            ClassPathScanImplementationLookup lookup = new ClassPathScanImplementationLookup();
            lookup.load();
            return lookup;
        }

        @Bean
        public MIMETypesLoader mimeTypesLoader() {
            MIMETypesLoader mimeTypesLoader = new MIMETypesLoader();
            mimeTypesLoader.load();
            return mimeTypesLoader;
        }

        @Bean
        public PreviewUtils previewUtils() {
            return new PreviewUtils();
        }
    }

    @BeforeAll
    public static void setUp() {
        synchronized (LOG) {
            if (UTILITY_UI == null) {
                AnnotationConfigApplicationContext ctx = new AnnotationConfigApplicationContext();
                ctx.register(SyncopeEnduserWebApplicationTestConfig.class);
                ctx.register(SyncopeWebApplication.class);
                ctx.refresh();

                UTILITY_UI = new UtilityUIT(new WicketTester(ctx.getBean(SyncopeWebApplication.class)));
            }

            if (SYNCOPE_SERVICE == null) {
                SYNCOPE_SERVICE = new SyncopeClientFactoryBean().
                        setAddress(ADDRESS).create(ADMIN_UNAME, ADMIN_PWD).
                        getService(SyncopeService.class);
            }
        }
    }

    @BeforeAll
    public static void restSetup() {
        clientFactory = new SyncopeClientFactoryBean().setAddress(ADDRESS);

        String envContentType = System.getProperty(ENV_KEY_CONTENT_TYPE);
        if (StringUtils.isNotBlank(envContentType)) {
            clientFactory.setContentType(envContentType);
        }
        LOG.info("Performing IT with content type {}", clientFactory.getContentType().getMediaType());

        adminClient = clientFactory.create(ADMIN_UNAME, ADMIN_PWD);

        userService = adminClient.getService(UserService.class);
    }

    protected void doLogin(final String user, final String passwd) {
        UTILITY_UI.getTester().startPage(Login.class);
        UTILITY_UI.getTester().assertRenderedPage(Login.class);

        FormTester formTester = UTILITY_UI.getTester().newFormTester("login");
        formTester.setValue("username", user);
        formTester.setValue("password", passwd);
        formTester.submit("submit");
    }
}
