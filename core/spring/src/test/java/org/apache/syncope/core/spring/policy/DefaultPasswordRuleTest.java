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

package org.apache.syncope.core.spring.policy;

import org.apache.syncope.common.lib.policy.AbstractAccountRuleConf;
import org.apache.syncope.common.lib.policy.AbstractPasswordRuleConf;
import org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf;
import org.apache.syncope.common.lib.policy.PasswordRuleConf;
import org.apache.syncope.core.spring.security.TestPasswordRuleConf;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

class DefaultPasswordRuleTest {

    DefaultPasswordRule passwordRule = new DefaultPasswordRule();

    private static Stream<Object> ruleConfParameters() {
        List<Object> args = new ArrayList<>();

        //Null Test
        args.add(Arguments.of(null, true));

        //Other Tests
        args.add(Arguments.of(new DefaultPasswordRuleConf(), false));
        args.add(Arguments.of(getPasswordRuleConf(), false));


        //Jacoco
        //Invalid State (RepeatSame = 1 is invalid)
        DefaultPasswordRuleConf ruleConf = getDefaultPasswordRuleConf();
        ruleConf.setRepeatSame(1);
        args.add(Arguments.of(ruleConf, true));
        //Invalid Configuration
        PasswordRuleConf invalidRuleConf = new TestPasswordRuleConf();
        args.add(Arguments.of(invalidRuleConf, true));
        //Username as password enabled
        ruleConf = getPasswordRuleConf();
        ruleConf.setUsernameAllowed(true);
        args.add(Arguments.of(ruleConf, false));

        return args.stream();
    }

    private static Stream<Object> enforceParameters() {
        List<Object> args = new ArrayList<>();

        //Null Test
        args.add(Arguments.of(getFullRule(), null, null, false));
        //Void Test
        args.add(Arguments.of(getFullRule(), null, "", true));
        //Invalid Word Test
        args.add(Arguments.of(getFullRule(), null, "Ciaociao%01", true));
        //Valid Test
        args.add(Arguments.of(getFullRule(), null, "HolaHola%01", false));
        //Valid Test
        args.add(Arguments.of(getFullRule(), "username", "HolaHola%01", false));
        //Invalid Length Test
        args.add(Arguments.of(getFullRule(), null, "CiaCia", true));
        //Invalid Length Test
        args.add(Arguments.of(getFullRule(), null, "HolaHola01HolaHola%01", true));
        //Invalid -> Password == Username
        args.add(Arguments.of(getFullRule(), "HolaHola%01", "HolaHola%01", true));

        //Jacoco
        //Using RepeatSame rule
        DefaultPasswordRule rule = new DefaultPasswordRule();
        DefaultPasswordRuleConf ruleConf = getDefaultPasswordRuleConf();
        ruleConf.setRepeatSame(2);
        rule.setConf(ruleConf);
        args.add(Arguments.of(rule, "user", "HolaHola%01", false));



        return args.stream();
    }

    @ParameterizedTest
    @MethodSource("ruleConfParameters")
    void setConfTest(AbstractPasswordRuleConf ruleConf, boolean isExpectedAnException) {
        try {
            passwordRule.setConf(ruleConf);

            Assertions.assertEquals(passwordRule.getConf(), passwordRule.getConf());
        } catch (Exception e) {
            if(isExpectedAnException) return;
            throw e;
        }
        if(isExpectedAnException) Assertions.fail();
    }

    @ParameterizedTest
    @MethodSource("enforceParameters")
    void enforceTest(DefaultPasswordRule passwordRule, String username, String clearPassword, boolean isExpectedAnException) {
        try {
            passwordRule.enforce(username, clearPassword);
        } catch (Exception e) {
            if(isExpectedAnException) return;
            throw e;
        }
        if(isExpectedAnException) Assertions.fail();
    }

    private static DefaultPasswordRule getFullRule() {
        DefaultPasswordRule rule = new DefaultPasswordRule();
        DefaultPasswordRuleConf ruleConf = getDefaultPasswordRuleConf();

        rule.setConf(ruleConf);
        return rule;
    }

    private static DefaultPasswordRuleConf getDefaultPasswordRuleConf() {
        DefaultPasswordRuleConf ruleConf = new DefaultPasswordRuleConf();
        ruleConf.setLowercase(1);
        ruleConf.setUppercase(1);
        ruleConf.setMinLength(8);
        ruleConf.setMaxLength(16);
        ruleConf.setAlphabetical(1);
        ruleConf.setDigit(1);
        ruleConf.setUsernameAllowed(false);
        ruleConf.setSpecial(1);
        ruleConf.getSpecialChars().add('@');
        ruleConf.getSpecialChars().add('%');
        ruleConf.getWordsNotPermitted().add("Ciao");
        ruleConf.getWordsNotPermitted().add("Hello");
        return ruleConf;
    }

    private static DefaultPasswordRuleConf getPasswordRuleConf() {
        DefaultPasswordRuleConf ruleConf = new DefaultPasswordRuleConf();
        ruleConf.setMinLength(8);
        ruleConf.setMaxLength(50);
        ruleConf.setAlphabetical(1);
        ruleConf.setDigit(1);

        return ruleConf;
    }
}