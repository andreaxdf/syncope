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

import org.apache.commons.text.CharacterPredicate;
import org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf;
import org.apache.syncope.core.persistence.api.entity.policy.PasswordPolicy;
import org.apache.syncope.core.provisioning.api.serialization.POJOHelper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

@SpringJUnitConfig(locations = { "classpath:springTest.xml" })
class DefaultPasswordGeneratorTest {

    DefaultPasswordGenerator passwordGenerator = new DefaultPasswordGenerator();
    final int NUM_ITERATIONS = 1000;

    int howMany(String password, CharacterPredicate predicate) {
        int count = 0;

        for(char c: password.toCharArray()) {
            if(predicate.test(c)) count++;
        }

        return count;
    }

    DefaultPasswordRuleConf getPasswordRuleConf() {
        DefaultPasswordRuleConf ruleConf = new DefaultPasswordRuleConf();
        ruleConf.setMinLength(8);
        ruleConf.setMaxLength(50);
        ruleConf.setAlphabetical(1);
        ruleConf.setDigit(1);

        return ruleConf;
    }

    List<PasswordPolicy> getPasswordPolicies(DefaultPasswordRuleConf ruleConf) {
        TestImplementation passwordRule = new TestImplementation();
        passwordRule.setBody(POJOHelper.serialize(ruleConf));

        return List.of(new TestPasswordPolicy(passwordRule));
    }

    private static Stream<Arguments> parameters() {
        return Stream.of(
                Arguments.of(-1),
                Arguments.of(0),
                Arguments.of(1),
                Arguments.of(6)
        );
    }

    public static Stream<Arguments> specialCharParameters() {
        return Stream.of(
                Arguments.of(List.of()),
                Arguments.of(List.of('@', '!')),
                Arguments.of(List.of('#', '*', '§')),
                Arguments.of(List.of('@', '!', '#', '*', '§'))
        );
    }

    boolean checkPresence(String string, List<Character> searched) {
        for(char c: string.toCharArray()) {
            if(searched.contains(c)) {
                return true;
            }
        }

        return false;
    }

    @ParameterizedTest
    @MethodSource("specialCharParameters")
    void testIllegalChar(List<Character> illegalCharList) {

        DefaultPasswordRuleConf ruleConf = getPasswordRuleConf();

        for(Character character: illegalCharList) {
            ruleConf.getIllegalChars().add(character);
        }

        try {
            for (int i = 0; i < NUM_ITERATIONS; i++) {
                String password = passwordGenerator.generate(getPasswordPolicies(ruleConf));

                assertFalse(checkPresence(password, illegalCharList));
            }
        } catch (Exception e) {
            if(illegalCharList.isEmpty()) return;
            Assertions.fail();
        }
    }

    //In this case, the password generator does not respect the illegal characters' policy.
    @ParameterizedTest
//    @Disabled
    @MethodSource("specialCharParameters")
    void testIllegalAndSpecialChar(List<Character> illegalCharList) {

        DefaultPasswordRuleConf ruleConf = getPasswordRuleConf();

        ruleConf.setSpecial(1);
        ruleConf.getSpecialChars().add('@');
        ruleConf.getSpecialChars().add('&');

        for(Character character: illegalCharList) {
            ruleConf.getIllegalChars().add(character);
        }

        try {
            for (int i = 0; i < NUM_ITERATIONS; i++) {
                String password = passwordGenerator.generate(getPasswordPolicies(ruleConf));

                assertFalse(checkPresence(password, illegalCharList));
            }
        } catch (Exception e) {
            if(illegalCharList.isEmpty()) return;
            Assertions.fail();
        }
    }

    //This method tests the password generation with "WordsNotPermitted" policy, but the generated password
    // does not respect the policy.
    @Test
//    @Disabled
    void testWordsNotPermitted() {

        final String CIAO = "Ciao";
        DefaultPasswordRuleConf ruleConf = new DefaultPasswordRuleConf();

        for(Character character: CIAO.toCharArray()) {
            ruleConf.getSpecialChars().add(character);
        }

        ruleConf.setMinLength(4);
        ruleConf.setMaxLength(4);
        ruleConf.setSpecial(4);
        ruleConf.setAlphabetical(0);
        ruleConf.setDigit(0);
        ruleConf.getWordsNotPermitted().add(CIAO);

        for (int i = 0; i < NUM_ITERATIONS; i++) {
            String password = passwordGenerator.generate(getPasswordPolicies(ruleConf));

            assertFalse(password.contains(CIAO));
        }

    }

    @ParameterizedTest
    @MethodSource("specialCharParameters")
    void testSpecial(List<Character> specialCharList) {

        DefaultPasswordRuleConf ruleConf = getPasswordRuleConf();

        ruleConf.setSpecial(1);

        for(Character character: specialCharList) {
            ruleConf.getSpecialChars().add(character);
        }

        try {
            for (int i = 0; i < NUM_ITERATIONS; i++) {
                String password = passwordGenerator.generate(getPasswordPolicies(ruleConf));

                assertTrue(checkPresence(password, specialCharList));
            }
        } catch (Exception e) {
            if(specialCharList.isEmpty()) return;
            Assertions.fail();
        }
    }

    //In Javadoc description of DefaultPasswordGenerator class it is said that min/max length values are set by default,
    // so there shouldn't be Exception with any length.
    @Test
    void testDefault() {
        DefaultPasswordRuleConf ruleConf = new DefaultPasswordRuleConf();

        ruleConf.setDigit(1);

        for (int i = 0; i < NUM_ITERATIONS; i++) {
            String password = passwordGenerator.generate(getPasswordPolicies(ruleConf));

            assertTrue(password.chars().anyMatch(Character::isDigit));
        }
    }

    //BufferOverflowException
    @Test
//    @Disabled
    void testDigit2() {
        DefaultPasswordRuleConf ruleConf = new DefaultPasswordRuleConf();

        ruleConf.setMaxLength(1500);
        ruleConf.setDigit(10);
        ruleConf.setAlphabetical(1);


        for (int i = 0; i < NUM_ITERATIONS; i++) {
            String password = passwordGenerator.generate(getPasswordPolicies(ruleConf));

            assertTrue(howMany(password, Character::isDigit) >= 1);
        }
    }

    @ParameterizedTest
    @MethodSource("parameters")
    void testDigit(int howMany) {
        DefaultPasswordRuleConf ruleConf = getPasswordRuleConf();

        ruleConf.setDigit(howMany);

        for (int i = 0; i < NUM_ITERATIONS; i++) {
            String password = passwordGenerator.generate(getPasswordPolicies(ruleConf));

            assertTrue(howMany(password, Character::isDigit) >= howMany);
        }
    }

    @ParameterizedTest
    @MethodSource("parameters")
    void testChar(int howMany) {
        DefaultPasswordRuleConf ruleConf = getPasswordRuleConf();

        ruleConf.setAlphabetical(howMany);

        for (int i = 0; i < NUM_ITERATIONS; i++) {
            String password = passwordGenerator.generate(getPasswordPolicies(ruleConf));

            assertTrue(howMany(password, Character::isAlphabetic) >= howMany);
        }
    }

    @ParameterizedTest
    @MethodSource("parameters")
    void testUpperCase(int howMany) {
        DefaultPasswordRuleConf ruleConf = getPasswordRuleConf();

        ruleConf.setAlphabetical(1);
        ruleConf.setUppercase(howMany);

        for (int i = 0; i < NUM_ITERATIONS; i++) {
            String password = passwordGenerator.generate(getPasswordPolicies(ruleConf));

            assertTrue(howMany(password, Character::isUpperCase) >= howMany);
        }
    }

    @ParameterizedTest
    @MethodSource("parameters")
    void testLowerCase(int howMany) {
        DefaultPasswordRuleConf ruleConf = getPasswordRuleConf();

        ruleConf.setAlphabetical(1);
        ruleConf.setLowercase(howMany);

        for (int i = 0; i < NUM_ITERATIONS; i++) {
            String password = passwordGenerator.generate(getPasswordPolicies(ruleConf));

            assertTrue(howMany(password, Character::isLowerCase) >= howMany);
        }
    }

    @Test
    void testOverflow() {
        try {
            DefaultPasswordRuleConf ruleConf = getPasswordRuleConf();

            ruleConf.setMinLength(Integer.MAX_VALUE);

            passwordGenerator.generate(getPasswordPolicies(ruleConf));
        } catch (OutOfMemoryError e) {
            return;
        }
        Assertions.fail();
    }

    //I think this is a bug, because the password generated does not respect all the configured rules (respect only the min length).
    @Test
//    @Disabled
    void testMinLengthBiggerThanMax() {
        try {
            DefaultPasswordRuleConf ruleConf = getPasswordRuleConf();

            ruleConf.setMinLength(10);
            ruleConf.setMaxLength(8);

            passwordGenerator.generate(getPasswordPolicies(ruleConf));
        } catch (Exception e) {
            return;
        }
        Assertions.fail();
    }

    @Test
    void testEmptyPolicy() {
        DefaultPasswordRuleConf ruleConf = new DefaultPasswordRuleConf();

        for (int i = 0; i < NUM_ITERATIONS; i++) {
            String password = passwordGenerator.generate(getPasswordPolicies(ruleConf));

            assertNotNull(password);
        }
    }

    @Test
    void testInvalideInstance() {

    }
}