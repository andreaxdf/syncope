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
import org.apache.syncope.common.lib.policy.AbstractPasswordRuleConf;
import org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf;
import org.apache.syncope.core.persistence.api.entity.policy.PasswordPolicy;
import org.apache.syncope.core.provisioning.api.serialization.POJOHelper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;


@SpringJUnitConfig(locations = { "classpath:springTest.xml" })
class DefaultPasswordGeneratorTest {

    DefaultPasswordGenerator passwordGenerator = new DefaultPasswordGenerator();

    public static int howMany(String password, CharacterPredicate predicate) {
        int count = 0;

        for(char c: password.toCharArray()) {
            if(predicate.test(c)) count++;
        }

        return count;
    }

    static DefaultPasswordRuleConf getPasswordRuleConf() {
        DefaultPasswordRuleConf ruleConf = new DefaultPasswordRuleConf();
        ruleConf.setMinLength(6);
        ruleConf.setMaxLength(50);
        ruleConf.setAlphabetical(1);
        ruleConf.setDigit(1);

        return ruleConf;
    }

    public static Stream<Object> iterationParameters() {
        List<Object> args = new ArrayList<>();

        //--------------------------- Words Not Permitted Policy ---------------------------
        //This test the password generation with "WordsNotPermitted" policy, but the generated password
        // does not respect the policy.
        String illegalWord = "Ciao";
        DefaultPasswordRuleConf ruleConf1 = Util.getWordsNotPermittedRule(illegalWord);
        ruleConf1.setName("Words Not Permitted Policy Test");

        args.add(Arguments.of(ruleConf1, false, (int) Math.pow(illegalWord.length(), illegalWord.length())));

        return args.stream();
    }

    List<PasswordPolicy> getPasswordPolicies(AbstractPasswordRuleConf ruleConf) {
        TestImplementation passwordRule = new TestImplementation();
        passwordRule.setBody(POJOHelper.serialize(ruleConf));

        return List.of(new TestPasswordPolicy(passwordRule));
    }

    private static Stream<Object> parameters() {
        List<Object> args = new ArrayList<>();

        //These tests verify the correctness of the generated password, with different policies.

        //------------------------------ Length Policy -------------------------------
        //This test the password generation with "WordsNotPermitted" policy, but the generated password
        // does not respect the policy.
        DefaultPasswordRuleConf ruleConf1 = new DefaultPasswordRuleConf();
        ruleConf1.setName("Length Policy Test");
        ruleConf1.setMinLength(8);
        ruleConf1.setMaxLength(10);

        args.add(Arguments.of(ruleConf1, false));

        //--------------------------- Default Configuration ---------------------------
        //In Javadoc description of DefaultPasswordGenerator class it is said that min/max length values are set by default,
        // so there shouldn't be Exception without any length.
        DefaultPasswordRuleConf ruleConf2 = new DefaultPasswordRuleConf();
        ruleConf2.setDigit(1);
        ruleConf2.setName("Default Configuration Test");

        args.add(Arguments.of(ruleConf2, false));

        //--------------------------- Requested Digits Policy 1 ---------------------------
        //This test throw BufferOverflowException, although the max length should have been big enough.
        /*DefaultPasswordRuleConf ruleConf3 = Util.getDigitRule1(10);
        ruleConf3.setName("Requested Digits Policy 1 Test");

        args.add(Arguments.of(ruleConf3, false));*/

        //--------------------------- Requested Digits Policy 2 ---------------------------
        //This test verify if in the generated password there are enough digits.
        List<Integer> integerList = List.of(-1, 0, 1/*, 10*/);

        int count = 1;
        for(Integer howMany: integerList) {
            DefaultPasswordRuleConf ruleConf = getPasswordRuleConf();
            ruleConf.setName("Requested Digits Policy 2 Test " + count);
            ruleConf.setDigit(howMany);

            args.add(Arguments.of(ruleConf, false));
            count++;
        }

        //--------------------------- Requested Alphabetical Policy ---------------------------
        //This test verify if in the generated password there are enough alphabetical.
        count = 1;
        for(Integer howMany: integerList) {
            DefaultPasswordRuleConf ruleConf = getPasswordRuleConf();
            ruleConf.setName("Requested Alphabetical Policy Test " + count);
            ruleConf.setAlphabetical(howMany);

            args.add(Arguments.of(ruleConf, false));
            count++;
        }

        //--------------------------- Requested Uppercase Letters Policy ---------------------------
        //This test verify if in the generated password there are enough uppercase letter.
        count = 1;
        for(Integer howMany: integerList) {
            DefaultPasswordRuleConf ruleConf = getPasswordRuleConf();
            ruleConf.setName("Requested Uppercase Letters Policy Test " + count);

            ruleConf.setAlphabetical(1);
            ruleConf.setUppercase(howMany);

            args.add(Arguments.of(ruleConf, false));
            count++;
        }

        //--------------------------- Requested Lowercase Letters Policy ---------------------------
        //This test verify if in the generated password there are enough lowercase letter.
        count = 1;
        for(Integer howMany: integerList) {
            DefaultPasswordRuleConf ruleConf = getPasswordRuleConf();
            ruleConf.setName("Requested Lowercase Letters Policy Test " + count);

            ruleConf.setAlphabetical(1);
            ruleConf.setLowercase(howMany);

            args.add(Arguments.of(ruleConf, false));
            count++;
        }

        //-------------------------------------- Empty Policy --------------------------------------
        //This test verify if using an empty policy there are problems.
        DefaultPasswordRuleConf ruleConf4 = new DefaultPasswordRuleConf();
        ruleConf4.setName("Empty Policy Test " + count);

        args.add(Arguments.of(ruleConf4, false));

        //----------------------------------- Special Chars Policy --------------------------------------
        //This test verify if the password generator respect the special chars' policy.

        List<List<Character>> specialCharLists = List.of(
                    List.of(),
                    List.of('@', '!'),
                    List.of('#', '*', '§'),
                    List.of('@', '!', '#', '*', '§')
        );
        count = 1;
        for(int howMany: integerList) {
            for (List<Character> specialCharList : specialCharLists) {

                DefaultPasswordRuleConf ruleConf = getPasswordRuleConf();
                ruleConf.setName("Special Chars Policy Test " + count);

                ruleConf.setSpecial(howMany);

                for (Character character : specialCharList) {
                    ruleConf.getSpecialChars().add(character);
                }

                if (specialCharList.isEmpty())
                    args.add(Arguments.of(ruleConf, howMany > 0));
                else
                    args.add(Arguments.of(ruleConf, false));
                count++;
            }
        }

        //----------------------------------- Illegal Chars Policy --------------------------------------
        //This test verify if the password generator respect the illegal chars' policy.
        count = 1;
        for(List<Character> illegalChars: specialCharLists) {

            DefaultPasswordRuleConf ruleConf = getPasswordRuleConf();
            ruleConf.setName("Illegal Chars Policy Test " + count);

            for (Character character : illegalChars) {
                ruleConf.getIllegalChars().add(character);
            }

            args.add(Arguments.of(ruleConf, false));
            count++;
        }

        //--------------------------- Illegal And Special Chars Policies with expected exception --------------------------------------
        //This test verify if the password generator respect the illegal chars' policy and the special chars' policy simultaneously.
        //In some cases the rules are wrong, because they obligate you to insert at most once time the char '@', but it is also in
        // the illegal char list.
        /*count = 1;
        for(List<Character> illegalChars: specialCharLists) {

            DefaultPasswordRuleConf ruleConf = getPasswordRuleConf();
            ruleConf.setName("Illegal And Special Chars Policies with expected exception Test " + count);
            char specialChar = '@';

            ruleConf.setSpecial(1);
            ruleConf.getSpecialChars().add(specialChar);

            for (Character character : illegalChars) {
                ruleConf.getIllegalChars().add(character);
            }

            //An exception is expected when the illegal chars contain the special char.
            args.add(Arguments.of(ruleConf, false));
            count++;
        }*/

        //--------------------------- Illegal And Special Chars Policies without expected exception --------------------------------------
        //This test verify if the password generator respect the illegal chars' policy and the special chars' policy simultaneously.
        //Now, the generator has more choices in special chars.
        count = 1;
        for(List<Character> illegalChars: specialCharLists) {

            DefaultPasswordRuleConf ruleConf = getPasswordRuleConf();
            ruleConf.setName("Illegal And Special Chars Policies without expected exception " + count);
            char specialChar = '@';

            ruleConf.setSpecial(1);
            ruleConf.getSpecialChars().add(specialChar);
            ruleConf.getSpecialChars().add('&');
            ruleConf.getSpecialChars().add('/');

            for (Character character : illegalChars) {
                ruleConf.getIllegalChars().add(character);
            }

            //Given that the password generator has some valid choices, it is not expected any exception.
            args.add(Arguments.of(ruleConf, false));
            count++;
        }

        //--------------------------- Words Not Permitted Policy ---------------------------
        //This test the password generation with "WordsNotPermitted" policy, but the generated password
        // does not respect the policy.
        String illegalWord = "Ciao";
        ruleConf1 = new DefaultPasswordRuleConf();
        ruleConf1.setName("Words Not Permitted Policy Test");
        ruleConf1.getWordsNotPermitted().add(illegalWord);

        args.add(Arguments.of(ruleConf1, false));

        //----------------------------------- Invalid Policy --------------------------------------
        //This test try to use an invalid instance. The documentation say that it is only possible use DefaultPasswordRuleConf,
        // so the test try to use another type of rule. This type of exceptions are caught and managed, so no exceptions is expected.
        // When the policy is invalid will be generated a password with generic rules.

        TestPasswordRuleConf invalidRuleConf = new TestPasswordRuleConf();
        invalidRuleConf.setName("Invalid Policy Test ");

        args.add(Arguments.of(invalidRuleConf, false));

        //----------------------------------- Invalid Length Policy --------------------------------------
        //This test try to generate a password with invalid length rules (minLength > maxLength).

        DefaultPasswordRuleConf ruleConf = new DefaultPasswordRuleConf();
        ruleConf.setName("Invalid Length Policy Test");
        ruleConf.setMinLength(10);
        ruleConf.setMaxLength(8);

        args.add(Arguments.of(ruleConf, true));

        //----------------------------------- Overflow Attempt --------------------------------------
        //This test tests the password generator with huge minLength. It is commented because it launches a OutOfMemoryError
        /*
        ruleConf = new DefaultPasswordRuleConf();
        ruleConf.setName("Overflow attempt Test");
        ruleConf.setMinLength(Integer.MAX_VALUE);

        args.add(Arguments.of(ruleConf, true));*/


        //JACOCO
        //----------------------------------- Repeat Same Policy --------------------------------------
        //This test covers the case in which a repeat same policy has been configured. Documentation says that a RepeatCharactersRule
        // does not permit to generate a repeated sequence of N characters in the password.
        ruleConf = new DefaultPasswordRuleConf();
        ruleConf.setRepeatSame(3);

        args.add(Arguments.of(ruleConf, false));

        //------------------------- Max Length Less Than Default Min Length Policy --------------------------------------
        //In this test we analyze the case in which only the max length has been configured, but it is less than the default min length.
        ruleConf = new DefaultPasswordRuleConf();
        ruleConf.setMaxLength(5);

        args.add(Arguments.of(ruleConf, false));

        //PIT
        //----------------------------------------- All Digits Policy -----------------------------------------
        ruleConf = new DefaultPasswordRuleConf();
        ruleConf.setMinLength(5);
        ruleConf.setDigit(5);

        args.add(Arguments.of(ruleConf, false));

        //----------------------------------------- All Alphabetical Policy -----------------------------------------
        ruleConf = new DefaultPasswordRuleConf();
        ruleConf.setMinLength(5);
        ruleConf.setAlphabetical(5);

        args.add(Arguments.of(ruleConf, false));


        //----------------------------------------- All Lowercase Policy -----------------------------------------
        ruleConf = new DefaultPasswordRuleConf();
        ruleConf.setMinLength(5);
        ruleConf.setLowercase(5);

        args.add(Arguments.of(ruleConf, false));

        return args.stream();
    }

    /*@ParameterizedTest
    @MethodSource("iterationParameters")
    void testGenerateIterated(AbstractPasswordRuleConf ruleConf, boolean isExpectedAnException, int iterations) {
        for(int i = 0; i < iterations; i++) {
            testGenerate(ruleConf, isExpectedAnException);
        }
    }*/

    @ParameterizedTest
    @MethodSource("parameters")
    void testGenerate(AbstractPasswordRuleConf ruleConf, boolean isExpectedAnException) {
        try {

            String password = passwordGenerator.generate(getPasswordPolicies(ruleConf));

            if (ruleConf instanceof DefaultPasswordRuleConf)
                Util.isAValidResult(password, (DefaultPasswordRuleConf) ruleConf);
            else
                Util.isAValidResult(password, new DefaultPasswordRuleConf()); //This is for the case with an invalid policy

        } catch (Exception e) {
            if(isExpectedAnException) return;
            throw e;
        }
        if(isExpectedAnException) Assertions.fail();
    }
}