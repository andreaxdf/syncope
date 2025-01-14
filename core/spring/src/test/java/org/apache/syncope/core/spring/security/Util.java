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

import org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf;
import org.apache.syncope.core.spring.policy.DefaultPasswordRule;
import org.junit.jupiter.api.Assertions;
import org.passay.PasswordData;
import org.passay.RepeatCharactersRule;
import org.passay.RuleResult;

import java.util.List;


public class Util {

    private static final int VERY_MIN_LENGTH = 0;

    private static final int DEFAULT_MAX_LENGTH = 64;

    private static final int DEFAULT_MIN_LENGTH = 8;


    public static DefaultPasswordRuleConf getWordsNotPermittedRule(String string) {
        DefaultPasswordRuleConf ruleConf = new DefaultPasswordRuleConf();

        for(Character character: string.toCharArray()) {
            ruleConf.getSpecialChars().add(character);
        }

        ruleConf.setMinLength(4);
        ruleConf.setMaxLength(4);
        ruleConf.setSpecial(4);
        ruleConf.setAlphabetical(0);
        ruleConf.setDigit(0);
        ruleConf.getWordsNotPermitted().add(string);

        return ruleConf;
    }

    public static DefaultPasswordRuleConf getDigitRule1(int numOfDigits) {
        DefaultPasswordRuleConf ruleConf = new DefaultPasswordRuleConf();

        ruleConf.setMaxLength(1500);
        ruleConf.setDigit(numOfDigits);
        ruleConf.setAlphabetical(1);

        return ruleConf;
    }

    public static boolean checkPresence(String string, List<Character> searched) {
        for(char c: string.toCharArray()) {
            if(searched.contains(c)) {
                return true;
            }
        }

        return false;
    }

    public static int howManySpecials(String string, List<Character> searched) {
        int count = 0;

        for(char c: string.toCharArray()) {
            if(searched.contains(c)) {
                count++;
            }
        }

        return count;
    }

    public static boolean isDigitRuleRespected(String password, int howMany) {
        return DefaultPasswordGeneratorTest.howMany(password, Character::isDigit) >= howMany;
    }

    public static boolean isAlphabeticalRuleRespected(String password, int howMany) {
        return DefaultPasswordGeneratorTest.howMany(password, Character::isAlphabetic) >= howMany;
    }

    public static boolean isSpecialCharsRuleRespected(String password, List<Character> specialCharList, int howMany) {
        return howManySpecials(password, specialCharList) >= howMany;
    }

    public static boolean isUppercaseRuleRespected(String password, int howMany) {
        return DefaultPasswordGeneratorTest.howMany(password, Character::isUpperCase) >= howMany;
    }

    public static boolean isLowercaseRuleRespected(String password, int howMany) {
        return DefaultPasswordGeneratorTest.howMany(password, Character::isLowerCase) >= howMany;
    }

    public static boolean isWordNotPermittedPolicyRespected(String password, List<String> illegalWordList) {

        for(String illegalWord: illegalWordList) {
            if(password.contains(illegalWord)) return false;
        }

        return true;
    }

    public static boolean isLengthRespected(String password, int minLength, int maxLength) {
        return password.length() >= minLength && password.length() <= maxLength;
    }

    private static boolean isIllegalCharsRuleRespected(String password, List<Character> illegalCharList) {
        return !checkPresence(password, illegalCharList);
    }

    public static void isAValidResult(String password, DefaultPasswordRuleConf ruleConf) {

        DefaultPasswordRule rule = new DefaultPasswordRule();
        rule.setConf(ruleConf);

        rule.enforce((String) null, password);

        /*Assertions.assertTrue(isSpecialCharsRuleRespected(password, ruleConf.getSpecialChars(), ruleConf.getSpecial()));

        if(!ruleConf.getIllegalChars().isEmpty()) {
            Assertions.assertTrue(isIllegalCharsRuleRespected(password, ruleConf.getIllegalChars()));
        }

        Assertions.assertTrue(isAlphabeticalRuleRespected(password, ruleConf.getAlphabetical()));


        Assertions.assertTrue(isDigitRuleRespected(password, ruleConf.getDigit()));

        if(!ruleConf.getWordsNotPermitted().isEmpty()) {
            Assertions.assertTrue(isWordNotPermittedPolicyRespected(password, ruleConf.getWordsNotPermitted()));
        }

        Assertions.assertTrue(isLowercaseRuleRespected(password, ruleConf.getLowercase()));

        Assertions.assertTrue(isUppercaseRuleRespected(password, ruleConf.getUppercase()));

        if(ruleConf.getRepeatSame() > 0) {
            Assertions.assertTrue(isRepeatSameRuleRespected(password, ruleConf.getRepeatSame()));
        }
        int minLength = ruleConf.getMinLength() > 0 ? ruleConf.getMinLength() : DEFAULT_MIN_LENGTH;
        int maxLength = ruleConf.getMaxLength() > 0 ? ruleConf.getMaxLength() : DEFAULT_MAX_LENGTH;
        if(maxLength < DEFAULT_MIN_LENGTH) minLength = maxLength;

        Assertions.assertTrue(isLengthRespected(password, minLength, maxLength));*/

    }

    private static boolean isRepeatSameRuleRespected(String password, int repeatSame) {
        RepeatCharactersRule rule = new RepeatCharactersRule(repeatSame);
        PasswordData passwordData = new PasswordData(password);
        RuleResult result = rule.validate(passwordData);

        return result.isValid();
    }
}
