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
import org.junit.jupiter.api.Assertions;

import java.util.List;


public class Util {

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

    public static boolean isDigitRuleRespected(String password, int howMany) {
        return DefaultPasswordGeneratorTest.howMany(password, Character::isDigit) >= howMany;
    }

    public static boolean isAlphabeticalRuleRespected(String password, int howMany) {
        return DefaultPasswordGeneratorTest.howMany(password, Character::isAlphabetic) >= howMany;
    }

    public static boolean isSpecialCharsRuleRespected(String password, List<Character> specialCharList) {
        return checkPresence(password, specialCharList);
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

        if(ruleConf.getSpecial() > 0) {
            Assertions.assertTrue(isSpecialCharsRuleRespected(password, ruleConf.getSpecialChars()));
        }
        if(!ruleConf.getIllegalChars().isEmpty()) {
            Assertions.assertTrue(isIllegalCharsRuleRespected(password, ruleConf.getIllegalChars()));
        }
        if(ruleConf.getAlphabetical() > 0) {
            Assertions.assertTrue(isAlphabeticalRuleRespected(password, ruleConf.getAlphabetical()));
        }
        if(ruleConf.getDigit() > 0) {
            Assertions.assertTrue(isDigitRuleRespected(password, ruleConf.getDigit()));
        }
        if(!ruleConf.getWordsNotPermitted().isEmpty()) {
            Assertions.assertTrue(isWordNotPermittedPolicyRespected(password, ruleConf.getWordsNotPermitted()));
        }
        if(ruleConf.getLowercase() > 0) {
            Assertions.assertTrue(isLowercaseRuleRespected(password, ruleConf.getLowercase()));
        }
        if(ruleConf.getUppercase() > 0) {
            Assertions.assertTrue(isUppercaseRuleRespected(password, ruleConf.getUppercase()));
        }
        int minLength = ruleConf.getMinLength() > 0 ? ruleConf.getMinLength() : 8;
        int maxLength = ruleConf.getMaxLength() > 0 ? ruleConf.getMaxLength() : 64;

        Assertions.assertTrue(isLengthRespected(password, minLength, maxLength));

    }
}
