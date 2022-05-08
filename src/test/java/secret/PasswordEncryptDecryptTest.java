package secret;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Random;

class PasswordEncryptDecryptTest {

    @Test
    void whenEndcryptAndDecryptAMessage_shouldReturnSameMessage(){

        String originalMessage = "This is a secret message";

        var msg = PasswordEncryptDecrypt.encrypt(originalMessage);
        var decry = PasswordEncryptDecrypt.decrypt(msg);

        Assertions.assertEquals(originalMessage, decry);
    }

    @ParameterizedTest
    @ValueSource(ints = {32, 24, 16})
    void whenGetKey_withStringWith32Chars_shouldReturn32CharString(int number){
        var generatedString = RandomStringUtils.random(number, true, true);

        Assertions.assertEquals(number, PasswordEncryptDecrypt.getKey(generatedString).length());
    }

    @ParameterizedTest
    @CsvSource({
            "33, 1000, 32",
            "25, 31, 24",
            "17, 23, 16",
            "0, 15, 16",
    })
    void whenGetKey_withStringBetween25And31Chars_shouldReturn24CharString(int lowerNumber, int higherNumber, int expectedNumber){
        Random random = new Random();
        var number = random.ints(lowerNumber, higherNumber)
                           .findFirst()
                           .getAsInt();
        var generatedString = RandomStringUtils.random(number, true, true);

        Assertions.assertEquals(expectedNumber, PasswordEncryptDecrypt.getKey(generatedString).length());
    }

}