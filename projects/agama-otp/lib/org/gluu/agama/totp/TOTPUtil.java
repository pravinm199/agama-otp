package org.gluu.agama.totp;

import java.security.SecureRandom;
import com.lochbridge.oath.otp.*;
import com.lochbridge.oath.otp.keyprovisioning.*;
import java.util.concurrent.TimeUnit;
import com.google.common.io.BaseEncoding;

public class TOTPUtil {

    public TOTPUtil() {
    }

    // Method to generate a secret key using SecureRandom
    public static String generateSecretKey(String algorithm) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);

        SecureRandom secureRandom = new SecureRandom();
        keyGenerator.init(secureRandom);

        Key secretKey = keyGenerator.generateKey();

        // Helper method to convert byte array to hexadecimal string
        byte[] bytes = secretKey.getEncoded();
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02X", b));
        }
        return result.toString();
    }

    // Method to generate TOTP Secret URI
    public static String generateTotpSecretKeyUri(String secretKey, String issuer, String userDisplayName) {
        int digits = 6;
        int timeStep = 30;

        String secretKeyBase32 = base32Encode(secretKey);
        OTPKey key = new OTPKey(secretKeyBase32, OTPType.TOTP);
        String label = issuer + " " + userDisplayName;

        OTPAuthURI uri = OTPAuthURIBuilder.fromKey(key).label(label).issuer(issuer).digits(digits)
                .timeStep(TimeUnit.SECONDS.toMillis(timeStep)).build();
        return uri.toUriString();
    }

    private static String base32Encode(String input) {
        byte[] bytesToEncode = input.getBytes();
        return BaseEncoding.base32().omitPadding().encode(bytesToEncode);
    }

    private static String base64URLEncode(String input) {
        byte[] bytesToEncode = input.getBytes();
        return BaseEncoding.base64Url().encode(bytesToEncode);
    }

    private static String base64UrlDecode(String input) {
        byte[] decodedBytes = BaseEncoding.base64Url().decode(input);
        return new String(decodedBytes);
    }
}
