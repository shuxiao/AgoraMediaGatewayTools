package com.mycompany.app;

import org.msgpack.core.MessagePack;
import org.msgpack.core.MessageBufferPacker;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class App {
    public static void main(String[] args)throws Exception {
        String appcert = "0123456789abcdef0123456789abcdef"; // The App Certificate for the project
        String channelName = "test123"; // The channel name
        String uid = "1001"; // The uid, can be either a Integer uid or a String uid, a zero or empty value means random uid
        String tempid = ""; // The template Id, can be empty
        int expiresAfter = 86400; // Expires after XX seconds, a zero value means expires immediately

        try {
            String streamkey = generateStreamKey(appcert, channelName, uid, tempid, expiresAfter);
            System.out.println(streamkey);
        } catch (Exception e) { 
            e.printStackTrace();
            System.exit(1);
        }
    }

    public static String generateStreamKey(String appCert, String channel, String uid, String tempid, int expiresAfter) throws Exception {
        long expiresAt = System.currentTimeMillis() / 1000 + expiresAfter;

        // Check if values are valid
        if(!isValidAppcert(appCert)) {
            throw new IllegalArgumentException("Invalid App Certificate found");
        }

        if(!isValidAgoraChannelName(channel)) {
            throw new IllegalArgumentException("Invalid channel name found");
        }

        if(!isValidAgoraAccount(uid)) {
            throw new IllegalArgumentException("Invalid uid found");
        }

        MessageBufferPacker packer = MessagePack.newDefaultBufferPacker();
        packer.packMapHeader(4); // the number of key-value pairs

        packer.packString("C");
        packer.packString(channel);
        packer.packString("U");
        packer.packString(uid);
        packer.packString("T");
        packer.packString(tempid);
        packer.packString("E");
        packer.packLong(expiresAt);

        packer.close();

        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);

        byte[] key = hexStringToByteArray(appCert);

        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        Cipher encrypter = Cipher.getInstance("AES/CTR/NoPadding");
        encrypter.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] data = packer.toByteArray();
        byte[] encrypted = encrypter.doFinal(data);

        byte[] ivAndData = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, ivAndData, 0, iv.length);
        System.arraycopy(encrypted, 0, ivAndData, iv.length, encrypted.length);

        String streamKey = Base64.getUrlEncoder().withoutPadding().encodeToString(ivAndData);

        return streamKey;
    }

    public static boolean isValidAppcert(String appCert) {
        if (appCert == null || appCert.length() != 32) {
            return false;
        }

        for (char c : appCert.toCharArray()) {
            if (!((c >= '0' && c <= '9') || 
                        (c >= 'a' && c <= 'f'))) {
                return false;
            }
        }
        return true;
    }

    private static boolean isAllowedSpecialChar(char c) {
        String specialChars = "!#$%&()+-:;<=>.?@[]^_{|}~,";
        return specialChars.indexOf(c) != -1;
    }

    public static boolean isValidAgoraChannelName(String channelName) {
        if (channelName == null || channelName.length() == 0 || 
                channelName.length() > 64 || channelName.equals("null")) {
            return false;
        }

        for (int i = 0; i < channelName.length(); i++) {
            char c = channelName.charAt(i);
            if (!Character.isLetterOrDigit(c) && c != ' ' && !isAllowedSpecialChar(c)) {
                return false;
            }
        }

        return true;
    }

    public static boolean isValidAgoraAccount(String account) {
        if (account == null || account.length() > 255) {
            return false;
        }

        for (int i = 0; i < account.length(); i++) {
            char c = account.charAt(i);
            if (!Character.isLetterOrDigit(c) && c != ' ' && !isAllowedSpecialChar(c)) {
                return false;
            }
        }

        return true;
    }

    public static byte[] hexStringToByteArray(String hex) {
        int length = hex.length();
        byte[] data = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}

