package ua.edu.sumdu.crypto.levchenko.rsatool.rsa;

import java.math.BigInteger;

class Util {
    public static BigInteger bytes2int(byte[] bytes) {
        return new BigInteger(1, bytes);
    }

    public static BigInteger string2int(String str) {
        byte[] bytes = new byte[str.length()];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) str.charAt(i);
        }
        return new BigInteger(1, bytes);
    }

    public static byte[] int2bytes(BigInteger n) {
        return n.toByteArray();
    }

    public static String int2string(BigInteger n) {
        byte[] bytes = n.toByteArray();
        StringBuilder str = new StringBuilder();
        for (byte symbol : bytes) {
            str.append((char) symbol);
        }
        return str.toString();
    }
}
