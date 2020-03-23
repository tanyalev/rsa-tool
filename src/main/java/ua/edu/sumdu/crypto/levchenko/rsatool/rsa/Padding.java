package ua.edu.sumdu.crypto.levchenko.rsatool.rsa;

import ua.edu.sumdu.crypto.levchenko.rsatool.Decryptor;
import ua.edu.sumdu.crypto.levchenko.rsatool.Encryptor;
import ua.edu.sumdu.crypto.levchenko.rsatool.KeyPair;

import java.math.BigInteger;

public enum Padding implements Encryptor, Decryptor {
    NONE {
        @Override
        public byte[] decrypt(KeyPair.PrivateKey key, byte[] data) {
            BigInteger c = new BigInteger(1, data);
            BigInteger decryptedData = c.modPow(key.getD(), key.getN());
            return decryptedData.toByteArray();
        }

        @Override
        public byte[] encrypt(KeyPair.PublicKey key, byte[] data) {
            BigInteger m = new BigInteger(1, data);
            BigInteger encryptedData = m.modPow(key.getE(), key.getN());
            return encryptedData.toByteArray();
        }
    },

    PKCS1 {
        @Override
        public byte[] encrypt(KeyPair.PublicKey publicKey, byte[] data) {
            return null;
        }

        @Override
        public byte[] decrypt(KeyPair.PrivateKey privateKey, byte[] data) {
            return null;
        }
    };
}
