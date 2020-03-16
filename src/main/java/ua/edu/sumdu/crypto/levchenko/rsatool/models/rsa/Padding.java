package ua.edu.sumdu.crypto.levchenko.rsatool.models.rsa;

import ua.edu.sumdu.crypto.levchenko.rsatool.models.Decryptor;
import ua.edu.sumdu.crypto.levchenko.rsatool.models.Encryptor;
import ua.edu.sumdu.crypto.levchenko.rsatool.models.KeyPair;

import java.math.BigInteger;

public enum Padding implements Encryptor, Decryptor {
    NONE("None") {
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

    PKCS1("PKCS1") {
        @Override
        public byte[] encrypt(KeyPair.PublicKey publicKey, byte[] data) {
            return null;
        }

        @Override
        public byte[] decrypt(KeyPair.PrivateKey privateKey, byte[] data) {
            return null;
        }
    };

    private String name;

    Padding(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }
}
