package ua.edu.sumdu.crypto.levchenko.rsatool.rsa;

import ua.edu.sumdu.crypto.levchenko.rsatool.Decryptor;
import ua.edu.sumdu.crypto.levchenko.rsatool.Encryptor;
import ua.edu.sumdu.crypto.levchenko.rsatool.KeyPair;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Logger;

public enum Padding implements Encryptor, Decryptor {
    NONE {
        @Override
        public byte[] encrypt(KeyPair.PublicKey key, byte[] data) {
            BigInteger m = new BigInteger(1, data);
            BigInteger encryptedData = m.modPow(key.getE(), key.getN());
            return encryptedData.toByteArray();
        }

        @Override
        public byte[] decrypt(KeyPair.PrivateKey key, byte[] data) {
            BigInteger c = new BigInteger(1, data);
            BigInteger decryptedData = c.modPow(key.getD(), key.getN());
            return decryptedData.toByteArray();
        }
    },

    PKCS1 {
        @Override
        public byte[] encrypt(KeyPair.PublicKey publicKey, byte[] data) {
            int keyLen = ((publicKey.getN().bitLength() + 7) / 8)  - 11;
            if (data.length > keyLen) {
                log.severe(String.format("message is too long %d > %d", data.length, keyLen));
                return new byte[0];
            }

            // EncryptionBlock = 00 | 02 | ..PS.. | 00 | data

            int psLen = keyLen - data.length - 3;
            byte[] encryptionBlock = new byte[keyLen];
            encryptionBlock[0] = 0x00;
            encryptionBlock[1] = 0x02;

            byte[] psBlock = new byte[psLen];
            Random random = new Random();
            random.nextBytes(psBlock);

            System.arraycopy(encryptionBlock, 2, psBlock, 0, encryptionBlock.length);

            encryptionBlock[psLen + 2] = 0x00;

            System.arraycopy(encryptionBlock, psLen + 3, data, 0, encryptionBlock.length);

            return NONE.encrypt(publicKey, encryptionBlock);
        }

        @Override
        public byte[] decrypt(KeyPair.PrivateKey privateKey, byte[] data) {
            int keyLen = (privateKey.getN().bitLength() + 7) / 8;
            if (data.length != keyLen) {
                log.severe(String.format("message len is not equal to key len %d != %d", data.length, keyLen));
                return new byte[0];
            }

            byte[] decryptedData = NONE.decrypt(privateKey, data);
            if (decryptedData[0] != 0x00 || decryptedData[1] != 0x02) {
                log.warning("message hasn't PKCS #1 padding");
                return decryptedData;
            }

            int paddingEnding = Arrays.binarySearch(decryptedData, 2, decryptedData.length - 1, (byte) 0x00) + 2;
            if (paddingEnding < 2) {
                log.severe("end of padding not found");
                return new byte[0];
            }

            return Arrays.copyOfRange(decryptedData, paddingEnding + 1, decryptedData.length - 1);
        }
    };

    private final static Logger log = Logger.getLogger(Padding.class.getName());
}
