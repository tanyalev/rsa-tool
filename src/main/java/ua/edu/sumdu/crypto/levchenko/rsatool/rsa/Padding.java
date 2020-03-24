package ua.edu.sumdu.crypto.levchenko.rsatool.rsa;

import ua.edu.sumdu.crypto.levchenko.rsatool.Decryptor;
import ua.edu.sumdu.crypto.levchenko.rsatool.Encryptor;
import ua.edu.sumdu.crypto.levchenko.rsatool.KeyPair;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Logger;

import static ua.edu.sumdu.crypto.levchenko.rsatool.rsa.Util.*;

public enum Padding implements Encryptor, Decryptor {
    NONE {
        @Override
        public int getCharsPerChunk(BigInteger N) {
            return (N.bitLength() - 1) / 8;
        }

        @Override
        public BigInteger encrypt(KeyPair.PublicKey key, BigInteger data) {
            return data.modPow(key.getE(), key.getN());
        }

        @Override
        public BigInteger decrypt(KeyPair.PrivateKey key, BigInteger data) {
            return data.modPow(key.getD(), key.getN());
        }
    },

    PKCS1 {
        @Override
        public int getCharsPerChunk(BigInteger N) {
            return ((N.bitLength() + 7) / 8) - 11;
        }

        @Override
        public BigInteger encrypt(KeyPair.PublicKey publicKey, BigInteger data) {
            byte[] rawData = int2string(data).getBytes();

            int keyLen = getCharsPerChunk(publicKey.getN()) + 11;
            if (rawData.length > keyLen - 11) {
                log.severe(String.format("message is too long %d > %d", rawData.length, keyLen));
                return BigInteger.ZERO;
            }

            // EncryptionBlock = 00 | 02 | ..PS.. | 00 | data

            int psLen = keyLen - rawData.length - 3;
            byte[] encryptionBlock = new byte[keyLen];
            encryptionBlock[0] = (byte) 0x00;
            encryptionBlock[1] = (byte) 0x02;

            byte[] psBlock = new byte[psLen];
            Random random = new Random();
            random.nextBytes(psBlock);

            System.arraycopy(psBlock, 0, encryptionBlock, 2, psBlock.length);

            encryptionBlock[psLen + 2] = (byte) 0x00;

            System.arraycopy(rawData, 0, encryptionBlock, psLen + 3, rawData.length);

            BigInteger encryptionBlockNumber = bytes2int(encryptionBlock);
            return NONE.encrypt(publicKey, encryptionBlockNumber);
        }

        @Override
        public BigInteger decrypt(KeyPair.PrivateKey privateKey, BigInteger data) {
            byte[] rawData = int2bytes(data);

            int keyLen = getCharsPerChunk(privateKey.getN()) + 11;
            if (rawData.length != keyLen) {
                log.severe(String.format("message len is not equal to key len %d != %d", rawData.length, keyLen));
                return BigInteger.ZERO;
            }

            byte[] notPaddedDecryptedData = int2bytes(NONE.decrypt(privateKey, bytes2int(rawData)));
            byte[] decryptedData = new byte[keyLen];
            Arrays.fill(decryptedData, (byte) 0x00);
            System.arraycopy(notPaddedDecryptedData, 0, decryptedData,
                    keyLen - notPaddedDecryptedData.length, notPaddedDecryptedData.length);

            log.info(Arrays.toString(decryptedData));
            if (decryptedData[0] != (byte) 0x00 || decryptedData[1] != (byte) 0x02) {
                log.warning("message hasn't PKCS #1 padding");
                return bytes2int(decryptedData);
            }

            int paddingEnding = Arrays.binarySearch(decryptedData, 2, decryptedData.length, (byte) 0x00) + 2;
            if (paddingEnding < 2) {
                log.severe("end of padding not found");
                return BigInteger.ZERO;
            }

            return bytes2int(Arrays.copyOfRange(decryptedData, paddingEnding - 1, decryptedData.length));
        }
    };

    private final static Logger log = Logger.getLogger(Padding.class.getName());

    public abstract int getCharsPerChunk(BigInteger N);
}
