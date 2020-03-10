package ua.edu.sumdu.crypto.levchenko.rsatool.models.rsa;

import ua.edu.sumdu.crypto.levchenko.rsatool.models.KeyPair;
import ua.edu.sumdu.crypto.levchenko.rsatool.models.Padding;

import java.math.BigInteger;

public class NoPadding implements Padding {
    public byte[] decrypt(KeyPair.PrivateKey key, byte[] data) {
        BigInteger c = new BigInteger(1, data);
        BigInteger decryptedData = c.modPow(key.getD(), key.getN());
        return decryptedData.toByteArray();
    }

    public byte[] encrypt(KeyPair.PublicKey key, byte[] data) {
        BigInteger m = new BigInteger(1, data);
        BigInteger encryptedData = m.modPow(key.getE(), key.getN());
        return encryptedData.toByteArray();
    }

    @Override
    public String toString() {
        return "None";
    }
}
