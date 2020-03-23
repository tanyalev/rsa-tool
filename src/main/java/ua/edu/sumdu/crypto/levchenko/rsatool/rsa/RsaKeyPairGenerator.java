package ua.edu.sumdu.crypto.levchenko.rsatool.rsa;

import ua.edu.sumdu.crypto.levchenko.rsatool.KeyPair;

import java.math.BigInteger;
import java.util.List;
import java.util.Random;

public class RsaKeyPairGenerator {
    public KeyPair generateKeyPair(int keySize) {
        assert List.of(512, 1024, 2048, 4096).contains(keySize) : "Key size must be one of 512, 1024, 2048, 4096.";

        int keyPartSize = keySize / 2;

        BigInteger e = BigInteger.valueOf(65537);

        while (true) {
            BigInteger p = new BigInteger(keyPartSize, new Random());
            BigInteger q = new BigInteger(keyPartSize, new Random());

            BigInteger n = p.multiply(q);
            if (n.bitLength() == keySize) {
                p = p.subtract(BigInteger.ONE);
                q = q.subtract(BigInteger.ONE);

                BigInteger totient = p.multiply(q);

                BigInteger d = e.modInverse(totient);
                if (!d.equals(BigInteger.ZERO) && !d.equals(BigInteger.ONE)) {
                    return new KeyPair(new KeyPair.PublicKey(n, e, keySize), new KeyPair.PrivateKey(n, d, keySize));
                }
            }
        }
    }
}
