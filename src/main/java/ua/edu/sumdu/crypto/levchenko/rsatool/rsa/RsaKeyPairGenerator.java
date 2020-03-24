package ua.edu.sumdu.crypto.levchenko.rsatool.rsa;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;
import java.util.Random;

public class RsaKeyPairGenerator {
    public KeyPair generateKeyPair(int keySize) {
        assert List.of(512, 1024, 2048, 4096).contains(keySize) : "Key size must be one of 512, 1024, 2048, 4096.";

        int keyPartSize = keySize / 2;

        Random random = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(keyPartSize, random);
        BigInteger q = BigInteger.probablePrime(keyPartSize, random);

        BigInteger n = p.multiply(q);
        BigInteger phi = p.subtract(BigInteger.ONE)
                .multiply(q.subtract(BigInteger.ONE));

        BigInteger e;
        do {
            e = new BigInteger(phi.bitLength(), random);
        } while (e.compareTo(BigInteger.ONE) <= 0 || e.compareTo(phi) >= 0 || !e.gcd(phi).equals(BigInteger.ONE));

        BigInteger d = e.modInverse(phi);

        return new KeyPair(new KeyPair.PublicKey(n, e, keySize), new KeyPair.PrivateKey(n, d, keySize));
    }
}
