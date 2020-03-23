package ua.edu.sumdu.crypto.levchenko.rsatool;

import java.math.BigInteger;

public interface Decryptor {
    BigInteger decrypt(KeyPair.PrivateKey key, BigInteger data);
}
