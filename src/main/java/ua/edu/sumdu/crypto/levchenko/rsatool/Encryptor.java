package ua.edu.sumdu.crypto.levchenko.rsatool;

import java.math.BigInteger;

public interface Encryptor {
    BigInteger encrypt(KeyPair.PublicKey key, BigInteger data);
}
