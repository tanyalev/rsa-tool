package ua.edu.sumdu.crypto.levchenko.rsatool.rsa;

import ua.edu.sumdu.crypto.levchenko.rsatool.rsa.KeyPair;

import java.math.BigInteger;

public interface Decryptor {
    BigInteger decrypt(KeyPair.PrivateKey key, BigInteger data);
}
