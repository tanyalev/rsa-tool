package ua.edu.sumdu.crypto.levchenko.rsatool.rsa;

import ua.edu.sumdu.crypto.levchenko.rsatool.rsa.KeyPair;

import java.math.BigInteger;

public interface Encryptor {
    BigInteger encrypt(KeyPair.PublicKey key, BigInteger data);
}
