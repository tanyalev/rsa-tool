package ua.edu.sumdu.crypto.levchenko.rsatool.models;

public interface Decryptor {
    byte[] decrypt(KeyPair.PrivateKey key, byte[] data) throws Exception;
}
