package ua.edu.sumdu.crypto.levchenko.rsatool.models;

public interface Encryptor {
    byte[] encrypt(KeyPair.PublicKey key, byte[] data) throws Exception;
}
