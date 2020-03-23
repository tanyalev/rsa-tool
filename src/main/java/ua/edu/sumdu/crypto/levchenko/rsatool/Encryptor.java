package ua.edu.sumdu.crypto.levchenko.rsatool;

public interface Encryptor {
    byte[] encrypt(KeyPair.PublicKey key, byte[] data);
}
