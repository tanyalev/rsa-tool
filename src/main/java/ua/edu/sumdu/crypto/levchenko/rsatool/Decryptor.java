package ua.edu.sumdu.crypto.levchenko.rsatool;

public interface Decryptor {
    byte[] decrypt(KeyPair.PrivateKey key, byte[] data) throws Exception;
}
