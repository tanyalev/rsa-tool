package ua.edu.sumdu.crypto.levchenko.rsatool.models.rsa;

import ua.edu.sumdu.crypto.levchenko.rsatool.models.KeyPair;
import ua.edu.sumdu.crypto.levchenko.rsatool.models.Padding;
import ua.edu.sumdu.crypto.levchenko.rsatool.models.rsa.exceptions.RsaException;

public class PkcsPadding implements Padding {
    @Override
    public byte[] decrypt(KeyPair.PrivateKey key, byte[] data) throws RsaException {
        return new byte[0];
    }

    @Override
    public byte[] encrypt(KeyPair.PublicKey key, byte[] data) throws RsaException {
        return new byte[0];
    }

    @Override
    public String toString() {
        return "PKCS";
    }
}
