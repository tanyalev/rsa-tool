package ua.edu.sumdu.crypto.levchenko.rsatool;

import ua.edu.sumdu.crypto.levchenko.rsatool.models.KeyPair;
import ua.edu.sumdu.crypto.levchenko.rsatool.models.KeyPairGenerator;
import ua.edu.sumdu.crypto.levchenko.rsatool.models.rsa.RsaKeyPairGenerator;

public class Main {
    public static void main(String[] args) {
        KeyPairGenerator keyPairGenerator = new RsaKeyPairGenerator();
        KeyPair keyPair = keyPairGenerator.generateKeyPair(2048);
        System.out.println(keyPair.getPublicKey());
        System.out.println(keyPair.getPrivateKey());
    }
}
