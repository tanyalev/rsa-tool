package ua.edu.sumdu.crypto.levchenko.rsatool.models.rsa;

import ua.edu.sumdu.crypto.levchenko.rsatool.models.KeyPair;
import ua.edu.sumdu.crypto.levchenko.rsatool.models.Padding;
import ua.edu.sumdu.crypto.levchenko.rsatool.models.rsa.exceptions.RsaException;

import java.math.BigInteger;
import java.util.Objects;

public class Rsa {
    private Padding padding = new NoPadding();

    public Padding getPadding() {
        return padding;
    }

    public void setPadding(Padding padding) {
        this.padding = Objects.requireNonNullElseGet(padding, NoPadding::new);
    }

    /**
     * data:
     * {
     *     "data":"0248F849A042489C85B..."
     *     "padding": "None"
     * }
     *
     * privateKey:
     * {
     *     "N": 1247,
     *     "D": 928418247158924571894....
     * }
     * */
    public String decrypt(String privateKey, String data) throws Exception {
        KeyPair.PrivateKey key = new KeyPair.PrivateKey(privateKey);
        Message message = new Message(data);
        return new String(padding.decrypt(key, message.getData()));
    }

    /**
     * data:
     * {
     *     "data":"0248F849A042489C85B..."
     *     "padding": "None"
     * }
     *
     * publicKey:
     * {
     *     "N": 1247,
     *     "E": 928418247158924571894....
     * }
     * */
    public String encrypt(String publicKey, String data) throws Exception {
        KeyPair.PublicKey key = new KeyPair.PublicKey(publicKey);
        Message message = new Message(data);
        return new String(padding.encrypt(key, message.getData()));
    }

    private static class Message {
        private byte[] data;
        private String padding;

        public Message(String rawMessage) {

        }

        public byte[] getData() {
            return data;
        }

        public String getPadding() {
            return padding;
        }
    }
}
