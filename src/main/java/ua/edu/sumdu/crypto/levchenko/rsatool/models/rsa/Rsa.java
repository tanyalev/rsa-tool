package ua.edu.sumdu.crypto.levchenko.rsatool.models.rsa;

import ua.edu.sumdu.crypto.levchenko.rsatool.models.KeyPair;
import ua.edu.sumdu.crypto.levchenko.rsatool.models.rsa.exceptions.RsaWrongPaddingRsaException;

import java.util.Arrays;
import java.util.Objects;

public class Rsa {
    private Padding padding;

    public Rsa() {
        this.padding = Padding.NONE;
    }

    public void setPadding(Padding padding) {
        this.padding = padding;
    }

    /**
     * base64(data:
     * {
     *     "data":"0248F849A042489C85B..."
     *     "padding": "None"
     * })
     * base64(
     * privateKey:
     * {
     *     "N": 1247,
     *     "D": 928418247158924571894....
     * })
     * */
    public String decrypt(String privateKey, Message message) throws Exception {
        if (message.padding.equals(padding.toString())) {
            KeyPair.PrivateKey key = new KeyPair.PrivateKey(privateKey);
            byte[] decryptedData = padding.decrypt(key, message.getData());
            return new String(decryptedData);
        }

        throw new RsaWrongPaddingRsaException(String.format("Message padding %s is not selected one %s!",
                message.getPadding(), padding.toString()));
    }

    /**
     * base64(
     * data:
     * {
     *     "data":"0248F849A042489C85B..."
     *     "padding": "None"
     * })
     * base64(
     * publicKey:
     * {
     *     "N": 1247,
     *     "E": 928418247158924571894....
     * })
     * */
    public Message encrypt(String publicKey, String data) throws Exception {
        KeyPair.PublicKey key = new KeyPair.PublicKey(publicKey);
        byte[] encryptedData = padding.encrypt(key, data.getBytes());
        return new Message(encryptedData, padding.toString());
    }

    public static class Message {
        private byte[] data;
        private String padding;

        public static Message fromRawData(String rawData) {
            byte[] data = new byte[1];
            String padding = "";
            return new Message(data, padding);
        }

        private Message(byte[] data, String padding) {
            this.data = data;
            this.padding = padding;
        }

        public String toRawData() {

        }

        public byte[] getData() {
            return data;
        }

        public String getPadding() {
            return padding;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Message message = (Message) o;
            return Arrays.equals(getData(), message.getData()) &&
                    getPadding().equals(message.getPadding());
        }

        @Override
        public int hashCode() {
            int result = Objects.hash(getPadding());
            result = 31 * result + Arrays.hashCode(getData());
            return result;
        }
    }
}
