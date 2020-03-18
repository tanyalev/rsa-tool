package ua.edu.sumdu.crypto.levchenko.rsatool.models.rsa;

import org.json.JSONObject;
import ua.edu.sumdu.crypto.levchenko.rsatool.models.KeyPair;
import ua.edu.sumdu.crypto.levchenko.rsatool.models.rsa.exceptions.RsaWrongPaddingRsaException;

import java.util.Arrays;
import java.util.Base64;
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
    public String decrypt(KeyPair.PrivateKey privateKey, Message message) throws Exception {
        if (message.padding.equals(padding.toString())) {
            byte[] decryptedData = padding.decrypt(privateKey, message.getData());
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
    public Message encrypt(KeyPair.PublicKey publicKey, String data) throws Exception {
        byte[] encryptedData = padding.encrypt(publicKey, data.getBytes());
        return new Message(encryptedData, padding.toString());
    }

    public static class Message {
        private byte[] data;
        private String padding;

        Message(byte[] data, String padding) {
            this.data = data;
            this.padding = padding;
        }

        public static Message fromRawData(String rawData) {
            String decodedRawData = new String(Base64.getDecoder().decode(rawData));
            JSONObject jsonObject = new JSONObject(decodedRawData);
            byte[] data = jsonObject.getString("data").getBytes();
            String padding = jsonObject.getString("padding");
            return new Message(data, padding);
        }

        public String toRawData() {
            JSONObject jsonObject = new JSONObject(this);
            String rawData = jsonObject.toString();
            return Base64.getEncoder().encodeToString(rawData.getBytes());
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
