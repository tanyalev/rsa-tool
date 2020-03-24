package ua.edu.sumdu.crypto.levchenko.rsatool.rsa;

import org.json.JSONArray;
import org.json.JSONObject;
import ua.edu.sumdu.crypto.levchenko.rsatool.KeyPair;
import ua.edu.sumdu.crypto.levchenko.rsatool.rsa.exceptions.RsaWrongPaddingRsaException;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.stream.Collectors;

import static ua.edu.sumdu.crypto.levchenko.rsatool.rsa.Util.int2string;
import static ua.edu.sumdu.crypto.levchenko.rsatool.rsa.Util.string2int;

public class Rsa {
    private Padding padding;

    public Rsa() {
        this.padding = Padding.NONE;
    }

    public void setPadding(Padding padding) {
        this.padding = padding;
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
        int charsPerChunk = padding.getCharsPerChunk(publicKey.getN());

        StringBuilder dataBuilder = new StringBuilder(data);
        while (dataBuilder.length() % charsPerChunk != 0) {
            dataBuilder.append(" ");
        }

        data = dataBuilder.toString();
        int chunks = data.length() / charsPerChunk;
        BigInteger[] encryptedChunks = new BigInteger[chunks];

        for (int i = 0; i < chunks; i++) {
            String substring = data.substring(charsPerChunk * i, charsPerChunk * (i+1));
            encryptedChunks[i] = padding.encrypt(publicKey, string2int(substring));
        }

        return new Message(encryptedChunks, padding.toString());
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
            return Arrays.stream(message.getData())
                    .map(encryptedChunk -> int2string(padding.decrypt(privateKey, encryptedChunk)))
                    .collect(Collectors.joining());
        }
        throw new RsaWrongPaddingRsaException(String.format("Message padding %s is not selected one %s!",
                message.getPadding(), padding.toString()));
    }

    public static class Message {
        private BigInteger[] data;
        private String padding;

        Message(BigInteger[] data, String padding) {
            this.data = data;
            this.padding = padding;
        }

        public static Message fromRawData(String rawData) {
            String decodedRawData = new String(Base64.getDecoder().decode(rawData), StandardCharsets.UTF_8);
            JSONObject jsonObject = new JSONObject(decodedRawData);
            JSONArray jsonArrayData = jsonObject.getJSONArray("data");
            BigInteger[] data = new BigInteger[jsonArrayData.length()];
            for (int i = 0; i < jsonArrayData.length(); i++) {
                data[i] = jsonArrayData.getBigInteger(i);
            }
            String padding = jsonObject.getString("padding");
            return new Message(data, padding);
        }

        public String toRawData() {
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("data", data);
            jsonObject.put("padding", padding);
            String rawData = jsonObject.toString();
            return Base64.getEncoder().encodeToString(rawData.getBytes());
        }

        public BigInteger[] getData() {
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
