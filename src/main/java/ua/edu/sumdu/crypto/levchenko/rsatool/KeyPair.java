package ua.edu.sumdu.crypto.levchenko.rsatool;

import org.json.JSONObject;

import java.math.BigInteger;
import java.util.Base64;
import java.util.Objects;

public class KeyPair {
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public KeyPair(PublicKey publicKey, PrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KeyPair keyPair = (KeyPair) o;
        return getPublicKey().equals(keyPair.getPublicKey()) &&
                getPrivateKey().equals(keyPair.getPrivateKey());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getPublicKey(), getPrivateKey());
    }

    private static class Key {
        public String toRawData() {
            JSONObject jsonObject = new JSONObject(this);
            String rawData = jsonObject.toString();
            return Base64.getEncoder().encodeToString(rawData.getBytes());
        }
    }

    public static class PublicKey extends Key {
        private BigInteger N;
        private BigInteger E;
        private int size;

        public PublicKey(BigInteger N, BigInteger E, int size) {
            this.N = N;
            this.E = E;
            this.size = size;
        }

        public static PublicKey fromRawData(String rawKey) {
            String decodedRawData = new String(Base64.getDecoder().decode(rawKey));
            JSONObject jsonObject = new JSONObject(decodedRawData);
            BigInteger n = jsonObject.getBigInteger("N");
            BigInteger e = jsonObject.getBigInteger("E");
            int size = jsonObject.getInt("size");
            return new PublicKey(n, e, size);
        }

        public BigInteger getN() {
            return N;
        }

        public BigInteger getE() {
            return E;
        }

        public int getSize() {
            return size;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            PublicKey key = (PublicKey) o;
            return getSize() == key.getSize() &&
                    getN().equals(key.getN()) &&
                    getE().equals(key.getE());
        }

        @Override
        public int hashCode() {
            return Objects.hash(getN(), getE(), getSize());
        }

        @Override
        public String toString() {
            return "PublicKey{" +
                    "N=" + N +
                    ", E=" + E +
                    ", size=" + size +
                    '}';
        }
    }

    public static class PrivateKey extends Key {
        private BigInteger N;
        private BigInteger D;
        private int size;

        public PrivateKey(BigInteger n, BigInteger d, int size) {
            this.N = n;
            this.D = d;
            this.size = size;
        }

        public static PrivateKey fromRawData(String rawData) {
            String decodedRawData = new String(Base64.getDecoder().decode(rawData));
            JSONObject jsonObject = new JSONObject(decodedRawData);
            BigInteger n = jsonObject.getBigInteger("N");
            BigInteger d = jsonObject.getBigInteger("D");
            int size = jsonObject.getInt("size");
            return new PrivateKey(n, d, size);
        }

        public BigInteger getN() {
            return N;
        }

        public BigInteger getD() {
            return D;
        }

        public int getSize() {
            return size;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            PrivateKey that = (PrivateKey) o;
            return getSize() == that.getSize() &&
                    getN().equals(that.getN()) &&
                    getD().equals(that.getD());
        }

        @Override
        public int hashCode() {
            return Objects.hash(getN(), getD(), getSize());
        }

        @Override
        public String toString() {
            return "PrivateKey{" +
                    "N=" + N +
                    ", D=" + D +
                    ", size=" + size +
                    '}';
        }
    }
}
