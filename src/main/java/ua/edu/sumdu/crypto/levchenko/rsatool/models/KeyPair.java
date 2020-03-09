package ua.edu.sumdu.crypto.levchenko.rsatool.models;

import java.math.BigInteger;
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

    public static class PublicKey {
        private BigInteger n;
        private BigInteger e;

        public PublicKey(BigInteger n, BigInteger e) {
            this.n = n;
            this.e = e;
        }

        public BigInteger getN() {
            return n;
        }

        public BigInteger getE() {
            return e;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            PublicKey publicKey = (PublicKey) o;
            return getN().equals(publicKey.getN()) &&
                    getE().equals(publicKey.getE());
        }

        @Override
        public int hashCode() {
            return Objects.hash(getN(), getE());
        }

        @Override
        public String toString() {
            return "PublicKey{" +
                    "n=" + n +
                    ", e=" + e +
                    '}';
        }
    }

    public static class PrivateKey {
        private BigInteger n;
        private BigInteger d;

        public PrivateKey(BigInteger n, BigInteger d) {
            this.n = n;
            this.d = d;
        }

        public BigInteger getN() {
            return n;
        }

        public BigInteger getD() {
            return d;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            PrivateKey that = (PrivateKey) o;
            return getN().equals(that.getN()) &&
                    getD().equals(that.getD());
        }

        @Override
        public int hashCode() {
            return Objects.hash(getN(), getD());
        }

        @Override
        public String toString() {
            return "PrivateKey{" +
                    "n=" + n +
                    ", d=" + d +
                    '}';
        }
    }
}
