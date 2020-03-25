package ua.edu.sumdu.crypto.levchenko.rsatool;

import java.io.File;
import java.io.FileWriter;
import java.math.BigInteger;
import java.util.Scanner;
import java.util.logging.Logger;

public class Util {
    private static final Logger log = Logger.getLogger(Util.class.getName());

    public static BigInteger bytes2int(byte[] bytes) {
        return new BigInteger(1, bytes);
    }

    public static BigInteger string2int(String str) {
        byte[] bytes = new byte[str.length()];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) str.charAt(i);
        }
        return new BigInteger(1, bytes);
    }

    public static byte[] int2bytes(BigInteger n) {
        return n.toByteArray();
    }

    public static String int2string(BigInteger n) {
        byte[] bytes = n.toByteArray();
        StringBuilder str = new StringBuilder();
        for (byte symbol : bytes) {
            str.append((char) symbol);
        }
        return str.toString();
    }

    public static void writeToFile(String file, String data) throws Exception {
        File outputFile = new File(file);
        if (outputFile.createNewFile()) {
            log.info(String.format("\"%s\" file has been created.", file));
        } else {
            log.warning(String.format("\"%s\" file already exists.", file));
        }

        try (FileWriter fileWriter = new FileWriter(file)) {
            fileWriter.write(data);
        }
    }

    public static String readFromFile(String file) throws Exception {
        File inputFile = new File(file);
        Scanner scanner = new Scanner(inputFile);
        StringBuilder input = new StringBuilder();
        while (scanner.hasNextLine()) {
            input.append(scanner.nextLine());
        }
        return input.toString();
    }
}
