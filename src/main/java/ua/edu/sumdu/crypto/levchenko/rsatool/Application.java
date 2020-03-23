package ua.edu.sumdu.crypto.levchenko.rsatool;

import org.apache.commons.cli.*;
import ua.edu.sumdu.crypto.levchenko.rsatool.rsa.Padding;
import ua.edu.sumdu.crypto.levchenko.rsatool.rsa.Rsa;
import ua.edu.sumdu.crypto.levchenko.rsatool.rsa.RsaKeyPairGenerator;

import java.io.File;
import java.io.FileWriter;
import java.util.Objects;
import java.util.Properties;
import java.util.Scanner;
import java.util.function.Consumer;
import java.util.logging.Logger;

public class Application {
    private final static Logger log = Logger.getLogger(Application.class.getName());

    private Options options;
    private Properties properties;
    private Consumer<Properties> action;

    public Application(String[] args) {
        prepareOptions();
        parseCommandLineArgs(args);
    }

    public void run() {
        action.accept(properties);
    }

    private void writeToFile(String file, String data) throws Exception {
        File outputFile = new File(file);
        if (outputFile.createNewFile()) {
            log.fine(String.format("\"%s\" file has been created.", file));
        } else {
            log.warning(String.format("\"%s\" file already exists.", file));
        }

        FileWriter fileWriter = new FileWriter(file);
        fileWriter.write(data);
    }

    private String readFromFile(String file) throws Exception {
        File inputFile = new File(file);
        Scanner scanner = new Scanner(inputFile);
        StringBuilder input = new StringBuilder();
        while (scanner.hasNextLine()) {
            input.append(scanner.nextLine());
        }
        return input.toString();
    }

    private void generateKeyPair(Properties properties) {
        assert properties.contains("size") && properties.contains("file") : "Wrong properties!";

        int keySize = Integer.parseInt(properties.getProperty("size"));
        String file = properties.getProperty("file");

        RsaKeyPairGenerator keyPairGenerator = new RsaKeyPairGenerator();
        KeyPair keyPair = keyPairGenerator.generateKeyPair(keySize);

        String rawPublicKey = keyPair.getPublicKey().toRawData();
        String rawPrivateKey = keyPair.getPrivateKey().toRawData();

        String publicKeyFilename = String.format("%s_pub.key", file.strip());
        String privateKeyFilename = String.format("%s_priv.key", file.strip());

        try {
            writeToFile(publicKeyFilename, rawPublicKey);
            writeToFile(privateKeyFilename, rawPrivateKey);
        } catch (Exception e) {
            log.severe(String.format("Error writing key pair to file \"%s\": %s", file, e.getMessage()));
        }
    }

    private void encryptData(Properties properties) {
        assert properties.contains("file")
                && properties.contains("pubkey")
                && properties.contains("padding") : "Wrong properties!";

        String dataFile = properties.getProperty("file");
        String publicKeyFile = properties.getProperty("pubkey");
        boolean usePadding = Boolean.getBoolean(properties.getProperty("padding"));

        try {
            String data = readFromFile(dataFile);
            String rawPublicKey = readFromFile(publicKeyFile);
            KeyPair.PublicKey publicKey = KeyPair.PublicKey.fromRawData(rawPublicKey);

            Rsa rsa = new Rsa();
            rsa.setPadding(usePadding ? Padding.PKCS1 : Padding.NONE);

            Rsa.Message message = rsa.encrypt(publicKey, data);
            String rawEncryptedData = message.toRawData();
            String encryptedFile = String.format("%s_encrypted.data", dataFile);
            writeToFile(encryptedFile, rawEncryptedData);
        } catch (Exception e) {
            log.severe(String.format("Error encrypting data: %s", e.getMessage()));
        }
    }

    private void decryptData(Properties properties) {
        assert properties.contains("file") && properties.contains("privkey") : "Wrong properties!";

        String dataFile = properties.getProperty("file");
        String publicKeyFile = properties.getProperty("privkey");

        try {
            String data = readFromFile(dataFile);
            String rawPrivateKey = readFromFile(publicKeyFile);
            KeyPair.PrivateKey privateKey = KeyPair.PrivateKey.fromRawData(rawPrivateKey);
            Rsa.Message message = Rsa.Message.fromRawData(data);

            Rsa rsa = new Rsa();
            rsa.setPadding(Padding.valueOf(message.getPadding()));

            String decryptedData = rsa.decrypt(privateKey, message);
            String decryptedFile = String.format("%s_decrypted.data", dataFile);
            writeToFile(decryptedFile, decryptedData);
        } catch (Exception e) {
            log.severe(String.format("Error decrypting data: %s", e.getMessage()));
        }
    }

    private void usage(Properties properties) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("rsa-tool", options);
    }

    private void error(Properties properties) {
        log.severe("Error happened, exiting (-1).");
    }

    private void prepareOptions() {
        Option generateKeyPairOption = Option.builder("k")
                .argName("property=value")
                .numberOfArgs(2)
                .desc("generate key pair to <file>s with selected key <size>")
                .build();
        Option encryptDataOption = Option.builder("e")
                .argName("property=value")
                .numberOfArgs(2)
                .desc("encrypt data from <file> with selected <pubkey>")
                .build();
        Option decryptDataOption = Option.builder("d")
                .argName("property=value")
                .numberOfArgs(2)
                .desc("decrypt data from <file> with selected <privkey>")
                .build();

        options = new Options();
        options.addOption(generateKeyPairOption);
        options.addOption(encryptDataOption);
        options.addOption(decryptDataOption);
    }

    private void setupActionAndProperties(CommandLine line) {
        if (Objects.isNull(line)) {
            action = this::error;
            return;
        }

        boolean propertiesIsCorrect;

        if (line.hasOption("k")) {
            properties = line.getOptionProperties("k");
            propertiesIsCorrect = properties.contains("file") && properties.contains("size");
            action = this::generateKeyPair;
        } else if (line.hasOption("e")) {
            properties = line.getOptionProperties("e");
            propertiesIsCorrect = properties.contains("file")
                    && properties.contains("pubkey")
                    && properties.contains("padding");
            action = this::encryptData;
        } else if (line.hasOption("d")) {
            properties = line.getOptionProperties("d");
            propertiesIsCorrect = properties.contains("file") && properties.contains("privkey");
            action = this::decryptData;
        } else {
            action = this::usage;
            propertiesIsCorrect = true;
            properties = new Properties();
        }

        if (!propertiesIsCorrect) {
            log.severe("Properties is incorrect, please, provide more accurate data!");
            action = this::error;
        }
    }

    private void parseCommandLineArgs(String[] args) {
        CommandLineParser parser = new DefaultParser();
        CommandLine line = null;
        try {
            line = parser.parse(options, args);
        } catch (ParseException e) {
            log.severe(e.getMessage());
            action = this::error;
        }

        setupActionAndProperties(line);
    }
}
