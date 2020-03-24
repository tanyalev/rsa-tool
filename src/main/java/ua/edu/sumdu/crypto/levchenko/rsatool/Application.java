package ua.edu.sumdu.crypto.levchenko.rsatool;

import org.apache.commons.cli.*;
import ua.edu.sumdu.crypto.levchenko.rsatool.rsa.KeyPair;
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
            log.info(String.format("\"%s\" file has been created.", file));
        } else {
            log.warning(String.format("\"%s\" file already exists.", file));
        }

        try (FileWriter fileWriter = new FileWriter(file)) {
            fileWriter.write(data);
        }
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
        boolean usePadding = Boolean.parseBoolean(properties.getProperty("padding"));

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
        Option fileRequiredOption = Option.builder("f")
                .hasArg()
                .argName("file name")
                .desc("file name for a different reason")
                .build();
        Option generateKeyPairOption = Option.builder("k")
                .hasArg()
                .argName("key size")
                .desc("generate key pair to <file>s with selected key <size>")
                .build();
        Option encryptDataOption = Option.builder("e")
                .hasArg()
                .argName("public key file name")
                .desc("encrypt data from <file> with selected <pubkey>")
                .build();
        Option decryptDataOption = Option.builder("d")
                .hasArg()
                .argName("private key file name")
                .desc("decrypt data from <file> with selected <privkey>")
                .build();
        Option usePaddingOption = Option.builder("p")
                .hasArg(false)
                .required(false)
                .desc("use PKCS #1 padding (for encryption)")
                .build();
        Option helpOption = Option.builder("h")
                .hasArg(false)
                .required(false)
                .desc("print usage message")
                .build();

        options = new Options();
        options.addOption(fileRequiredOption);
        options.addOption(generateKeyPairOption);
        options.addOption(encryptDataOption);
        options.addOption(decryptDataOption);
        options.addOption(usePaddingOption);
        options.addOption(helpOption);
    }

    private Consumer<Properties> setupPropertiesForAction(CommandLine line) {
        if (Objects.isNull(line)) {
            return this::error;
        }

        if (line.hasOption("h")) {
            return this::usage;
        }

        properties = new Properties();

        if (line.hasOption("f")) {
            String file = line.getOptionValue("f");
            properties.setProperty("file", file);
        }

        if (line.hasOption("k")) {
            String keySize = line.getOptionValue("k");
            properties.setProperty("size", keySize);
            return this::generateKeyPair;
        }

        properties.setProperty("padding", Boolean.toString(line.hasOption("p")));

        if (line.hasOption("e")) {
            String publicKeyFile = line.getOptionValue("e");
            properties.setProperty("pubkey", publicKeyFile);
            return this::encryptData;
        }

        if (line.hasOption("d")) {
            String privateKeyFile = line.getOptionValue("d");
            properties.setProperty("privkey", privateKeyFile);
            return this::decryptData;
        }

        return this::usage;
    }

    private void parseCommandLineArgs(String[] args) {
        try {
            CommandLineParser parser = new DefaultParser();
            CommandLine line = parser.parse(options, args);
            action = setupPropertiesForAction(line);
        } catch (ParseException e) {
            log.severe(e.getMessage());
            action = this::error;
        }
    }
}
