package ua.edu.sumdu.crypto.levchenko.rsatool;

import org.apache.commons.cli.*;

import java.util.logging.Logger;

public class Main {
    private final static Logger log = Logger.getLogger(Main.class.getName());

    private static void generateKeyPair(int keySize, String name) {

    }

    private static void encryptData(String publicKeyFilename, String dataFilename) {

    }

    private static void decryptData(String privateKeyFilename, String dataFilename) {

    }

    private static void usage() {

    }

    public static void main(String[] args) {
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

        Options options = new Options();
        options.addOption(generateKeyPairOption);
        options.addOption(encryptDataOption);
        options.addOption(decryptDataOption);

        CommandLineParser parser = new DefaultParser();
        try {
            CommandLine line = parser.parse(options, args);
            if (line.hasOption("k")) {

            } else if (line.hasOption("e")) {

            } else if (line.hasOption("d")) {

            } else {
                usage();
            }
        } catch (ParseException e) {
            log.severe(e.getMessage());
        }
    }
}
