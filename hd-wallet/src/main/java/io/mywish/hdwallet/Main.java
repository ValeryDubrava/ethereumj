package io.mywish.hdwallet;

import com.mrd.bitlib.crypto.HdKeyNode;
import com.mrd.bitlib.model.NetworkParameters;
import com.mrd.bitlib.model.hdpath.HdKeyPath;
import com.mrd.bitlib.util.HexUtils;
import com.mrd.bitlib.util.KeyConverter;
import org.ethereum.crypto.HashUtil;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class Main {
    private final static KeyConverter keyConverter = new KeyConverter();
    private final static Charset CHARSET = Charset.forName("US-ASCII");

    public static void main(String[] args) throws Exception {
        interact();
    }

    private static void interact() throws Exception {
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));
        System.out.print("Chose mode: (p)assphrase, (e)xt public key: ");
        String modeString = bufferedReader.readLine();
        Mode mode = Mode.PASSPHRASE;
        if (modeString.startsWith("e")) {
            mode = Mode.EXT_PUB;
        }
        else if (modeString.startsWith("p")) {
            mode = Mode.PASSPHRASE;
        }
        else {
            System.out.println("Wrong value, use passphrase by default.");
        }

        String passphrase;
        HdKeyNode root;
        if (mode == Mode.PASSPHRASE) {
            System.out.print("Enter passphrase: ");
            passphrase = bufferedReader.readLine();
            if (passphrase == null || passphrase.isEmpty()) {
                throw new Exception("empty passphrase");
            }
            root = generateRootNode(passphrase);
        }
        else if (mode == Mode.EXT_PUB) {
            System.out.print("Enter ex key: ");
            String exKeyString = bufferedReader.readLine();
            if (exKeyString == null || exKeyString.isEmpty()) {
                throw new Exception("empty ex key string");
            }
            try {
                HdKeyNode exKey = HdKeyNode.parse(exKeyString, NetworkParameters.productionNetwork);
                root = exKey.createChildNode(HdKeyPath.valueOf("m"));
            }
            catch (Exception ex) {
                throw new Exception("Parsing error.", ex);
            }
        }
        else {
            throw new Exception("Unknown mode.");
        }

        System.out.print("Enter start index: ");
        String indexString = bufferedReader.readLine();
        int index = Integer.parseInt(indexString);
        if (index < 0) {
            throw new Exception("only positive index are available");
        }

        System.out.print("Enter count (1): ");
        String countString = bufferedReader.readLine();
        int count = 1;
        if (countString != null && !countString.isEmpty()) {
            count = Integer.parseInt(countString);
        }
        if (count < 1) {
            count = 1;
        }

        System.out.print("Available modes: ");
        final Mode finalMode = mode;
        System.out.println(
                EnumSet.allOf(OutputMode.class)
                        .stream()
                        .filter(outputMode -> finalMode != Mode.EXT_PUB || outputMode != OutputMode.PRIVATE)
                        .map(Enum::name)
                        .map(String::toLowerCase)
                        .collect(Collectors.joining(", "))
        );
        System.out.print("Please, chose on or several: ");
        String modesString = bufferedReader.readLine();
        Set<OutputMode> outputModes = Stream.of(modesString.split("[\\s,\\.]"))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(String::toUpperCase)
                .map(s -> {
                    try {
                        return OutputMode.valueOf(s);
                    }
                    catch (Exception ignored) {
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());

        System.out.println("Extended Public Key: " + root.getPublicNode().serialize(NetworkParameters.productionNetwork));

        for (int i = index; i < count + index; i++) {
            HdKeyNode node = generateChildren(root, i);
            if (outputModes.contains(OutputMode.ETH) || outputModes.contains(OutputMode.ALL_PUBLIC)) {
                System.out.println("ETH Address " + i + ": 0x" + HexUtils.toHex(node.getPublicKey().getAddress()));
            }
            if (outputModes.contains(OutputMode.RAW) || outputModes.contains(OutputMode.ALL_PUBLIC)) {
                System.out.println("Public key " + i + ": 0x" + HexUtils.toHex(node.getPublicKey().getPubKeyPoint().getEncoded(true)));
            }
            if (outputModes.contains(OutputMode.EOS) || outputModes.contains(OutputMode.ALL_PUBLIC)) {
                System.out.println("EOS Public key " + i + ": " + keyConverter.toEosPubKey(node.getPublicKey()));
            }
            if (outputModes.contains(OutputMode.TRON) || outputModes.contains(OutputMode.ALL_PUBLIC)) {
                System.out.println("TRON Public key " + i + ": " + keyConverter.toTronPubKeyFromEth(node.getPublicKey()));
            }
            if (node.isPrivateHdKeyNode() && (outputModes.contains(OutputMode.PRIVATE))) {
                if (outputModes.contains(OutputMode.ETH) || outputModes.contains(OutputMode.TRON) || outputModes.contains(OutputMode.RAW)) {
                    System.out.println("Private " + i + ": 0x" + HexUtils.toHex(node.getPrivateKey().getPrivKeyBytes()));
                }
                if (outputModes.contains(OutputMode.EOS)) {
                    System.out.println("EOS (WIF) Private " + i + ": " + keyConverter.toWif(node.getPrivateKey()));
                }
            }
        }

    }

    public static HdKeyNode generateRootNode(String passphrase) throws UnsupportedEncodingException {
        HdKeyPath path = HdKeyPath.valueOf("m/44'/60'/0'/0");
        HdKeyNode root = HdKeyNode.fromSeed(HashUtil.sha3(passphrase.getBytes(CHARSET)));
        return root.createChildNode(path);
    }

    private static HdKeyNode generateChildren(HdKeyNode node, int index) {
        return node.createChildNode(index);
    }

    enum Mode {
        PASSPHRASE,
        EXT_PUB,
    }

    enum OutputMode {
        ETH,
        EOS,
        RAW,
        TRON,
        PRIVATE,
        ALL_PUBLIC
    }
}
