package io.mywish.hdwallet;

import com.mrd.bitlib.crypto.HdKeyNode;
import com.mrd.bitlib.model.hdpath.HdKeyPath;
import com.mrd.bitlib.util.HexUtils;
import com.mrd.bitlib.util.KeyConverter;
import org.ethereum.crypto.HashUtil;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class Main {
    private final static KeyConverter keyConverter = new KeyConverter();

    public static void main(String[] args) throws Exception {
        interact();
    }

    private static void interact() throws Exception {
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));
        System.out.print("Enter passphrase: ");
        String passphrase = bufferedReader.readLine();
        if (passphrase == null || passphrase.isEmpty()) {
            throw new Exception("empty passphrase");
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

        System.out.print("Do you need private key (no/yes): ");
        String yesNo = bufferedReader.readLine();
        boolean isPrivateRequired = "yes".equalsIgnoreCase(yesNo);

        for (int i = index; i < count + index; i ++) {
            HdKeyNode node = generateForEthereum(passphrase, i, isPrivateRequired);
            System.out.println("ETH Address " + i + ": 0x" + HexUtils.toHex(node.getPublicKey().getAddress()));
            System.out.println("Public key " + i + ": 0x" + HexUtils.toHex(node.getPublicKey().getPubKey()));
            System.out.println("EOS Public key " + i + ": " + keyConverter.toEosPubKey(node.getPublicKey()));
            if (node.isPrivateHdKeyNode()) {
                System.out.println("ETH Private " + i + ": 0x" + HexUtils.toHex(node.getPrivateKey().getPrivKeyBytes()));
                System.out.println("EOS Private " + i + ": " + keyConverter.toWif(node.getPrivateKey()));
            }
        }

    }

    private static HdKeyNode generateForEthereum(String passphrase, int index, boolean isPrivate) throws Exception {
        HdKeyPath path = HdKeyPath.valueOf("m/44'/60'/0'/0");
        HdKeyNode node = HdKeyNode.fromSeed(HashUtil.sha3(passphrase.getBytes("US-ASCII")));
        HdKeyNode parent = node.createChildNode(path);
        if (!isPrivate) {
            parent = parent.getPublicNode();
        }

        return parent.createChildNode(index);
    }
}
