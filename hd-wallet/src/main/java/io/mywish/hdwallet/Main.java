package io.mywish.hdwallet;

import com.mrd.bitlib.crypto.HdKeyNode;
import com.mrd.bitlib.model.hdpath.HdKeyPath;
import com.mrd.bitlib.util.HexUtils;
import org.ethereum.crypto.HashUtil;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class Main {
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

        System.out.print("Enter index: ");
        String indexString = bufferedReader.readLine();
        int index = Integer.parseInt(indexString);
        if (index < 0) {
            throw new Exception("only positive index are available");
        }

        System.out.print("Do you need private key (no/yes): ");
        String yesNo = bufferedReader.readLine();
        boolean isPrivateRequired = "yes".equalsIgnoreCase(yesNo);

        HdKeyNode node = generateForEthereum(passphrase, index, isPrivateRequired);
        System.out.println("Address " + index + ": 0x" + HexUtils.toHex(node.getPublicKey().getAddress()));
        if (node.isPrivateHdKeyNode()) {
            System.out.println("Private " + index + ": 0x" + HexUtils.toHex(node.getPrivateKey().getPrivKeyBytes()));
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
