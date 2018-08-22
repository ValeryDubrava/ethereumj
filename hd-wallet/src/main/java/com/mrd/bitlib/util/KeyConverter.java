package com.mrd.bitlib.util;

import org.bitcoinj.core.Base58;
import org.ethereum.crypto.ECKey;
import org.spongycastle.crypto.digests.GeneralDigest;
import org.spongycastle.crypto.digests.RIPEMD160Digest;
import org.spongycastle.crypto.digests.SHA256Digest;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class KeyConverter {
    /**
     * More info at https://en.bitcoin.it/wiki/Wallet_import_format
     *
     * @param ecKey        Elliptic Curve key container with private key.
     * @param isProduction Is key for production environment or testnet.
     * @return Private key in WIF (WEF) format.
     */
    public String toWif(ECKey ecKey, boolean isProduction) {
        byte[] keyBytes = ecKey.getPrivKeyBytes();
        if (keyBytes == null) {
            throw new IllegalArgumentException("ecKey must be private key");
        }
        return toWif(keyBytes, isProduction);
    }

    public String toWif(byte[] keyBytes, boolean isProduction, GeneralDigest digest) {
        return toWif(keyBytes, (byte) (isProduction ? 0x80 : 0xEF), digest);
    }

    public String toWif(byte[] keyBytes, byte prefix, GeneralDigest digest) {
        ByteBuffer buffer = ByteBuffer.wrap(new byte[keyBytes.length + 5]);
        buffer.put(prefix);
        buffer.put(keyBytes);

        byte[] digestBytes = calcDigest(buffer.array(), 0, keyBytes.length + 1, digest,true);
        buffer.put(digestBytes, 0, 4);

        return Base58.encode(buffer.array());
    }

    public String toWif(byte[] keyBytes, boolean isProduction) {
        return toWif(keyBytes, isProduction, new SHA256Digest());
    }

    public String toWif(ECKey ecKey) {
        return toWif(ecKey, true);
    }

    public String toEosPubKey(ECKey ecKey) {
        byte[] keyBytes = ecKey.getPubKeyPoint().getEncoded(true);
        byte[] digest = calcDigest(keyBytes, 0, keyBytes.length, new RIPEMD160Digest(), false);
        byte[] result = new byte[keyBytes.length + 4];
        System.arraycopy(keyBytes, 0, result, 0, keyBytes.length);
        System.arraycopy(digest, 0, result, keyBytes.length, 4);
        return "EOS" + Base58.encode(result);
    }

    public ECKey fromEosPubKey(String publicKey) {
        if (!publicKey.startsWith("EOS")) {
            throw new IllegalArgumentException("publicKey wrong format, it must be prefixed EOS");
        }

        byte[] keyWithCheckSum = Base58.decode(publicKey.substring(3));

        byte[] digest = calcDigest(keyWithCheckSum, 0, keyWithCheckSum.length - 4, new RIPEMD160Digest(), false);

        for (int i = 0; i < 4; i ++) {
            if (digest[i] != keyWithCheckSum[keyWithCheckSum.length - 5 + i]) {
                throw new IllegalStateException("checksum mismatch");
            }
        }

        byte[] key = new byte[keyWithCheckSum.length - 4];
        System.arraycopy(keyWithCheckSum, 0, key, 0, key.length);

        return ECKey.fromPublicOnly(key);
    }

    private byte[] calcDigest(byte[] exKey, int offset, int length, GeneralDigest digest, boolean secondPass) {
        digest.update(exKey, offset, length);
        byte[] digestFirstPass = new byte[digest.getDigestSize()];
        digest.doFinal(digestFirstPass, 0);
        digest.reset();
        if (!secondPass) {
            return digestFirstPass;
        }

        byte[] digestSecondPass = new byte[digest.getDigestSize()];
        digest.update(digestFirstPass, 0, digestFirstPass.length);
        digest.doFinal(digestSecondPass, 0);
        return digestSecondPass;
    }
}
