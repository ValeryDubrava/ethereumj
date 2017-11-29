/*
 * Copyright 2013, 2014 Megion Research & Development GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.mrd.bitlib.crypto;

import com.google.common.base.Preconditions;
import com.mrd.bitlib.model.NetworkParameters;
import com.mrd.bitlib.model.hdpath.HdKeyPath;
import com.mrd.bitlib.util.BitUtils;
import org.bitcoinj.core.Base58;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.crypto.HDUtils;
import org.ethereum.crypto.ECKey;
import org.spongycastle.crypto.digests.SHA3Digest;
import org.spongycastle.math.ec.ECPoint;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

/**
 * Implementation of BIP 32 HD wallet key derivation.
 * <p>
 * https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 */
public class HdKeyNode implements Serializable {

    public static final int HARDENED_MARKER = 0x80000000;

    public static class KeyGenerationException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public KeyGenerationException(String message) {
            super(message);
        }
    }

    private static final String BITCOIN_SEED = "Bitcoin seed";
    private static final int CHAIN_CODE_SIZE = 32;

    private final ECKey ecKey;
    private final byte[] _chainCode;
    private final int _depth;
    private final int _parentFingerprint;
    private final int _index;

    public HdKeyNode(ECKey ecKey, byte[] chainCode, int depth, int parentFingerprint, int index) {
        this.ecKey = ecKey;
//        this.publicKey = ecKey;
        _chainCode = chainCode;
        _depth = depth;
        _parentFingerprint = parentFingerprint;
        _index = index;
    }

    /**
     * Generate a master HD key node from a seed.
     *
     * @param seed
     *           the seed to generate the master HD wallet key from.
     * @return a master HD key node for the seed
     * @throws KeyGenerationException
     *            if the seed is not suitable for seeding an HD wallet key
     *            generation. This is extremely unlikely
     */
    public static HdKeyNode fromSeed(byte[] seed) throws KeyGenerationException {
        Preconditions.checkArgument(seed.length * 8 >= 128, "seed must be larger than 128");
        Preconditions.checkArgument(seed.length * 8 <= 512, "seed must be smaller than 512");
        byte[] I = hmacSha512(asciiStringToBytes(BITCOIN_SEED), seed);

        // Construct private key
        byte[] IL = BitUtils.copyOfRange(I, 0, 32);
        BigInteger k = new BigInteger(1, IL);
        if (k.compareTo(ECKey.CURVE.getN()) >= 0) {
            throw new KeyGenerationException(
                    "An unlikely thing happened: The derived key is larger than the N modulus of the curve");
        }
        if (k.equals(BigInteger.ZERO)) {
            throw new KeyGenerationException("An unlikely thing happened: The derived key is zero");
        }
        ECKey privateKey = ECKey.fromPrivate(IL);

        // Construct chain code
        byte[] IR = BitUtils.copyOfRange(I, 32, 32 + CHAIN_CODE_SIZE);
        return new HdKeyNode(privateKey, IR, 0, 0, 0);
    }

    /**
     * Is this a public or private key node.
     * <p>
     * A private key node can generate both public and private key hierarchies. A
     * public key node can only generate the corresponding public key
     * hierarchies.
     *
     * @return true if this is a private key node, false otherwise.
     */
    public boolean isPrivateHdKeyNode() {
        return ecKey.hasPrivKey();
    }

    /**
     * If this is a private key node, return the corresponding public key node of
     * this node, otherwise return a copy of this node.
     */
    public HdKeyNode getPublicNode() {
        return new HdKeyNode(ECKey.fromPublicOnly(ecKey.getPubKey()), _chainCode, _depth, _parentFingerprint, _index);
    }

    /**
     * Create the child private key of this node with the corresponding index.
     *
     * @param index
     *           the index to use
     * @return the private key corresponding to the specified index
     * @throws KeyGenerationException
     *            if this is not a private key node, or if no key can be created
     *            for this index (extremely unlikely)
     */
    public ECKey createChildPrivateKey(int index) throws KeyGenerationException {
        if (!isPrivateHdKeyNode()) {
            throw new KeyGenerationException("Not a private HD key node");
        }
        return createChildNode(index).ecKey;
    }

    /**
     * Create the child public key of this node with the corresponding index.
     *
     * @param index
     *           the index to use
     * @return the public key corresponding to the specified index
     * @throws KeyGenerationException
     *            if this is a public key node which is hardened, or if no key
     *            can be created for this index (extremely unlikely)
     */
    public ECKey createChildPublicKey(int index) throws KeyGenerationException {
        return createChildNode(index).ecKey;
    }


    /**
     * Create the Bip32 derived child from this KeyNode, according to the keyPath.
     *
     * @param keyPath
     *           the Bip32 Path
     * @return the child node corresponding to the current node + keyPath
     */
    public HdKeyNode createChildNode(HdKeyPath keyPath){
        List<Integer> addrN = keyPath.getAddressN();
        HdKeyNode ak = this;
        for (Integer i : addrN){
            ak = ak.createChildNode(i);
        }
        return ak;
    }

    /**
     * Create the hardened child node of this node with the corresponding index
     *
     * @param index
     *           the index to use
     * @return the child node corresponding to the specified index
     * @throws KeyGenerationException
     *            if this is a public key node which is hardened, or if no key
     *            can be created for this index (extremely unlikely)
     */
    public HdKeyNode createHardenedChildNode(int index) throws KeyGenerationException {
        return createChildNode(index | HARDENED_MARKER);
    }

    /**
     * Create the child node of this node with the corresponding index
     *
     * @param index
     *           the index to use
     * @return the child node corresponding to the specified index
     * @throws KeyGenerationException
     *            if this is a public key node which is hardened, or if no key
     *            can be created for this index (extremely unlikely)
     */
    public HdKeyNode createChildNode(int index) throws KeyGenerationException {
        byte[] data;
        byte[] publicKeyBytes = ecKey.getPubKey();
        if (0 == (index & HARDENED_MARKER)) {
            // Not hardened key
            ByteBuffer writer = ByteBuffer.allocate(publicKeyBytes.length + 4);
            writer.put(publicKeyBytes);
            writer.order(ByteOrder.LITTLE_ENDIAN).putInt(index);
            data = writer.array();
        } else {
            // Hardened key
            if (!isPrivateHdKeyNode()) {
                throw new KeyGenerationException("Cannot generate hardened HD key node from pubic HD key node");
            }
            ByteBuffer writer = ByteBuffer.allocate(33 + 4);
            writer.put((byte) 0);
            writer.put(ecKey.getPrivKeyBytes());
            writer.order(ByteOrder.LITTLE_ENDIAN).putInt(index);
            data = writer.array();
        }
        byte[] l = hmacSha512(_chainCode, data);
        byte[] lL = BitUtils.copyOfRange(l, 0, 32);
        byte[] lR = BitUtils.copyOfRange(l, 32, 64);

        BigInteger m = new BigInteger(1, lL);
        if (m.compareTo(ECKey.CURVE.getN()) >= 0) {
            throw new KeyGenerationException(
                    "An unlikely thing happened: A key derivation parameter is larger than the N modulus of the curve");
        }

        if (isPrivateHdKeyNode()) {

            BigInteger kpar = new BigInteger(1, ecKey.getPrivKeyBytes());
            BigInteger k = m.add(kpar).mod(ECKey.CURVE.getN());
            if (k.equals(BigInteger.ZERO)) {
                throw new KeyGenerationException("An unlikely thing happened: The derived key is zero");
            }

            // Make a 32 byte result where k is copied to the end
            byte[] privateKeyBytes = bigIntegerTo32Bytes(k);
            ECKey key = ECKey.fromPrivate(privateKeyBytes);
            return new HdKeyNode(key, lR, _depth + 1, getFingerprint(), index);
        } else {
            ECPoint q = ECKey.CURVE.getG().multiply(m).add(ecKey.getPubKeyPoint());
            if (q.isInfinity()) {
                throw new KeyGenerationException("An unlikely thing happened: Invalid key point at infinity");
            }
            // ECKey.CURVE.getCurve().createPoint(q.getXCoord().toBigInteger(), q.getYCoord().toBigInteger()).getEncoded()
            ECKey newPublicKey = ECKey.fromPublicOnly(q);
            return new HdKeyNode(newPublicKey, lR, _depth + 1, getFingerprint(), index);
        }
    }

    private byte[] bigIntegerTo32Bytes(BigInteger b) {
        // Returns an array of bytes which is at most 33 bytes long, and possibly
        // with a leading zero
        byte[] bytes = b.toByteArray();
        Preconditions.checkArgument(bytes.length <= 33);
        if (bytes.length == 33) {
            // The result is 32 bytes, but with zero at the beginning, which we
            // strip
            Preconditions.checkArgument(bytes[0] == 0);
            return BitUtils.copyOfRange(bytes, 1, 33);
        }
        // The result is 32 bytes or less, make it 32 bytes with the data at the
        // end
        byte[] result = new byte[32];
        System.arraycopy(bytes, 0, result, result.length - bytes.length, bytes.length);
        return result;
    }

    /**
     * Get the fingerprint of this node
     */
    public int getFingerprint() {
        byte[] hash = ecKey.getAddress();
        int fingerprint = (((int) hash[0]) & 0xFF) << 24;
        fingerprint += (((int) hash[1]) & 0xFF) << 16;
        fingerprint += (((int) hash[2]) & 0xFF) << 8;
        fingerprint += (((int) hash[3]) & 0xFF);
        return fingerprint;
    }

    /**
     * Get the private key of this node
     *
     * @throws KeyGenerationException
     *            if this is not a private key node
     */
    public ECKey getPrivateKey() throws KeyGenerationException {
        if (!isPrivateHdKeyNode()) {
            throw new KeyGenerationException("Not a private HD key node");
        }
        return ecKey;
    }

    /**
     * Get the public key of this node.
     */
    public ECKey getPublicKey() {
        return ecKey;
    }

    private static final byte[] PRODNET_PUBLIC = new byte[] { (byte) 0x04, (byte) 0x88, (byte) 0xB2, (byte) 0x1E };
    private static final byte[] TESTNET_PUBLIC = new byte[] { (byte) 0x04, (byte) 0x35, (byte) 0x87, (byte) 0xCF };
    private static final byte[] PRODNET_PRIVATE = new byte[] { (byte) 0x04, (byte) 0x88, (byte) 0xAD, (byte) 0xE4 };
    private static final byte[] TESTNET_PRIVATE = new byte[] { (byte) 0x04, (byte) 0x35, (byte) 0x83, (byte) 0x94 };

    /**
     * Serialize this node
     */
    public String serialize(NetworkParameters network) throws KeyGenerationException {
        ByteBuffer writer = ByteBuffer.allocate(4 + 1 + 4 + 4 + 32 + 33 + 4);
        if (network.isProdnet()) {
            writer.put(isPrivateHdKeyNode() ? PRODNET_PRIVATE : PRODNET_PUBLIC);
        } else {
            writer.put(isPrivateHdKeyNode() ? TESTNET_PRIVATE : TESTNET_PUBLIC);
        }
        writer.put((byte) (_depth & 0xFF));
        writer.order(ByteOrder.BIG_ENDIAN);
        writer.putInt(_parentFingerprint);
        writer.putInt(_index);
        writer.put(_chainCode);
        if (isPrivateHdKeyNode()) {
            writer.put((byte) 0);
            writer.put(ecKey.getPrivKeyBytes());
        } else {
            writer.put(ecKey.getPubKey());
        }
        byte[] checkSum = Arrays.copyOfRange(Sha256Hash.hashTwice(writer.array(), 0, writer.position()), 0, 4);
        writer.put(checkSum);
        return Base58.encode(writer.array());
    }

    /**
     * Create a node from a serialized string
     *
     * @param string
     *           the string to parse
     * @param network
     *           the network the node is to be used on
     * @return a HD wallet key node
     * @throws KeyGenerationException
     *            if there is an error parsing the string to a HD wallet key node
     *            on the specified network
     */
    public static HdKeyNode parse(String string, NetworkParameters network) throws KeyGenerationException {
        try {
            byte[] bytes = Base58.decodeChecked(string);
            if (bytes == null) {
                throw new KeyGenerationException("Invalid checksum");
            }
            if (bytes.length != 78) {
                throw new KeyGenerationException("Invalid size");
            }
            ByteBuffer reader = ByteBuffer.wrap(bytes);
            boolean isPrivate;
            byte[] magic = new byte[4];
            reader.get(magic);
            if (BitUtils.areEqual(magic, PRODNET_PRIVATE)) {
                if (!network.isProdnet()) {
                    throw new KeyGenerationException("Invalid network");
                }
                isPrivate = true;
            } else if (BitUtils.areEqual(magic, PRODNET_PUBLIC)) {
                if (!network.isProdnet()) {
                    throw new KeyGenerationException("Invalid network");
                }
                isPrivate = false;
            } else if (BitUtils.areEqual(magic, TESTNET_PRIVATE)) {
                if (network.isProdnet()) {
                    throw new KeyGenerationException("Invalid network");
                }
                isPrivate = true;
            } else if (BitUtils.areEqual(magic, TESTNET_PUBLIC)) {
                if (network.isProdnet()) {
                    throw new KeyGenerationException("Invalid network");
                }
                isPrivate = false;
            } else {
                throw new KeyGenerationException("Invalid magic header for HD key node");
            }

            int depth = ((int) reader.get()) & 0xFF;
            reader.order(ByteOrder.BIG_ENDIAN);
            int parentFingerprint = reader.getInt();
            int index = reader.getInt();
            byte[] chainCode = new byte[CHAIN_CODE_SIZE];
            reader.get(chainCode);
            if (isPrivate) {
                if (reader.get() != (byte) 0x00) {
                    throw new KeyGenerationException("Invalid private key");
                }
                byte[] privateKeyBytes = new byte[32];
                reader.get(privateKeyBytes);
                ECKey privateKey = ECKey.fromPrivate(privateKeyBytes);
                return new HdKeyNode(privateKey, chainCode, depth, parentFingerprint, index);
            } else {
                byte[] publicKeyBytes = new byte[33];
                reader.get(publicKeyBytes);
                ECKey publicKey = ECKey.fromPublicOnly(publicKeyBytes);
                return new HdKeyNode(publicKey, chainCode, depth, parentFingerprint, index);
            }
        } catch (Exception e) {
            throw new KeyGenerationException("Insufficient bytes in serialization");
        }
    }

    @Override
    public String toString() {
        return "Fingerprint: " + Integer.toString(getFingerprint());
    }

    private static byte[] asciiStringToBytes(String string) {
        try {
            return string.getBytes("US-ASCII");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException();
        }
    }

    @Override
    public int hashCode() {
        return ecKey.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof HdKeyNode)) {
            return false;
        }
        HdKeyNode other = (HdKeyNode) obj;
        if (!this.ecKey.equals(other.ecKey)) {
            return false;
        }
        if (this._depth != other._depth) {
            return false;
        }
        if (this._parentFingerprint != other._parentFingerprint) {
            return false;
        }
        if (this._index != other._index) {
            return false;
        }
        if (!BitUtils.areEqual(this._chainCode, other._chainCode)) {
            return false;
        }
        return this.isPrivateHdKeyNode() == other.isPrivateHdKeyNode();
    }

    // returns the own index of this key
    public int getIndex(){
        return _index;
    }

    // returns the parent fingerprint
    public int getParentFingerprint(){
        return _parentFingerprint;
    }

    // return the hierarchical depth of this node
    public int getDepth(){
        return _depth;
    }


    // generate internal uuid from public key of the HdKeyNode
    public UUID getUuid() {
        // Create a UUID from the byte indexes 8-15 and 16-23 of the account public key
        byte[] publicKeyBytes = this.getPublicKey().getPrivKeyBytes();
        return new UUID(BitUtils.uint64ToLong(publicKeyBytes, 8), BitUtils.uint64ToLong(
                publicKeyBytes, 16));
    }

    private static byte[] hmacSha512(byte[] key, byte[] seed) {
        return HDUtils.hmacSha512(key, seed);
    }
}