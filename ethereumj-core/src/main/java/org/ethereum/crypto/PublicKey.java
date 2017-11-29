package org.ethereum.crypto;

import org.spongycastle.math.ec.ECPoint;

public interface PublicKey {
    byte[] getPubKey();
    ECPoint getPubKeyPoint();
    byte[] getAddress();
}
