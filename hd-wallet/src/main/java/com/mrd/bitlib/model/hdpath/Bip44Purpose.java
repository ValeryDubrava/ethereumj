package com.mrd.bitlib.model.hdpath;

import com.mrd.bitlib.model.NetworkParameters;


public class Bip44Purpose extends HdKeyPath {
    public Bip44Purpose(HdKeyPath parent, Long index, boolean hardened) {
        super(parent, index, hardened);
    }

    public Bip44CoinType getCoinTypeBitcoin(){
        return  new Bip44CoinType(this, 0L, true);
    }

    public Bip44CoinType getCoinTypeBitcoinTestnet(){
        return  new Bip44CoinType(this, 1L, true);
    }

    public Bip44CoinType getCoinTypeBitcoin(boolean testnet){
        if (testnet){
            return getCoinTypeBitcoinTestnet();
        }else{
            return getCoinTypeBitcoin();
        }
    }

    public Bip44CoinType getBip44CoinType(NetworkParameters forNetwork){
        return getCoinTypeBitcoin(forNetwork.isTestnet());
    }

    @Override
    protected HdKeyPath knownChildFactory(Long index, boolean hardened) {
        if (hardened) {
            return new Bip44CoinType(this, index, true);
        } else {
            return new HdKeyPath(this, index, hardened);
        }
    }
}