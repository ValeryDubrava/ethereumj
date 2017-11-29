package com.mrd.bitlib.model.hdpath;

public class Bip44Account extends Bip44CoinType {
    public Bip44Account(Bip44CoinType parent, Long index, boolean hardened) {
        super(parent, index, hardened);
    }

    public Bip44Chain getChain(boolean external){
        return new Bip44Chain(this, Long.valueOf(external ? 0 : 1), false);
    }

    public Bip44Chain getInternalChain(){
        return getChain(false);
    }

    public Bip44Chain getExternalChain(){
        return getChain(true);
    }

    @Override
    protected HdKeyPath knownChildFactory(Long index, boolean hardened) {
        if (!hardened){
            return  new Bip44Chain(this, index, false);
        }else{
            return new HdKeyPath(this, index, hardened);
        }
    }
}