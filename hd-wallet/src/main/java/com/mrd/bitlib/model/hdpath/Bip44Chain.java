package com.mrd.bitlib.model.hdpath;


import java.util.Optional;

public class Bip44Chain extends Bip44Account {

    public Bip44Chain(Bip44Account parent, Long index, boolean hardened) {
        super(parent, index, hardened);
    }

    public Bip44Address getAddress(Long index){
        return new Bip44Address(this, index, false);
    }
    public Bip44Address getAddress(int index){
        return new Bip44Address(this, Long.valueOf(index), false);
    }

    public boolean isExternal(){
        Optional<Bip44Chain> chainType = findPartOf(Bip44Chain.class);
        if (chainType.isPresent()) {
            return chainType.get().index.intValue() == 0;
        }else{
            throw new RuntimeException("No chaintyp present");
        }

    }

    @Override
    protected HdKeyPath knownChildFactory(Long index, boolean hardened) {
        if (!hardened){
            return  new Bip44Address(this, index, false);
        }else{
            return new HdKeyPath(this, index, hardened);
        }
    }
}