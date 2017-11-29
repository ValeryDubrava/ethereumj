package com.mrd.bitlib.model.hdpath;

public class Bip44Address extends Bip44Chain {
    public Bip44Address(Bip44Chain parent, Long index, boolean hardened) {
        super(parent, index, hardened);
    }

    @Override
    protected HdKeyPath knownChildFactory(Long index, boolean hardened) {
        throw new RuntimeException("Bip44 allows no childs below addresses");
    }
}