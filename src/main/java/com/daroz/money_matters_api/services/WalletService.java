package com.daroz.money_matters_api.services;

import org.springframework.stereotype.Service;

@Service
public class WalletService {

    public String getWalletByEmail() {
        return "Unimplemented method 'getWalletByEmail'";
    }

    public void createWallet() {
        System.out.println("Creating wallet");
    }

    public void updateWallet(Double value) {
        System.out.println("Wallet value received: " + value);
    }

}
