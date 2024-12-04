package com.daroz.money_matters_api.resources;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.daroz.money_matters_api.services.WalletService;

@RestController
@RequestMapping("/wallet")
public class WalletResource {

    @Autowired
    private WalletService walletService;

    @GetMapping
    public String getWalletByEmail(@RequestParam String email) {
        return walletService.getWalletByEmail();
    }

}