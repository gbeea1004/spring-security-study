package com.geonhee.springsecuritystudy.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    @GetMapping
    public String home() {
        return "OK";
    }

    @GetMapping("loginPage")
    public String loginPage() {
        return "loginPage";
    }
}
