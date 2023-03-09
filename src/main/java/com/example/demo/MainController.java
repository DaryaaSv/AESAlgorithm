package com.example.demo;

import com.example.demo.JavaCode.AESCipher;
import org.apache.commons.codec.DecoderException;
import org.springframework.stereotype.Controller;
import org.apache.commons.codec.binary.Hex;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

@Controller
public class MainController {
    String result = "";
    @GetMapping("/")
    public String Main(Model model) {
        model.addAttribute("result", result);
        return "index";
    }
    @PostMapping("/")
    public String postMain(@RequestParam() String plain_text,
                           @RequestParam() String key,
                           @RequestParam() String iv,
                           @RequestParam("function") String function,
                           @RequestParam("block_cipher") String selectedValue,
                           @RequestParam("to_file_system") String toFile,
                           Model model
    ) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        if(function.equals("encryption")) {
            result = AESCipher.encrypt(plain_text, key, iv, selectedValue);
        }
        else if(function.equals("decryption")) {
            result = AESCipher.decrypt(plain_text, key, iv, selectedValue);
        }

        if(toFile.equals("on")) {
            FileWriter writer = new FileWriter("C:/Users/Dasha/output.txt", false);
            writer.write(result);
            writer.close();
        }

        return "redirect:/";
    }
}
