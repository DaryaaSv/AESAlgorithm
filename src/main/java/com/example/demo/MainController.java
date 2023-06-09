package com.example.demo;

import com.example.demo.JavaCode.AESCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.security.Security;

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
                           @RequestParam(name = "to_file_system", required = false) String toFile,
                           @RequestParam(name = "file", required = false) MultipartFile file,
                           Model model
    ) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        if(!file.isEmpty()) {
            String filePath = file.getOriginalFilename();
            File fileInput = new File(filePath);
            FileReader fileReader = new FileReader(fileInput);
            BufferedReader bufferedReader = new BufferedReader(fileReader);
            String line = bufferedReader.readLine();
            plain_text = line;
            bufferedReader.close();
            fileReader.close();
        }
        if(function.equals("encryption")) result = AESCipher.encrypt(plain_text, key, iv, selectedValue);
        else if(function.equals("decryption"))  result = AESCipher.decrypt(plain_text, key, iv, selectedValue);

        if(toFile != null) {
            FileWriter writer = new FileWriter("C:\\Users\\Dasha\\IdeaProjects\\demo2\\output.txt", false);
            writer.write(result);
            writer.close();
        }

        return "redirect:/";
    }
}
