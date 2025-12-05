package com.github.xsluck;

import java.io.StringReader;
import java.security.PrivateKey;
import java.security.Security;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import com.github.xsluck.utils.JceGmPKCS8DecryptorProviderBuilder;

public class TestSignVerify {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        String encryptedKeyPem = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
                + "                MIIBBjBhBgkqhkiG9w0BBQ0wVDA0BgkqhkiG9w0BBQwwJwQQ1AaLX5C6wk9j7pgn\n"
                + "                KnwmtwIDAQAAAgEQMAsGCSqBHM9VAYMRAjAcBggqgRzPVQFoAgQQKR42A1uEeRC6\n"
                + "                m7OZRXbd7gSBoN7VTM3WxD2zVVQRCzR3FzfbowoW6cFizWEQ7aeEC3u6UsamlXfX\n"
                + "                UL1XZBJLgF9Nxg3IQh9E8IpJS2HEKuImnubHecrlUYEo9ueIOk32gGMkuOoA2MTv\n"
                + "                KKvvpwqOikHTs0s8H8ZLHMndyR3HskEh0FCHlOViqEb6WNHnY/f1o28yjUxbBPUf\n"
                + "                0hkk6XTn2DmfRVqtWCI6s/EsL1ZHkQWcI+w=\n"
                + "                -----END ENCRYPTED PRIVATE KEY-----";

        String password = "Secure@2025"; // 替换为你自己的密码
        PemReader pemReader = new PemReader(new StringReader(encryptedKeyPem));
        PemObject pemObject = pemReader.readPemObject();
        PKCS8EncryptedPrivateKeyInfo pkcs8EncryptedPrivateKeyInfo = new PKCS8EncryptedPrivateKeyInfo(pemObject.getContent());
        JceGmPKCS8DecryptorProviderBuilder jce = new JceGmPKCS8DecryptorProviderBuilder();
        InputDecryptorProvider decProv = jce.build(password.toCharArray());
        PrivateKeyInfo pki = pkcs8EncryptedPrivateKeyInfo.decryptPrivateKeyInfo(decProv);

        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        PrivateKey prv = converter.getPrivateKey(pki);
        System.out.println(prv.getClass() + ": " + prv);
    }
}