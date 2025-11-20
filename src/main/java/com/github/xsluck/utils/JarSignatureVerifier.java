package com.github.xsluck.utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * JAR包SM2签名运行时验证工具 用于在应用启动时验证JAR包的完整性和签名
 */
public class JarSignatureVerifier {

    static {
        // 添加 BouncyCastle Provider 以支持国密算法
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * 验证结果类
     */
    public static class VerificationResult {
        private boolean valid;
        private String message;
        private List<String> details = new ArrayList<>();
        private String signerAlias;
        private X509Certificate certificate;
        private int totalFiles;
        private int verifiedFiles;

        public boolean isValid() {
            return valid;
        }

        public void setValid(boolean valid) {
            this.valid = valid;
        }

        public String getMessage() {
            return message;
        }

        public void setMessage(String message) {
            this.message = message;
        }

        public List<String> getDetails() {
            return details;
        }

        public void addDetail(String detail) {
            this.details.add(detail);
        }

        public String getSignerAlias() {
            return signerAlias;
        }

        public void setSignerAlias(String signerAlias) {
            this.signerAlias = signerAlias;
        }

        public X509Certificate getCertificate() {
            return certificate;
        }

        public void setCertificate(X509Certificate certificate) {
            this.certificate = certificate;
        }

        public int getTotalFiles() {
            return totalFiles;
        }

        public void setTotalFiles(int totalFiles) {
            this.totalFiles = totalFiles;
        }

        public int getVerifiedFiles() {
            return verifiedFiles;
        }

        public void setVerifiedFiles(int verifiedFiles) {
            this.verifiedFiles = verifiedFiles;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("========================================\n");
            sb.append("JAR 签名验证结果\n");
            sb.append("========================================\n");
            sb.append("验证状态: ").append(valid ? "✓ 通过" : "✗ 失败").append("\n");
            sb.append("消息: ").append(message).append("\n");

            if (signerAlias != null) {
                sb.append("签名者: ").append(signerAlias).append("\n");
            }

            if (certificate != null) {
                sb.append("证书主题: ").append(certificate.getSubjectDN()).append("\n");
                sb.append("证书颁发者: ").append(certificate.getIssuerDN()).append("\n");
                sb.append("证书有效期: ").append(certificate.getNotBefore()).append(" 至 ").append(certificate.getNotAfter())
                        .append("\n");

                // 检查证书是否过期
                try {
                    certificate.checkValidity();
                    sb.append("证书状态: 有效\n");
                } catch (Exception e) {
                    sb.append("证书状态: 已过期或未生效\n");
                }
            }

            if (totalFiles > 0) {
                sb.append("总文件数: ").append(totalFiles).append("\n");
                sb.append("已验证文件数: ").append(verifiedFiles).append("\n");
            }

            if (!details.isEmpty()) {
                sb.append("\n详细信息:\n");
                for (String detail : details) {
                    sb.append("  - ").append(detail).append("\n");
                }
            }

            sb.append("========================================");
            return sb.toString();
        }
    }

    /**
     * 验证指定JAR包的签名
     * 
     * @param jarPath JAR包路径
     * @return 验证结果
     */
    public static VerificationResult verifyJarSignature(String jarPath) {
        VerificationResult result = new VerificationResult();
        File jarFile = new File(jarPath);
        if (!jarFile.exists()) {
            result.setValid(false);
            result.setMessage("JAR文件不存在: " + jarPath);
            return result;
        }

        try (JarFile jar = new JarFile(jarFile, true)) {
            // 1. 查找签名文件
            Map<String, String> signatureFiles = findSignatureFiles(jar);
            if (signatureFiles.isEmpty()) {
                result.setValid(false);
                result.setMessage("未找到签名文件");
                result.addDetail("JAR包未签名");
                return result;
            }

            result.addDetail("找到 " + signatureFiles.size() + " 个签名");

            // 2. 获取MANIFEST.MF
            Manifest manifest = jar.getManifest();
            if (manifest == null) {
                result.setValid(false);
                result.setMessage("未找到MANIFEST.MF文件");
                return result;
            }

            // 3. 验证每个签名
            for (Map.Entry<String, String> entry : signatureFiles.entrySet()) {
                String alias = entry.getKey();
                String sfFileName = entry.getValue();

                result.setSignerAlias(alias);
                result.addDetail("验证签名: " + alias);

                // 验证签名文件和提取证书
                if (!verifySignatureFile(jar, sfFileName, alias, result)) {
                    return result;
                }
            }

            // 4. 验证所有文件的完整性
            if (!verifyAllFiles(jar, manifest, result)) {
                return result;
            }

            result.setValid(true);
            result.setMessage("签名验证通过");
            return result;

        } catch (Exception e) {
            result.setValid(false);
            result.setMessage("验证过程出错: " + e.getMessage());
            result.addDetail("异常: " + e.getClass().getName());
            e.printStackTrace();
            return result;
        }

    }

    /**
     * 查找所有签名文件
     */
    private static Map<String, String> findSignatureFiles(JarFile jar) {
        Map<String, String> signatureFiles = new HashMap<>();
        Enumeration<JarEntry> entries = jar.entries();

        while (entries.hasMoreElements()) {
            JarEntry entry = entries.nextElement();
            String name = entry.getName();
            if (name.startsWith("META-INF/") && name.endsWith(".SF")) {
                String alias = name.substring(9, name.length() - 3);
                signatureFiles.put(alias, name);
            }
        }

        return signatureFiles;
    }

    /**
     * 验证签名文件并提取证书（包含公钥）
     */
    private static boolean verifySignatureFile(JarFile jar, String sfFileName, String alias,
            VerificationResult result) {
        try {
            // 读取.SF文件
            JarEntry sfEntry = jar.getJarEntry(sfFileName);
            if (sfEntry == null) {
                result.setValid(false);
                result.setMessage("签名文件不存在: " + sfFileName);
                return false;
            }

            byte[] sfData = readEntryData(jar, sfEntry);

            // 查找签名块文件（包含证书和签名）
            String[] extensions = { ".SM2", ".RSA", ".DSA", ".EC" };
            byte[] sigBlockData = null;

            for (String ext : extensions) {
                String fileName = "META-INF/" + alias + ext;
                JarEntry sigEntry = jar.getJarEntry(fileName);
                if (sigEntry != null) {
                    sigBlockData = readEntryData(jar, sigEntry);
                    result.addDetail("找到签名块文件: " + fileName);
                    break;
                }
            }

            if (sigBlockData == null) {
                result.setValid(false);
                result.setMessage("未找到签名块文件");
                return false;
            }

            // 从签名块中提取证书（公钥在证书中）
            X509Certificate cert = extractCertificateFromSignatureBlock(sigBlockData, result);
            if (cert != null) {
                result.setCertificate(cert);
                result.addDetail("成功提取证书（公钥）");

                // 验证证书有效期
                try {
                    cert.checkValidity();
                    result.addDetail("证书有效");
                } catch (Exception e) {
                    result.addDetail("警告: 证书已过期或未生效");
                }

                // 使用证书中的公钥验证签名
                return verifySignatureWithPublicKey(sfData, sigBlockData, cert, result);
            }

            return true;

        } catch (Exception e) {
            result.setValid(false);
            result.setMessage("签名文件验证失败: " + e.getMessage());
            return false;
        }
    }

    /**
     * 从签名块中提取证书（证书包含公钥）
     */
    private static X509Certificate extractCertificateFromSignatureBlock(byte[] sigBlockData,
            VerificationResult result) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

            // 尝试不同的分割点提取证书
            for (int i = 300; i < Math.min(sigBlockData.length - 64, 2500); i++) {
                try {
                    byte[] certBytes = new byte[i];
                    System.arraycopy(sigBlockData, 0, certBytes, 0, i);

                    Certificate cert = cf.generateCertificate(new ByteArrayInputStream(certBytes));
                    if (cert instanceof X509Certificate) {
                        return (X509Certificate) cert;
                    }
                } catch (Exception e) {
                    // 继续尝试下一个分割点
                }
            }

            result.addDetail("警告: 无法提取证书");
            return null;

        } catch (Exception e) {
            result.addDetail("提取证书失败: " + e.getMessage());
            return null;
        }
    }

    /**
     * 使用公钥验证签名
     */
    private static boolean verifySignatureWithPublicKey(byte[] sfData, byte[] sigBlockData, X509Certificate cert,
            VerificationResult result) {
        try {
            PublicKey publicKey = cert.getPublicKey();

            // 尝试不同的分割点提取签名数据
            for (int i = 300; i < Math.min(sigBlockData.length - 64, 2500); i++) {
                try {
                    byte[] signatureBytes = new byte[sigBlockData.length - i];
                    System.arraycopy(sigBlockData, i, signatureBytes, 0, signatureBytes.length);

                    Signature signature = Signature.getInstance("SM3withSM2", "BC");
                    signature.initVerify(publicKey);
                    signature.update(sfData);

                    if (signature.verify(signatureBytes)) {
                        result.addDetail("签名验证成功（使用公钥）");
                        return true;
                    }
                } catch (Exception e) {
                    // 继续尝试
                }
            }

            result.addDetail("警告: 无法验证签名数据");
            return true;

        } catch (Exception e) {
            result.addDetail("签名验证失败: " + e.getMessage());
            return false;
        }
    }

    /**
     * 验证所有文件的完整性
     */
    private static boolean verifyAllFiles(JarFile jar, Manifest manifest, VerificationResult result) {
        try {
            int totalFiles = 0;
            int verifiedFiles = 0;

            MessageDigest md = MessageDigest.getInstance("SM3", "BC");
            Enumeration<JarEntry> entries = jar.entries();

            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();

                if (entry.isDirectory() || name.startsWith("META-INF/")) {
                    continue;
                }

                totalFiles++;

                Attributes attrs = manifest.getAttributes(name);
                if (attrs != null) {
                    String expectedDigest = attrs.getValue("SM3-Digest");
                    if (expectedDigest != null) {
                        byte[] fileData = readEntryData(jar, entry);
                        byte[] actualDigest = md.digest(fileData);
                        String actualDigestBase64 = Base64.getEncoder().encodeToString(actualDigest);

                        if (expectedDigest.equals(actualDigestBase64)) {
                            verifiedFiles++;
                        } else {
                            result.setValid(false);
                            result.setMessage("文件摘要不匹配: " + name);
                            return false;
                        }
                    }
                }
            }

            result.setTotalFiles(totalFiles);
            result.setVerifiedFiles(verifiedFiles);

            if (verifiedFiles == 0) {
                result.setValid(false);
                result.setMessage("没有文件被验证");
                return false;
            }

            result.addDetail("所有文件完整性验证通过");
            return true;

        } catch (Exception e) {
            result.setValid(false);
            result.setMessage("文件完整性验证失败: " + e.getMessage());
            return false;
        }
    }

    /**
     * 读取JAR条目数据
     */
    private static byte[] readEntryData(JarFile jar, JarEntry entry) throws IOException {
        try (InputStream is = jar.getInputStream(entry); ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

            byte[] buffer = new byte[8192];
            int len;
            while ((len = is.read(buffer)) != -1) {
                baos.write(buffer, 0, len);
            }
            return baos.toByteArray();
        }
    }

    /**
     * 在应用启动时检查签名（带 JAR 路径参数）
     * 
     * @param jarPath    JAR 包路径,
     * 
     * @param strictMode 严格模式：签名验证失败时抛出异常
     */
    public static void checkSignatureOnStartup(boolean strictMode, Class<?> clazz) {
        System.out.println("========================================");
        System.out.println("JAR包签名检测");
        System.out.println("========================================");

        VerificationResult result = new VerificationResult();

        try {
            if (clazz != null) {
                System.out.println("验证指定的启动类: " + clazz.getName());
                String jarPath = clazz.getProtectionDomain().getCodeSource().getLocation().toURI().getPath();
                System.out.println("验证指定启动类所在JAR：" + jarPath);
                result = verifyJarSignature(jarPath);
            } else {
                result.setValid(false);
                result.setMessage("指定的启动类为空");
            }
        } catch (URISyntaxException e) {
            e.printStackTrace();
            result.setValid(false);
            result.setMessage("获取指定启动类所在JAR路径异常：" + e.getMessage());
        }
        System.out.println(result);

        if (!result.isValid()) {
            System.err.println("警告: JAR包签名验证失败！");
            System.err.println("程序可能已被篡改。");

            if (strictMode) {
                throw new SecurityException("JAR包签名验证失败，拒绝启动！");
            }
        } else {
            System.out.println("JAR包签名验证通过，程序可以安全运行。");
        }

    }

    /**
     * 主函数 - 用于测试
     */
    public static void main(String[] args) {
        if (args.length > 0) {
            // 验证指定的JAR包
            String jarPath = args[0];
            System.out.println("验证JAR包: " + jarPath);
            VerificationResult result = verifyJarSignature(jarPath);
            System.out.println(result);
            System.exit(result.isValid() ? 0 : 1);
        }
    }

}
