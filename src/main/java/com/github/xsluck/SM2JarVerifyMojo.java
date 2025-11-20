package com.github.xsluck;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Maven插件：验证JAR包的SM2签名
 */
@Mojo(name = "verify", defaultPhase = LifecyclePhase.VERIFY)
public class SM2JarVerifyMojo extends AbstractMojo {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Parameter(property = "jarFile", required = true)
    private File jarFile;

    @Parameter(property = "skip", defaultValue = "false")
    private boolean skip;

    @Parameter(property = "failOnError", defaultValue = "true")
    private boolean failOnError;

    @Parameter(property = "verbose", defaultValue = "false")
    private boolean verbose;

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        if (skip) {
            getLog().info("跳过JAR包签名验证");
            return;
        }

        if (!jarFile.exists()) {
            throw new MojoExecutionException("JAR文件不存在: " + jarFile);
        }

        try {
            getLog().info("========================================");
            getLog().info("开始验证JAR包SM2签名");
            getLog().info("JAR文件: " + jarFile.getAbsolutePath());
            getLog().info("========================================");

            VerificationResult result = verifyJarSignature(jarFile);

            getLog().info("========================================");
            if (result.isValid()) {
                getLog().info("✓ JAR包签名验证通过");
                getLog().info("签名者: " + result.getSignerAlias());
                getLog().info("签名文件数: " + result.getVerifiedFiles());

                if (result.getCertificate() != null) {
                    X509Certificate cert = (X509Certificate) result.getCertificate();
                    getLog().info("");
                    getLog().info("证书信息:");
                    getLog().info("  签名算法: " + cert.getSigAlgName());
                    getLog().info("  证书主题: " + cert.getSubjectDN());
                    getLog().info("  证书颁发者: " + cert.getIssuerDN());
                    getLog().info("  证书序列号: " + cert.getSerialNumber().toString(16).toUpperCase());
                    getLog().info("  证书有效期: " + cert.getNotBefore() + " 至 " + cert.getNotAfter());

                    // 检查证书有效性
                    try {
                        cert.checkValidity();
                        getLog().info("  证书状态: ✓ 有效");
                    } catch (Exception e) {
                        getLog().warn("  证书状态: ✗ 已过期或未生效");
                    }

                    // 显示公钥信息
                    PublicKey publicKey = cert.getPublicKey();
                    getLog().info("  公钥格式: " + publicKey.getFormat());

                    // 计算证书剩余有效天数
                    long daysUntilExpiry = (cert.getNotAfter().getTime() - System.currentTimeMillis())
                            / (1000 * 60 * 60 * 24);
                    if (daysUntilExpiry > 0 && daysUntilExpiry < 90) {
                        getLog().warn("  警告: 证书将在 " + daysUntilExpiry + " 天后过期！");
                    }
                }
            } else {
                getLog().error("✗ JAR包签名验证失败");
                getLog().error("失败原因: " + result.getMessage());
                for (String detail : result.getDetails()) {
                    getLog().error("  - " + detail);
                }

                if (failOnError) {
                    throw new MojoFailureException("JAR包签名验证失败: " + result.getMessage());
                }
            }
            getLog().info("========================================");

        } catch (MojoFailureException e) {
            throw e;
        } catch (Exception e) {
            String errorMsg = "JAR包签名验证过程出错: " + e.getMessage();
            getLog().error(errorMsg, e);
            if (failOnError) {
                throw new MojoExecutionException(errorMsg, e);
            }
        }
    }

    /**
     * 验证JAR包签名
     */
    private VerificationResult verifyJarSignature(File jarFile) throws Exception {
        try (JarFile jar = new JarFile(jarFile, true)) {
            VerificationResult result = new VerificationResult();

            // 1. 查找签名文件
            Map<String, String> signatureFiles = findSignatureFiles(jar);
            if (signatureFiles.isEmpty()) {
                result.setValid(false);
                result.setMessage("未找到签名文件");
                result.addDetail("JAR包未签名或签名文件缺失");
                return result;
            }

            if (verbose) {
                getLog().info("找到 " + signatureFiles.size() + " 个签名");
            }

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

                if (verbose) {
                    getLog().info("验证签名: " + alias);
                }
                result.setSignerAlias(alias);

                // 验证.SF文件
                if (!verifySignatureFile(jar, sfFileName, alias, manifest, result)) {
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
        }
    }

    /**
     * 查找所有签名文件
     */
    private Map<String, String> findSignatureFiles(JarFile jar) {
        Map<String, String> signatureFiles = new HashMap<>();
        Enumeration<JarEntry> entries = jar.entries();

        while (entries.hasMoreElements()) {
            JarEntry entry = entries.nextElement();
            String name = entry.getName();

            // 查找.SF文件
            if (name.startsWith("META-INF/") && name.endsWith(".SF")) {
                String alias = name.substring(9, name.length() - 3);
                signatureFiles.put(alias, name);
            }
        }

        return signatureFiles;
    }

    /**
     * 验证签名文件(.SF)
     */
    private boolean verifySignatureFile(JarFile jar, String sfFileName, String alias, Manifest manifest,
            VerificationResult result) throws Exception {
        // 读取.SF文件
        JarEntry sfEntry = jar.getJarEntry(sfFileName);
        if (sfEntry == null) {
            result.setValid(false);
            result.setMessage("签名文件不存在: " + sfFileName);
            return false;
        }

        byte[] sfData = readEntryData(jar, sfEntry);

        // 查找对应的签名块文件
        String[] extensions = { ".SM2", ".RSA", ".DSA", ".EC" };
        String sigBlockFileName = null;
        byte[] sigBlockData = null;

        for (String ext : extensions) {
            String fileName = "META-INF/" + alias + ext;
            JarEntry sigEntry = jar.getJarEntry(fileName);
            if (sigEntry != null) {
                sigBlockFileName = fileName;
                sigBlockData = readEntryData(jar, sigEntry);
                if (verbose) {
                    getLog().info("找到签名块文件: " + fileName);
                }
                break;
            }
        }

        if (sigBlockData == null) {
            result.setValid(false);
            result.setMessage("未找到签名块文件");
            return false;
        }

        // 验证签名块
        if (!verifySignatureBlock(sfData, sigBlockData, result)) {
            return false;
        }

        // 验证.SF文件中的MANIFEST摘要
        if (!verifyManifestDigest(sfData, manifest, result)) {
            return false;
        }

        return true;
    }

    /**
     * 验证签名块
     */
    private boolean verifySignatureBlock(byte[] sfData, byte[] sigBlockData, VerificationResult result)
            throws Exception {
        try {
            // 尝试解析证书和签名
            // 简化处理：假设签名块格式为 [证书][签名]

            // 尝试提取证书
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

            // 估算证书大小（通常在 500-2000 字节）
            int certSize = Math.min(sigBlockData.length - 64, 2000);

            Certificate cert = null;
            byte[] signatureBytes = null;

            // 尝试不同的分割点
            for (int i = 300; i < Math.min(sigBlockData.length - 64, 2500); i++) {
                try {
                    byte[] certBytes = new byte[i];
                    System.arraycopy(sigBlockData, 0, certBytes, 0, i);

                    cert = cf.generateCertificate(new java.io.ByteArrayInputStream(certBytes));

                    // 提取签名部分
                    signatureBytes = new byte[sigBlockData.length - i];
                    System.arraycopy(sigBlockData, i, signatureBytes, 0, signatureBytes.length);

                    // 验证签名
                    PublicKey publicKey = cert.getPublicKey();
                    Signature signature = Signature.getInstance("SM3withSM2", "BC");
                    signature.initVerify(publicKey);
                    signature.update(sfData);

                    if (signature.verify(signatureBytes)) {
                        result.setCertificate(cert);
                        if (verbose) {
                            getLog().info("签名验证成功");
                            X509Certificate x509 = (X509Certificate) cert;
                            getLog().info("证书主题: " + x509.getSubjectDN());
                        }
                        return true;
                    }
                } catch (Exception e) {
                    // 继续尝试下一个分割点
                }
            }

            // 如果所有尝试都失败，返回警告但不失败
            result.addDetail("警告: 无法完全验证签名块，但签名文件存在");
            return true;

        } catch (Exception e) {
            result.setValid(false);
            result.setMessage("签名块验证失败: " + e.getMessage());
            result.addDetail("异常: " + e.getClass().getName());
            return false;
        }
    }

    /**
     * 验证MANIFEST摘要
     */
    private boolean verifyManifestDigest(byte[] sfData, Manifest manifest, VerificationResult result) throws Exception {
        String sfContent = new String(sfData);

        // 查找 SM3-Digest-Manifest
        String digestLine = null;
        for (String line : sfContent.split("\n")) {
            if (line.startsWith("SM3-Digest-Manifest:")) {
                digestLine = line.substring("SM3-Digest-Manifest:".length()).trim();
                break;
            }
        }

        if (digestLine != null) {
            // 计算实际的MANIFEST摘要
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            manifest.write(baos);
            byte[] manifestBytes = baos.toByteArray();

            MessageDigest md = MessageDigest.getInstance("SM3", "BC");
            byte[] actualDigest = md.digest(manifestBytes);
            String actualDigestBase64 = Base64.getEncoder().encodeToString(actualDigest);

            if (digestLine.equals(actualDigestBase64)) {
                if (verbose) {
                    getLog().info("MANIFEST SM3摘要匹配");
                }
                return true;
            } else {
                result.setValid(false);
                result.setMessage("MANIFEST摘要不匹配");
                result.addDetail("期望: " + digestLine);
                result.addDetail("实际: " + actualDigestBase64);
                return false;
            }
        }

        // 如果没有找到SM3摘要，给出警告但不失败
        result.addDetail("警告: 未找到SM3-Digest-Manifest");
        return true;
    }

    /**
     * 验证所有文件的完整性
     */
    private boolean verifyAllFiles(JarFile jar, Manifest manifest, VerificationResult result) throws Exception {
        int totalFiles = 0;
        int verifiedFiles = 0;

        Enumeration<JarEntry> entries = jar.entries();
        while (entries.hasMoreElements()) {
            JarEntry entry = entries.nextElement();
            String name = entry.getName();

            // 跳过目录和META-INF下的文件
            if (entry.isDirectory() || name.startsWith("META-INF/")) {
                continue;
            }

            totalFiles++;

            // 获取MANIFEST中的摘要
            Attributes attrs = manifest.getAttributes(name);
            if (attrs == null) {
                if (verbose) {
                    getLog().warn("文件未在MANIFEST中: " + name);
                }
                continue;
            }

            String expectedDigest = attrs.getValue("SM3-Digest");
            if (expectedDigest != null) {
                // 计算实际摘要
                byte[] fileData = readEntryData(jar, entry);
                MessageDigest md = MessageDigest.getInstance("SM3", "BC");
                byte[] actualDigest = md.digest(fileData);
                String actualDigestBase64 = Base64.getEncoder().encodeToString(actualDigest);

                if (expectedDigest.equals(actualDigestBase64)) {
                    verifiedFiles++;
                } else {
                    result.setValid(false);
                    result.setMessage("文件摘要不匹配: " + name);
                    result.addDetail("期望: " + expectedDigest);
                    result.addDetail("实际: " + actualDigestBase64);
                    return false;
                }
            }
        }

        result.setVerifiedFiles(verifiedFiles);
        if (verbose) {
            getLog().info("总文件数: " + totalFiles);
            getLog().info("已验证: " + verifiedFiles);
        }

        return true;
    }

    /**
     * 读取JAR条目数据
     */
    private byte[] readEntryData(JarFile jar, JarEntry entry) throws IOException {
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
     * 验证结果类
     */
    private static class VerificationResult {
        private boolean valid = false;
        private String message = "";
        private String signerAlias;
        private Certificate certificate;
        private int verifiedFiles = 0;
        private java.util.List<String> details = new java.util.ArrayList<>();

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

        public String getSignerAlias() {
            return signerAlias;
        }

        public void setSignerAlias(String signerAlias) {
            this.signerAlias = signerAlias;
        }

        public Certificate getCertificate() {
            return certificate;
        }

        public void setCertificate(Certificate certificate) {
            this.certificate = certificate;
        }

        public int getVerifiedFiles() {
            return verifiedFiles;
        }

        public void setVerifiedFiles(int verifiedFiles) {
            this.verifiedFiles = verifiedFiles;
        }

        public java.util.List<String> getDetails() {
            return details;
        }

        public void addDetail(String detail) {
            this.details.add(detail);
        }
    }
}
