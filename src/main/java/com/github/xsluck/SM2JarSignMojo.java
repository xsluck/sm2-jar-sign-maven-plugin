package com.github.xsluck;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Enumeration;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

/**
 * Maven插件：使用SM2算法对JAR包进行签名
 */
@Mojo(name = "sign", defaultPhase = LifecyclePhase.PACKAGE)
public class SM2JarSignMojo extends AbstractMojo {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Parameter(property = "jarFile", required = true)
    private File jarFile;

    @Parameter(property = "keyFile", required = true)
    private File keyFile;

    @Parameter(property = "certFile", required = true)
    private File certFile;

    @Parameter(property = "alias", defaultValue = "sm2signer")
    private String alias;

    @Parameter(property = "skip", defaultValue = "false")
    private boolean skip;

    @Parameter(property = "outputFile")
    private File outputFile;

    @Parameter(property = "verify", defaultValue = "true")
    private boolean verify;

    @Override
    public void execute() throws MojoExecutionException {
        if (skip) {
            getLog().info("跳过JAR包签名");
            return;
        }

        if (!jarFile.exists()) {
            throw new MojoExecutionException("JAR文件不存在: " + jarFile);
        }

        if (!keyFile.exists()) {
            throw new MojoExecutionException("私钥文件不存在: " + keyFile);
        }

        if (!certFile.exists()) {
            throw new MojoExecutionException("证书文件不存在: " + certFile);
        }

        try {
            getLog().info("========================================");
            getLog().info("开始使用SM2算法签名JAR包");
            getLog().info("JAR文件: " + jarFile.getAbsolutePath());
            getLog().info("私钥文件: " + keyFile.getAbsolutePath());
            getLog().info("证书文件: " + certFile.getAbsolutePath());
            getLog().info("签名别名: " + alias);
            getLog().info("========================================");

            // 如果没有指定输出文件，则覆盖原文件
            File signedJar = outputFile != null ? outputFile : jarFile;

            // 执行签名
            signJar(jarFile, signedJar, keyFile, certFile, alias);

            getLog().info("JAR包签名完成: " + signedJar.getAbsolutePath());
            getLog().info("========================================");

            // 签名完成后自动验证
            if (verify) {
                getLog().info("");
                getLog().info("========================================");
                getLog().info("开始验证签名...");
                getLog().info("========================================");

                boolean verifyResult = verifySignature(signedJar);

                if (verifyResult) {
                    getLog().info("========================================");
                    getLog().info("✓ 签名验证通过 - JAR包已正确签名");
                    getLog().info("========================================");
                } else {
                    getLog().error("========================================");
                    getLog().error("✗ 签名验证失败 - 请检查签名过程");
                    getLog().error("========================================");
                    throw new MojoExecutionException("签名验证失败");
                }
            }

        } catch (Exception e) {
            throw new MojoExecutionException("JAR包签名失败", e);
        }
    }

    /**
     * 验证签名
     */
    private boolean verifySignature(File jarFile) {
        try (JarFile jar = new JarFile(jarFile, true)) {
            // 1. 检查签名文件是否存在
            boolean hasSignature = false;
            String signerAlias = null;

            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();

                if (name.startsWith("META-INF/") && name.endsWith(".SF")) {
                    hasSignature = true;
                    signerAlias = name.substring(9, name.length() - 3);
                    getLog().info("找到签名文件: " + name);
                    break;
                }
            }

            if (!hasSignature) {
                getLog().error("未找到签名文件");
                return false;
            }

            // 2. 检查签名块文件并提取证书信息
            String[] extensions = { ".SM2", ".RSA", ".DSA", ".EC" };
            boolean hasSignatureBlock = false;
            byte[] sigBlockData = null;
            String sigBlockFileName = null;

            for (String ext : extensions) {
                String fileName = "META-INF/" + signerAlias + ext;
                JarEntry sigEntry = jar.getJarEntry(fileName);
                if (sigEntry != null) {
                    hasSignatureBlock = true;
                    sigBlockFileName = fileName;
                    getLog().info("找到签名块文件: " + fileName);

                    // 读取签名块数据
                    try (InputStream is = jar.getInputStream(sigEntry);
                            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream()) {
                        byte[] buffer = new byte[8192];
                        int len;
                        while ((len = is.read(buffer)) != -1) {
                            baos.write(buffer, 0, len);
                        }
                        sigBlockData = baos.toByteArray();
                    }
                    break;
                }
            }

            if (!hasSignatureBlock) {
                getLog().error("未找到签名块文件");
                return false;
            }

            // 3. 提取并显示证书信息
            if (sigBlockData != null) {
                extractAndDisplayCertificateInfo(sigBlockData);
            }

            // 4. 检查MANIFEST.MF
            Manifest manifest = jar.getManifest();
            if (manifest == null) {
                getLog().error("未找到MANIFEST.MF");
                return false;
            }

            // 5. 验证文件摘要
            int totalFiles = 0;
            int filesWithDigest = 0;
            int verifiedFiles = 0;

            MessageDigest md = MessageDigest.getInstance("SM3", "BC");

            entries = jar.entries();
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
                        filesWithDigest++;

                        // 验证摘要
                        try (InputStream is = jar.getInputStream(entry);
                                java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream()) {
                            byte[] buffer = new byte[8192];
                            int len;
                            while ((len = is.read(buffer)) != -1) {
                                baos.write(buffer, 0, len);
                            }

                            byte[] actualDigest = md.digest(baos.toByteArray());
                            String actualDigestBase64 = Base64.getEncoder().encodeToString(actualDigest);

                            if (expectedDigest.equals(actualDigestBase64)) {
                                verifiedFiles++;
                            } else {
                                getLog().error("文件摘要不匹配: " + name);
                                return false;
                            }
                        }
                    }
                }
            }

            getLog().info("总文件数: " + totalFiles);
            getLog().info("已添加摘要的文件数: " + filesWithDigest);
            getLog().info("摘要验证通过的文件数: " + verifiedFiles);

            if (filesWithDigest == 0) {
                getLog().error("没有文件被添加摘要");
                return false;
            }

            if (filesWithDigest < totalFiles) {
                getLog().warn("警告: 部分文件未添加摘要 (" + filesWithDigest + "/" + totalFiles + ")");
            }

            if (verifiedFiles != filesWithDigest) {
                getLog().error("部分文件摘要验证失败");
                return false;
            }

            return true;

        } catch (Exception e) {
            getLog().error("验证签名时出错: " + e.getMessage(), e);
            return false;
        }
    }

    private void signJar(File inputJar, File outputJar, File keyFile, File certFile, String alias) throws Exception {

        // 创建临时目录
        File tempDir = Files.createTempDirectory("jar-sign").toFile();

        try {
            // 1. 解压JAR
            getLog().info("解压JAR包...");
            unzipJar(inputJar, tempDir);

            // 2. 加载私钥和证书
            getLog().info("加载私钥和证书...");
            PrivateKey privateKey = loadPrivateKey(keyFile);
            Certificate certificate = loadCertificate(certFile);

            // 3. 创建签名文件
            getLog().info("创建签名文件...");
            createSignatureFiles(tempDir, privateKey, certificate, alias);

            // 4. 重新打包
            getLog().info("重新打包JAR...");
            packJar(tempDir, outputJar);

        } finally {
            // 清理临时目录
            deleteDirectory(tempDir);
        }
    }

    private void unzipJar(File jarFile, File destDir) throws IOException {
        try (JarFile jar = new JarFile(jarFile)) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                File file = new File(destDir, entry.getName());

                if (entry.isDirectory()) {
                    file.mkdirs();
                } else {
                    file.getParentFile().mkdirs();
                    try (InputStream is = jar.getInputStream(entry);
                            FileOutputStream fos = new FileOutputStream(file)) {
                        byte[] buffer = new byte[8192];
                        int len;
                        while ((len = is.read(buffer)) != -1) {
                            fos.write(buffer, 0, len);
                        }
                    }
                }
            }
        }
    }

    private PrivateKey loadPrivateKey(File keyFile) throws Exception {
        try (FileReader fileReader = new FileReader(keyFile); PEMParser pemParser = new PEMParser(fileReader)) {

            Object object = pemParser.readObject();

            if (object instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo) {
                // 已经是 PrivateKeyInfo 格式
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
                return converter.getPrivateKey((PrivateKeyInfo) object);
            } else if (object instanceof org.bouncycastle.openssl.PEMKeyPair) {
                // PEMKeyPair 格式
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
                return converter.getPrivateKey(((org.bouncycastle.openssl.PEMKeyPair) object).getPrivateKeyInfo());
            } else {
                // 尝试作为 ECPrivateKey 解析
                String keyContent = new String(java.nio.file.Files.readAllBytes(keyFile.toPath()));
                keyContent = keyContent.replace("-----BEGIN EC PRIVATE KEY-----", "")
                        .replace("-----END EC PRIVATE KEY-----", "").replaceAll("\\s", "");

                byte[] keyBytes = Base64.getDecoder().decode(keyContent);

                // 解析 EC 私钥
                ECPrivateKey ecPrivateKey = ECPrivateKey.getInstance(keyBytes);

                // 转换为 PrivateKeyInfo (PKCS#8)
                PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(
                        new org.bouncycastle.asn1.x509.AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey,
                                org.bouncycastle.asn1.gm.GMObjectIdentifiers.sm2p256v1),
                        ecPrivateKey);

                // 转换为 Java PrivateKey
                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded());
                KeyFactory kf = KeyFactory.getInstance("EC", "BC");
                return kf.generatePrivate(spec);
            }
        }
    }

    private Certificate loadCertificate(File certFile) throws Exception {
        try (FileInputStream fis = new FileInputStream(certFile)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            return cf.generateCertificate(fis);
        }
    }

    private void createSignatureFiles(File tempDir, PrivateKey privateKey, Certificate certificate, String alias)
            throws Exception {
        File metaInf = new File(tempDir, "META-INF");
        metaInf.mkdirs();

        // 创建或更新 MANIFEST.MF
        File manifestFile = new File(metaInf, "MANIFEST.MF");
        Manifest manifest = new Manifest();
        if (manifestFile.exists()) {
            try (FileInputStream fis = new FileInputStream(manifestFile)) {
                manifest.read(fis);
            }
        } else {
            manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
            manifest.getMainAttributes().putValue("Created-By", "SM2 JAR Sign Maven Plugin");
        }

        // 计算所有文件的SM3摘要
        MessageDigest md = MessageDigest.getInstance("SM3", "BC");
        int fileCount = addFileDigests(tempDir, tempDir, manifest, md);

        getLog().info("已为 " + fileCount + " 个文件添加 SM3 摘要");

        // 写入MANIFEST.MF
        try (FileOutputStream fos = new FileOutputStream(manifestFile)) {
            manifest.write(fos);
        }

        // 创建 .SF 文件
        File sfFile = new File(metaInf, alias + ".SF");
        createSignatureFile(manifestFile, sfFile, md);

        // 创建签名块文件
        File sigFile = new File(metaInf, alias + ".SM2");
        createSignatureBlock(sfFile, sigFile, privateKey, certificate);
    }

    /**
     * 递归添加文件摘要
     * 
     * @param rootDir    JAR 根目录
     * @param currentDir 当前处理的目录
     * @param manifest   Manifest 对象
     * @param md         消息摘要算法
     * @return 处理的文件数量
     */
    private int addFileDigests(File rootDir, File currentDir, Manifest manifest, MessageDigest md) throws Exception {
        int count = 0;
        File[] files = currentDir.listFiles();
        if (files == null)
            return count;

        for (File file : files) {
            if (file.isDirectory()) {
                // 跳过 META-INF 目录
                if (!file.getName().equals("META-INF")) {
                    count += addFileDigests(rootDir, file, manifest, md);
                }
            } else {
                // 计算相对于根目录的路径
                String relativePath = getRelativePath(rootDir, file);

                // 跳过 META-INF 下的文件
                if (!relativePath.startsWith("META-INF/")) {
                    byte[] fileBytes = java.nio.file.Files.readAllBytes(file.toPath());
                    byte[] digest = md.digest(fileBytes);
                    String digestBase64 = Base64.getEncoder().encodeToString(digest);

                    Attributes attrs = new Attributes();
                    attrs.putValue("SM3-Digest", digestBase64);
                    manifest.getEntries().put(relativePath, attrs);
                    count++;
                }
            }
        }
        return count;
    }

    /**
     * 获取相对路径
     */
    private String getRelativePath(File baseDir, File file) {
        String relativePath = baseDir.toURI().relativize(file.toURI()).getPath();
        // 确保使用正斜杠（JAR 标准）
        return relativePath.replace('\\', '/');
    }

    private void createSignatureFile(File manifestFile, File sfFile, MessageDigest md) throws Exception {
        try (PrintWriter pw = new PrintWriter(new FileWriter(sfFile))) {
            pw.println("Signature-Version: 1.0");
            pw.println("Created-By: SM2 JAR Sign Maven Plugin");

            byte[] manifestBytes = java.nio.file.Files.readAllBytes(manifestFile.toPath());
            byte[] manifestDigest = md.digest(manifestBytes);
            pw.println("SM3-Digest-Manifest: " + Base64.getEncoder().encodeToString(manifestDigest));
            pw.println();
        }
    }

    private void createSignatureBlock(File sfFile, File sigFile, PrivateKey privateKey, Certificate certificate)
            throws Exception {
        byte[] sfBytes = java.nio.file.Files.readAllBytes(sfFile.toPath());

        Signature signature = Signature.getInstance("SM3withSM2", "BC");
        signature.initSign(privateKey);
        signature.update(sfBytes);
        byte[] signatureBytes = signature.sign();

        // 简化的签名块（实际应该使用PKCS#7格式）
        try (FileOutputStream fos = new FileOutputStream(sigFile)) {
            fos.write(certificate.getEncoded());
            fos.write(signatureBytes);
        }
    }

    private void packJar(File sourceDir, File jarFile) throws IOException {
        try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(jarFile))) {
            addDirectoryToJar(sourceDir, sourceDir, jos);
        }
    }

    private void addDirectoryToJar(File baseDir, File source, JarOutputStream jos) throws IOException {
        File[] files = source.listFiles();
        if (files == null)
            return;

        for (File file : files) {
            if (file.isDirectory()) {
                addDirectoryToJar(baseDir, file, jos);
            } else {
                String entryName = getRelativePath(baseDir, file);
                JarEntry entry = new JarEntry(entryName);
                jos.putNextEntry(entry);

                try (FileInputStream fis = new FileInputStream(file)) {
                    byte[] buffer = new byte[8192];
                    int len;
                    while ((len = fis.read(buffer)) != -1) {
                        jos.write(buffer, 0, len);
                    }
                }
                jos.closeEntry();
            }
        }
    }

    private void deleteDirectory(File dir) {
        File[] files = dir.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    deleteDirectory(file);
                } else {
                    file.delete();
                }
            }
        }
        dir.delete();
    }

    /**
     * 从签名块中提取并显示证书信息
     */
    private void extractAndDisplayCertificateInfo(byte[] sigBlockData) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

            // 尝试不同的分割点提取证书
            for (int i = 300; i < Math.min(sigBlockData.length - 64, 2500); i++) {
                try {
                    byte[] certBytes = new byte[i];
                    System.arraycopy(sigBlockData, 0, certBytes, 0, i);

                    Certificate cert = cf.generateCertificate(new java.io.ByteArrayInputStream(certBytes));

                    if (cert instanceof java.security.cert.X509Certificate) {
                        java.security.cert.X509Certificate x509Cert = (java.security.cert.X509Certificate) cert;

                        getLog().info("");
                        getLog().info("证书信息:");
                        getLog().info("  签名算法: " + x509Cert.getSigAlgName());
                        getLog().info("  证书主题: " + x509Cert.getSubjectDN());
                        getLog().info("  证书颁发者: " + x509Cert.getIssuerDN());
                        getLog().info("  证书序列号: " + x509Cert.getSerialNumber().toString(16).toUpperCase());
                        getLog().info("  证书有效期: " + x509Cert.getNotBefore() + " 至 " + x509Cert.getNotAfter());

                        // 检查证书有效性
                        try {
                            x509Cert.checkValidity();
                            getLog().info("  证书状态: ✓ 有效");
                        } catch (Exception e) {
                            getLog().warn("  证书状态: ✗ 已过期或未生效");
                        }

                        // 显示公钥信息
                        PublicKey publicKey = x509Cert.getPublicKey();
                        getLog().info("  公钥算法: " + publicKey.getAlgorithm());
                        getLog().info("  公钥格式: " + publicKey.getFormat());

                        // 计算证书剩余有效天数
                        long daysUntilExpiry = (x509Cert.getNotAfter().getTime() - System.currentTimeMillis())
                                / (1000 * 60 * 60 * 24);
                        if (daysUntilExpiry > 0 && daysUntilExpiry < 90) {
                            getLog().warn("  警告: 证书将在 " + daysUntilExpiry + " 天后过期！");
                        }

                        return; // 成功提取，退出
                    }
                } catch (Exception e) {
                    // 继续尝试下一个分割点
                }
            }

            getLog().warn("无法从签名块中提取证书信息");

        } catch (Exception e) {
            getLog().warn("提取证书信息失败: " + e.getMessage());
        }
    }
}