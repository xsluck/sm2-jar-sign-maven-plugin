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
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.zz.gmhelper.SM3Util;

import com.github.xsluck.utils.CertificateChainUtil;
import com.github.xsluck.utils.JceGmPKCS8DecryptorProviderBuilder;

/**
 * Maven插件：使用SM2算法对JAR包进行签名
 */
@Mojo(name = "sign", defaultPhase = LifecyclePhase.PACKAGE)
public class SM2JarSignMojo extends AbstractMojo {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Maven 项目对象，用于自动获取构建产物
     */
    @Component
    private MavenProject project;

    /**
     * 要签名的 JAR 文件（可选，默认自动获取项目构建的主 artifact）
     */
    @Parameter(property = "jarFile")
    private File jarFile;

    @Parameter(property = "keyFile", required = true)
    private File keyFile;

    @Parameter(property = "certChainFile", required = true)
    private File certChainFile;

    @Parameter(property = "password")
    private String password;

    @Parameter(property = "skip", defaultValue = "false")
    private boolean skip;

    @Parameter(property = "outputFile")
    private File outputFile;

    @Parameter(property = "verify", defaultValue = "true")
    private boolean verify;

    @Parameter(property = "strictCertValidation", defaultValue = "true")
    private boolean strictCertValidation;

    @Override
    public void execute() throws MojoExecutionException {
        if (skip) {
            getLog().info("跳过JAR包签名");
            return;
        }

        // 如果没有指定 jarFile，自动从项目获取主 artifact
        if (jarFile == null) {
            jarFile = getProjectArtifactFile();
        }

        if (jarFile == null || !jarFile.exists()) {
            throw new MojoExecutionException("JAR文件不存在: " + jarFile +
                    "\n请确保项目已正确打包，或手动指定 jarFile 参数");
        }

        if (!keyFile.exists()) {
            throw new MojoExecutionException("私钥文件不存在: " + keyFile);
        }

        if (!certChainFile.exists()) {
            throw new MojoExecutionException("证书链文件不存在: " + certChainFile);
        }

        try {
            getLog().info("========================================");
            getLog().info("开始使用SM2算法签名JAR包");
            getLog().info("JAR文件: " + jarFile.getAbsolutePath());
            getLog().info("私钥文件: " + keyFile.getAbsolutePath());
            getLog().info("证书链文件: " + certChainFile.getAbsolutePath());
            getLog().info("严格证书验证: " + strictCertValidation);
            getLog().info("========================================");

            // 如果没有指定输出文件，则覆盖原文件
            File signedJar = outputFile != null ? outputFile : jarFile;

            // 执行签名
            signJar(jarFile, signedJar, keyFile, certChainFile);

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
     * 从 Maven 项目获取主 artifact 文件（支持 JAR 和 WAR 包）
     */
    private File getProjectArtifactFile() {
        if (project == null) {
            getLog().warn("无法获取 Maven 项目对象");
            return null;
        }

        // 首先尝试从主 artifact 获取
        Artifact artifact = project.getArtifact();
        if (artifact != null && artifact.getFile() != null && artifact.getFile().exists()) {
            getLog().info("自动检测到项目 artifact: " + artifact.getFile().getAbsolutePath());
            return artifact.getFile();
        }

        // 如果主 artifact 没有文件，尝试构建默认路径
        String packaging = project.getPackaging();

        // 支持 jar 和 war 打包类型
        if (!"jar".equals(packaging) && !"war".equals(packaging)) {
            getLog().warn("项目打包类型不是 jar 或 war: " + packaging);
            return null;
        }

        // 构建默认的文件路径: target/${artifactId}-${version}.jar 或 .war
        String fileName = project.getArtifactId() + "-" + project.getVersion() + "." + packaging;
        File targetDir = new File(project.getBuild().getDirectory());
        File defaultFile = new File(targetDir, fileName);

        if (defaultFile.exists()) {
            getLog().info("自动检测到 " + packaging.toUpperCase() + " 文件: " + defaultFile.getAbsolutePath());
            return defaultFile;
        }

        getLog().warn("未找到 " + packaging.toUpperCase() + " 文件: " + defaultFile.getAbsolutePath());
        return null;
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

            for (String ext : extensions) {
                String fileName = "META-INF/" + signerAlias + ext;
                JarEntry sigEntry = jar.getJarEntry(fileName);
                if (sigEntry != null) {
                    hasSignatureBlock = true;
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

    private void signJar(File inputJar, File outputJar, File keyFile, File certChainFile) throws Exception {

        // 创建临时目录
        File tempDir = Files.createTempDirectory("jar-sign").toFile();

        try {
            // 1. 解压JAR
            getLog().info("解压JAR包...");
            unzipJar(inputJar, tempDir);

            // 2. 加载私钥和证书链
            getLog().info("加载私钥和证书链...");
            PrivateKey privateKey = loadPrivateKey(keyFile);

            // 加载证书链（叶子证书在前，CA证书在后）
            java.util.List<java.security.cert.X509Certificate> certChain = CertificateChainUtil
                    .loadCertificateChainFromFile(certChainFile);
            getLog().info("成功加载证书链，共 " + certChain.size() + " 个证书");

            // 叶子证书（签名证书）
            java.security.cert.X509Certificate certificate = certChain.get(0);

            // 2.1 验证证书链（如果启用严格验证）
            if (strictCertValidation) {
                getLog().info("验证证书链...");
                validateCertificateChain(certChain);
            }

            // 3. 创建签名文件
            getLog().info("创建签名文件...");
            createSignatureFiles(tempDir, privateKey, certChain, certificate.getSubjectDN().getName());

            // 4. 重新打包
            getLog().info("重新打包JAR...");
            packJar(tempDir, outputJar);
            // 5. 验证 JAR 结构
            getLog().info("验证JAR文件结构...");
            validateJarStructure(outputJar);
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
                // 未加密的 PrivateKeyInfo 格式 (PKCS#8)
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
                return converter.getPrivateKey((PrivateKeyInfo) object);

            } else if (object instanceof PKCS8EncryptedPrivateKeyInfo) {
                // 加密的 PKCS#8 私钥 (ENCRYPTED PRIVATE KEY)
                PKCS8EncryptedPrivateKeyInfo encryptedInfo = (PKCS8EncryptedPrivateKeyInfo) object;

                if (password == null || password.isEmpty()) {
                    throw new MojoExecutionException("私钥已加密，但未提供密码。请在配置中添加 <password> 参数或使用 -Dpassword=your_password");
                }

                try {
                    // 使用密码解密私钥
                    JceGmPKCS8DecryptorProviderBuilder builder = new JceGmPKCS8DecryptorProviderBuilder();
                    PrivateKeyInfo privateKeyInfo = encryptedInfo
                            .decryptPrivateKeyInfo(builder.build(password.toCharArray()));
                    JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
                    getLog().info("私钥加载成功...");
                    return converter.getPrivateKey(privateKeyInfo);

                } catch (PKCSException e) {
                    throw new MojoExecutionException("私钥解密失败：密码错误或私钥格式不支持", e);
                }

            } else if (object instanceof PEMEncryptedKeyPair) {
                // 加密的 PEM 密钥对 (ENCRYPTED PRIVATE KEY - 旧格式)
                PEMEncryptedKeyPair encryptedKeyPair = (PEMEncryptedKeyPair) object;

                if (password == null || password.isEmpty()) {
                    throw new MojoExecutionException("私钥已加密，但未提供密码。请在配置中添加 <password> 参数或使用 -Dpassword=your_password");
                }

                try {
                    // 使用密码解密私钥对
                    PEMDecryptorProvider decryptorProvider = new JcePEMDecryptorProviderBuilder().setProvider("BC")
                            .build(password.toCharArray());
                    org.bouncycastle.openssl.PEMKeyPair decryptedKeyPair = encryptedKeyPair
                            .decryptKeyPair(decryptorProvider);

                    JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
                    getLog().info("私钥加载成功...");
                    return converter.getPrivateKey(decryptedKeyPair.getPrivateKeyInfo());

                } catch (Exception e) {
                    throw new MojoExecutionException("私钥解密失败：密码错误或私钥格式不支持", e);
                }

            } else if (object instanceof org.bouncycastle.openssl.PEMKeyPair) {
                // 未加密的 PEMKeyPair 格式
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
                return converter.getPrivateKey(((org.bouncycastle.openssl.PEMKeyPair) object).getPrivateKeyInfo());

            } else {
                // 尝试作为 ECPrivateKey 解析（EC PRIVATE KEY 格式）
                String keyContent = new String(java.nio.file.Files.readAllBytes(keyFile.toPath()));

                // 检查是否是加密的格式
                if (keyContent.contains("ENCRYPTED")) {
                    throw new MojoExecutionException("检测到加密的私钥，但无法解析。请确保提供了正确的密码参数 <password>");
                }

                // 提取 EC PRIVATE KEY 块的内容（忽略 EC PARAMETERS 块）
                int beginIndex = keyContent.indexOf("-----BEGIN EC PRIVATE KEY-----");
                int endIndex = keyContent.indexOf("-----END EC PRIVATE KEY-----");

                if (beginIndex == -1 || endIndex == -1) {
                    throw new Exception(
                            "私钥文件格式错误：未找到 EC PRIVATE KEY 块。\n" + "支持的格式：\n" + "  - PKCS#8 格式 (BEGIN PRIVATE KEY)\n"
                                    + "  - 加密的 PKCS#8 格式 (BEGIN ENCRYPTED PRIVATE KEY)\n"
                                    + "  - EC 私钥格式 (BEGIN EC PRIVATE KEY)\n" + "当前文件内容：\n"
                                    + keyContent.substring(0, Math.min(200, keyContent.length())));
                }

                // 只提取 BEGIN 和 END 之间的内容
                String base64Content = keyContent
                        .substring(beginIndex + "-----BEGIN EC PRIVATE KEY-----".length(), endIndex)
                        .replaceAll("\\s", ""); // 移除所有空白字符

                byte[] keyBytes = Base64.getDecoder().decode(base64Content);

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
        } catch (MojoExecutionException e) {
            throw e;
        } catch (Exception e) {
            getLog().error("加载私钥异常...", e);
            throw e;
        }
    }

    /**
     * 验证证书链
     */
    private void validateCertificateChain(java.util.List<java.security.cert.X509Certificate> certChain)
            throws MojoExecutionException {
        try {
            CertificateChainUtil.ChainValidationResult result = CertificateChainUtil.validateCertificateChain(certChain,
                    null);

            if (!result.isValid()) {
                getLog().error("证书链验证失败: " + result.getMessage());
                for (String error : result.getErrors()) {
                    getLog().error("  - " + error);
                }
                throw new MojoExecutionException("证书链验证失败: " + result.getMessage());
            }

            getLog().info("✓ 证书链验证通过");
            getLog().info(CertificateChainUtil.printCertificateChainInfo(certChain));

        } catch (MojoExecutionException e) {
            throw e;
        } catch (Exception e) {
            throw new MojoExecutionException("证书链验证异常: " + e.getMessage(), e);
        }
    }

    private void createSignatureFiles(File tempDir, PrivateKey privateKey,
            java.util.List<java.security.cert.X509Certificate> certChain,
            String alias) throws Exception {
        File metaInf = new File(tempDir, "META-INF");
        metaInf.mkdirs();

        // 读取原始 MANIFEST.MF
        File manifestFile = new File(metaInf, "MANIFEST.MF");
        Manifest manifest = new Manifest();

        if (manifestFile.exists()) {
            try (FileInputStream fis = new FileInputStream(manifestFile)) {
                // 读取原始 MANIFEST
                manifest = new Manifest(fis);

                // 确保必要的版本信息
                if (manifest.getMainAttributes().getValue("Manifest-Version") == null) {
                    manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
                }

                // 更新 Created-By 属性
                manifest.getMainAttributes().putValue("Created-By", "SM2 JAR Sign Maven Plugin");

                getLog().info("成功读取原始 MANIFEST.MF，包含 " + manifest.getMainAttributes().size() + " 个主属性，"
                        + manifest.getEntries().size() + " 个条目");

            } catch (Exception e) {
                getLog().warn("读取原始 MANIFEST.MF 失败: " + e.getMessage() + "，创建新的");
                manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
                manifest.getMainAttributes().putValue("Created-By", "SM2 JAR Sign Maven Plugin");
            }
        } else {
            // 如果没有原始 MANIFEST，创建新的
            manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
            manifest.getMainAttributes().putValue("Created-By", "SM2 JAR Sign Maven Plugin");
        }

        // 计算所有文件的SM3摘要
        int fileCount = addFileDigests(tempDir, tempDir, manifest);

        getLog().info("已为 " + fileCount + " 个文件添加 SM3 摘要");

        // 写入MANIFEST.MF
        try (FileOutputStream fos = new FileOutputStream(manifestFile)) {
            manifest.write(fos);
        }

        // 创建 .SF 文件
        File sfFile = new File(metaInf, alias + ".SF");
        createSignatureFile(manifestFile, sfFile);

        // 创建签名块文件
        File sigFile = new File(metaInf, alias + ".SM2");
        createSignatureBlock(sfFile, sigFile, privateKey, certChain);
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
    private int addFileDigests(File rootDir, File currentDir, Manifest manifest) throws Exception {
        int count = 0;
        File[] files = currentDir.listFiles();
        if (files == null)
            return count;

        for (File file : files) {
            if (file.isDirectory()) {
                // 跳过 META-INF 目录
                if (!file.getName().equals("META-INF")) {
                    count += addFileDigests(rootDir, file, manifest);
                }
            } else {
                // 计算相对于根目录的路径
                String relativePath = getRelativePath(rootDir, file);
                // 跳过 META-INF 下的文件
                if (!relativePath.startsWith("META-INF/")) {
                    byte[] fileBytes = java.nio.file.Files.readAllBytes(file.toPath());
                    byte[] digest = SM3Util.hash(fileBytes);
                    String digestBase64 = Base64.getEncoder().encodeToString(digest);

                    // 获取或创建该文件的属性
                    Attributes attrs = manifest.getEntries().get(relativePath);
                    if (attrs == null) {
                        attrs = new Attributes();
                        manifest.getEntries().put(relativePath, attrs);
                    }

                    // 添加 SM3 摘要（不覆盖现有的其他摘要）
                    attrs.putValue("SM3-Digest", digestBase64);
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

    private void createSignatureFile(File manifestFile, File sfFile) throws Exception {
        try (PrintWriter pw = new PrintWriter(new FileWriter(sfFile))) {
            pw.println("Signature-Version: 1.0");
            pw.println("Created-By: SM2 JAR Sign Maven Plugin");
            byte[] manifestBytes = java.nio.file.Files.readAllBytes(manifestFile.toPath());
            byte[] manifestDigest = SM3Util.hash(manifestBytes);
            pw.println("SM3-Digest-Manifest: " + Base64.getEncoder().encodeToString(manifestDigest));
            pw.println();
        }
    }

    private void createSignatureBlock(File sfFile, File sigFile, PrivateKey privateKey,
            java.util.List<java.security.cert.X509Certificate> certChain)
            throws Exception {
        byte[] sfBytes = java.nio.file.Files.readAllBytes(sfFile.toPath());

        // 创建签名
        Signature signature = Signature.getInstance("SM3withSM2", "BC");
        signature.initSign(privateKey);
        signature.update(sfBytes);
        byte[] signatureBytes = signature.sign();

        getLog().info("创建包含证书链的签名块（" + certChain.size() + " 个证书）");

        // 使用新格式创建签名块（包含证书链）
        byte[] sigBlockData = CertificateChainUtil.createSignatureBlockWithChain(certChain, signatureBytes);

        try (FileOutputStream fos = new FileOutputStream(sigFile)) {
            fos.write(sigBlockData);
        }

        getLog().info("签名块大小: " + sigBlockData.length + " 字节");
    }

    private void packJar(File sourceDir, File jarFile) throws IOException {
        try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(jarFile))) {
            // 步骤1: 添加 MANIFEST.MF 作为第一个条目
            addManifestFirst(sourceDir, jos);

            // 步骤2: 添加其他所有文件和目录（排序后）
            addDirectoryToJar(sourceDir, sourceDir, jos);
        }
    }

    private void addManifestFirst(File sourceDir, JarOutputStream jos) throws IOException {
        File manifestFile = new File(sourceDir, "META-INF/MANIFEST.MF");
        if (manifestFile.exists()) {
            String entryName = "META-INF/MANIFEST.MF";
            JarEntry entry = new JarEntry(entryName);
            entry.setTime(manifestFile.lastModified());
            entry.setSize(manifestFile.length());

            jos.putNextEntry(entry);

            try (FileInputStream fis = new FileInputStream(manifestFile)) {
                byte[] buffer = new byte[8192];
                int len;
                while ((len = fis.read(buffer)) != -1) {
                    jos.write(buffer, 0, len);
                }
            }
            jos.closeEntry();

            getLog().info("已添加 MANIFEST.MF 作为第一个条目");
        } else {
            getLog().warn("未找到 MANIFEST.MF");
        }
    }

    private void addDirectoryToJar(File baseDir, File currentDir, JarOutputStream jos) throws IOException {
        File[] files = currentDir.listFiles();
        if (files == null)
            return;

        // 排序文件和目录（字母顺序）
        Arrays.sort(files, Comparator.comparing(File::getName));

        for (File file : files) {
            String relativePath = getRelativePath(baseDir, file);

            // 跳过已经添加的 MANIFEST.MF
            if (relativePath.equals("META-INF/MANIFEST.MF")) {
                continue;
            }

            if (file.isDirectory()) {
                // 添加目录条目（以 / 结尾）
                String dirPath = relativePath.endsWith("/") ? relativePath : relativePath + "/";
                JarEntry dirEntry = new JarEntry(dirPath);
                dirEntry.setTime(file.lastModified());
                jos.putNextEntry(dirEntry);
                jos.closeEntry();

                // 递归添加子目录内容
                addDirectoryToJar(baseDir, file, jos);
            } else {
                // 添加文件
                JarEntry entry = new JarEntry(relativePath);
                entry.setTime(file.lastModified());
                entry.setSize(file.length());

                // 设置权限（如果可执行）
                if (Files.isExecutable(file.toPath())) {
                    entry.setMethod(ZipEntry.DEFLATED);
                }

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

    private void validateJarStructure(File jarFile) throws IOException {
        try (JarFile jar = new JarFile(jarFile)) {
            // 检查第一个条目是否是 MANIFEST.MF
            Enumeration<JarEntry> entries = jar.entries();
            if (entries.hasMoreElements()) {
                JarEntry firstEntry = entries.nextElement();
                if (!"META-INF/MANIFEST.MF".equals(firstEntry.getName())) {
                    getLog().warn("警告: MANIFEST.MF 不是第一个条目: " + firstEntry.getName());
                } else {
                    getLog().info("✓ MANIFEST.MF 是第一个条目");
                }
            }

            // 检查是否有目录条目
            boolean hasDirEntry = false;
            entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.isDirectory()) {
                    hasDirEntry = true;
                    break;
                }
            }
            if (hasDirEntry) {
                getLog().info("✓ 包含目录条目");
            } else {
                getLog().warn("警告: 缺少目录条目");
            }

            // 检查 Main-Class
            Manifest manifest = jar.getManifest();
            String mainClass = manifest.getMainAttributes().getValue("Main-Class");
            if (mainClass != null) {
                getLog().info("✓ 找到 Main-Class: " + mainClass);
            } else {
                getLog().warn("警告: 未找到 Main-Class");
            }
        }
    }

    /**
     * 从签名块中提取并显示证书信息
     */
    private void extractAndDisplayCertificateInfo(byte[] sigBlockData) {
        try {
            // 尝试提取证书链
            java.util.List<java.security.cert.X509Certificate> certChain = CertificateChainUtil
                    .extractCertificateChainFromSignatureBlock(sigBlockData);

            if (certChain.isEmpty()) {
                getLog().warn("无法从签名块中提取证书");
                return;
            }

            getLog().info("");
            if (certChain.size() == 1) {
                getLog().info("证书信息（单证书）:");
            } else {
                getLog().info("证书链信息（共 " + certChain.size() + " 个证书）:");
            }

            // 显示每个证书的信息
            for (int i = 0; i < certChain.size(); i++) {
                java.security.cert.X509Certificate x509Cert = certChain.get(i);

                if (certChain.size() > 1) {
                    getLog().info("");
                    getLog().info("证书 " + (i + 1) + ":");
                }

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

                // 标识证书类型
                if (x509Cert.getSubjectDN().equals(x509Cert.getIssuerDN())) {
                    getLog().info("  类型: 自签名证书（根证书）");
                } else {
                    getLog().info("  类型: 中间证书或叶子证书");
                }

                // 计算证书剩余有效天数
                long daysUntilExpiry = (x509Cert.getNotAfter().getTime() - System.currentTimeMillis())
                        / (1000 * 60 * 60 * 24);
                if (daysUntilExpiry > 0 && daysUntilExpiry < 90) {
                    getLog().warn("  警告: 证书将在 " + daysUntilExpiry + " 天后过期！");
                }
            }

            // 如果有证书链，验证证书链
            if (certChain.size() > 1) {
                getLog().info("");
                getLog().info("验证证书链...");
                CertificateChainUtil.ChainValidationResult chainResult = CertificateChainUtil
                        .validateCertificateChain(certChain, null);

                if (chainResult.isValid()) {
                    getLog().info("✓ 证书链验证通过");
                } else {
                    getLog().warn("✗ 证书链验证失败: " + chainResult.getMessage());
                    for (String error : chainResult.getErrors()) {
                        getLog().warn("  - " + error);
                    }
                }
            }

        } catch (Exception e) {
            getLog().warn("提取证书信息失败: " + e.getMessage());
            e.printStackTrace();
        }
    }

}