# SM2 JAR Sign Maven Plugin

一个用于在 Maven 构建过程中自动使用国密 SM2 算法对 JAR 包进行签名的插件。

## 📋 目录

- [功能特性](#功能特性)
- [环境要求](#环境要求)
- [快速开始](#快速开始)
- [配置说明](#配置说明)
- [使用示例](#使用示例)
- [密钥管理](#密钥管理)
- [常见问题](#常见问题)
- [最佳实践](#最佳实践)

## ✨ 功能特性

- ✅ 支持国密 SM2 算法签名
- ✅ 支持 SM3 摘要算法
- ✅ 自动集成到 Maven 构建生命周期
- ✅ 支持多环境配置（开发/测试/生产）
- ✅ 支持 PEM 格式密钥和证书（PKCS#8 和 EC PRIVATE KEY）
- ✅ 自动验证签名完整性
- ✅ 详细的构建日志输出
- ✅ 支持跳过签名（开发环境）
- ✅ 签名时显示文件统计信息
- ✅ 验证时显示完整的证书信息
- ✅ 证书有效期检查和过期提醒
- ✅ 独立的验证 Goal（可单独验证 JAR 包）

## 🔧 环境要求

- **JDK**: 1.8 或更高版本
- **Maven**: 3.6.0 或更高版本
- **BouncyCastle**: 1.70 或更高版本
- **操作系统**: Linux / macOS / Windows

## 🚀 快速开始

### 1. 安装插件

将插件安装到本地 Maven 仓库：

```bash
cd sm2-jar-sign-maven-plugin
mvn clean install
```

### 2. 准备密钥和证书

生成 SM2 密钥对和证书：

```bash
# 使用 GmSSL 生成
gmssl sm2keygen -pass "changeit" -out sm2.key -pubout sm2.pub
gmssl certgen -C CN -ST Beijing -L Beijing -O "MyOrg" -OU "IT" \
    -CN "JAR Signer" -days 3650 -key sm2.key -pass "changeit" -out sm2.crt

# 转换为 PKCS#8 格式（Java 兼容）
openssl pkcs8 -topk8 -nocrypt -in sm2.key -out sm2-pkcs8.key
```

### 3. 配置项目 pom.xml

```xml
<build>
    <plugins>
        <plugin>
            <groupId>com.example</groupId>
            <artifactId>sm2-jar-sign-maven-plugin</artifactId>
            <version>1.0.0</version>
            <executions>
                <execution>
                    <id>sign-jar</id>
                    <phase>package</phase>
                    <goals>
                        <goal>sign</goal>
                    </goals>
                    <configuration>
                        <jarFile>${project.build.directory}/${project.build.finalName}.jar</jarFile>
                        <keyFile>${project.basedir}/keystore/sm2-pkcs8.key</keyFile>
                        <certFile>${project.basedir}/keystore/sm2.crt</certFile>
                        <alias>sm2signer</alias>
                    </configuration>
                </execution>
            </executions>
        </plugin>
    </plugins>
</build>
```

### 4. 构建并签名

```bash
# 签名并自动验证（推荐）
mvn clean package

# 签名后会自动验证签名是否正确
# 如果验证失败，构建会中断
```

## ⚙️ 配置说明

### 插件参数

| 参数 | 类型 | 必需 | 默认值 | 说明 |
|------|------|------|--------|------|
| `jarFile` | File | 是 | - | 要签名的 JAR 文件路径 |
| `keyFile` | File | 是 | - | SM2 私钥文件路径（PEM 格式，PKCS#8） |
| `certFile` | File | 是 | - | SM2 证书文件路径（PEM 格式） |
| `alias` | String | 否 | sm2signer | 签名别名 |
| `password` | String | 否 | - | 私钥密码（如果私钥加密） |
| `skip` | Boolean | 否 | false | 是否跳过签名 |
| `outputFile` | File | 否 | - | 输出文件路径（默认覆盖原文件） |
| `verify` | Boolean | 否 | true | 签名后是否自动验证 |

### 验证插件参数

| 参数 | 类型 | 必需 | 默认值 | 说明 |
|------|------|------|--------|------|
| `jarFile` | File | 是 | - | 要验证的 JAR 文件路径 |
| `skip` | Boolean | 否 | false | 是否跳过验证 |
| `failOnError` | Boolean | 否 | true | 验证失败时是否中断构建 |
| `verbose` | Boolean | 否 | false | 是否显示详细验证信息 |

### 使用 Properties 配置

在 `pom.xml` 中定义属性：

```xml
<properties>
    <!-- 签名配置 -->
    <jar.sign.enabled>true</jar.sign.enabled>
    <jar.sign.keyfile>${project.basedir}/keystore/sm2-pkcs8.key</jar.sign.keyfile>
    <jar.sign.certfile>${project.basedir}/keystore/sm2.crt</jar.sign.certfile>
    <jar.sign.alias>sm2signer</jar.sign.alias>
    <jar.sign.password></jar.sign.password>
</properties>

<build>
    <plugins>
        <plugin>
            <groupId>com.example</groupId>
            <artifactId>sm2-jar-sign-maven-plugin</artifactId>
            <version>1.0.0</version>
            <configuration>
                <jarFile>${project.build.directory}/${project.build.finalName}.jar</jarFile>
                <keyFile>${jar.sign.keyfile}</keyFile>
                <certFile>${jar.sign.certfile}</certFile>
                <alias>${jar.sign.alias}</alias>
                <password>${jar.sign.password}</password>
                <skip>${skipJarSign}</skip>
            </configuration>
        </plugin>
    </plugins>
</build>
```

### 多环境配置

使用 Maven Profile 配置不同环境：

```xml
<profiles>
    <!-- 开发环境 - 跳过签名 -->
    <profile>
        <id>dev</id>
        <activation>
            <activeByDefault>true</activeByDefault>
        </activation>
        <properties>
            <skipJarSign>true</skipJarSign>
        </properties>
    </profile>

    <!-- 测试环境 - 使用测试密钥 -->
    <profile>
        <id>test</id>
        <properties>
            <skipJarSign>false</skipJarSign>
            <jar.sign.keyfile>${project.basedir}/keystore/test-sm2.key</jar.sign.keyfile>
            <jar.sign.certfile>${project.basedir}/keystore/test-sm2.crt</jar.sign.certfile>
        </properties>
    </profile>

    <!-- 生产环境 - 使用生产密钥 -->
    <profile>
        <id>prod</id>
        <properties>
            <skipJarSign>false</skipJarSign>
            <jar.sign.keyfile>${project.basedir}/keystore/prod-sm2.key</jar.sign.keyfile>
            <jar.sign.certfile>${project.basedir}/keystore/prod-sm2.crt</jar.sign.certfile>
        </properties>
    </profile>
</profiles>
```

## 📝 使用示例

### 基本使用

```bash
# 开发环境（跳过签名）
mvn clean package

# 生产环境（启用签名）
mvn clean package -Pprod

# 测试环境
mvn clean package -Ptest
```

### 命令行覆盖配置

```bash
# 指定不同的密钥文件
mvn clean package -Djar.sign.keyfile=/path/to/custom.key

# 临时启用签名
mvn clean package -DskipJarSign=false

# 指定输出文件
mvn clean package -Djar.sign.output=/path/to/signed.jar
```

### 验证签名

**方法 1：自动验证（推荐）**

插件默认在签名后自动验证，无需额外配置：

```bash
mvn clean package -Pprod
```

输出示例：
```
[INFO] ========================================
[INFO] 开始使用SM2算法签名JAR包
[INFO] JAR文件: /path/to/your-app-1.0.0.jar
[INFO] 私钥文件: /path/to/sm2-pkcs8.key
[INFO] 证书文件: /path/to/sm2.crt
[INFO] 签名别名: sm2signer
[INFO] ========================================
[INFO] 解压JAR包...
[INFO] 加载私钥和证书...
[INFO] 创建签名文件...
[INFO] 已为 1028 个文件添加 SM3 摘要
[INFO] 重新打包JAR...
[INFO] JAR包签名完成: /path/to/your-app-1.0.0.jar
[INFO] ========================================
[INFO] 
[INFO] ========================================
[INFO] 开始验证签名...
[INFO] ========================================
[INFO] 找到签名文件: META-INF/sm2signer.SF
[INFO] 找到签名块文件: META-INF/sm2signer.SM2
[INFO] 
[INFO] 证书信息:
[INFO]   签名算法: SM3withSM2
[INFO]   证书主题: CN=JAR Signer, OU=IT, O=MyOrg, L=Beijing, ST=Beijing, C=CN
[INFO]   证书颁发者: CN=JAR Signer, OU=IT, O=MyOrg, L=Beijing, ST=Beijing, C=CN
[INFO]   证书序列号: 1234567890
[INFO]   证书有效期: Mon Jan 01 00:00:00 CST 2024 至 Tue Dec 31 23:59:59 CST 2034
[INFO]   证书状态: ✓ 有效
[INFO]   公钥算法: EC
[INFO]   公钥格式: X.509
[INFO] 总文件数: 1028
[INFO] 已添加摘要的文件数: 1028
[INFO] 摘要验证通过的文件数: 1028
[INFO] ========================================
[INFO] ✓ 签名验证通过 - JAR包已正确签名
[INFO] ========================================
```

**方法 2：独立验证**

使用插件的 verify goal：

```bash
# 验证指定的 JAR 包
mvn com.github.xsluck:sm2-jar-sign-maven-plugin:0.0.1:verify \
    -DjarFile=target/your-app-1.0.0.jar

# 显示详细信息
mvn com.github.xsluck:sm2-jar-sign-maven-plugin:0.0.1:verify \
    -DjarFile=target/your-app-1.0.0.jar \
    -Dverbose=true

# 验证失败不中断构建
mvn com.github.xsluck:sm2-jar-sign-maven-plugin:0.0.1:verify \
    -DjarFile=target/your-app-1.0.0.jar \
    -DfailOnError=false
```

**方法 3：使用 JDK jarsigner**

```bash
jarsigner -verify -verbose -certs target/your-app-1.0.0.jar
```

**方法 4：检查签名文件**

```bash
# 查看 JAR 包中的签名文件
jar -tf target/your-app-1.0.0.jar | grep META-INF
# 应该看到：
# META-INF/MANIFEST.MF
# META-INF/sm2signer.SF
# META-INF/sm2signer.SM2
```

## 🔐 密钥管理

### 密钥格式要求

插件支持以下密钥格式：

**私钥格式**：
- ✅ PKCS#8 PEM 格式（推荐）
- ✅ EC PRIVATE KEY PEM 格式（需要转换）

**证书格式**：
- ✅ X.509 PEM 格式
- ✅ X.509 DER 格式

### 密钥格式转换

如果您的私钥是 `EC PRIVATE KEY` 格式，需要转换为 `PKCS#8` 格式：

```bash
# 检查密钥格式
head -1 sm2.key
# 如果显示 "-----BEGIN EC PRIVATE KEY-----"，需要转换

# 转换为 PKCS#8 格式
openssl pkcs8 -topk8 -nocrypt -in sm2.key -out sm2-pkcs8.key

# 验证转换结果
head -1 sm2-pkcs8.key
# 应该显示 "-----BEGIN PRIVATE KEY-----"
```

### 密钥存储建议

**目录结构**：
```
your-project/
├── keystore/
│   ├── dev/
│   │   ├── sm2-pkcs8.key
│   │   └── sm2.crt
│   ├── test/
│   │   ├── sm2-pkcs8.key
│   │   └── sm2.crt
│   └── prod/
│       ├── sm2-pkcs8.key
│       └── sm2.crt
├── pom.xml
└── src/
```

**安全建议**：
- ⚠️ 不要将生产环境密钥提交到版本控制系统
- ✅ 使用 `.gitignore` 排除密钥文件
- ✅ 生产密钥应该存储在安全的密钥管理系统中
- ✅ 使用环境变量或加密配置传递密钥路径

**.gitignore 示例**：
```gitignore
# 排除生产密钥
keystore/prod/
*.key
*.p12
*.jks

# 允许测试密钥（可选）
!keystore/test/*.key
```

### 使用环境变量

```xml
<properties>
    <jar.sign.keyfile>${env.JAR_SIGN_KEY_FILE}</jar.sign.keyfile>
    <jar.sign.certfile>${env.JAR_SIGN_CERT_FILE}</jar.sign.certfile>
    <jar.sign.password>${env.JAR_SIGN_PASSWORD}</jar.sign.password>
</properties>
```

```bash
# 设置环境变量
export JAR_SIGN_KEY_FILE=/secure/path/sm2-pkcs8.key
export JAR_SIGN_CERT_FILE=/secure/path/sm2.crt
export JAR_SIGN_PASSWORD=your_password

# 构建
mvn clean package -Pprod
```

## ❓ 常见问题

### Q1: 报错 "encoded key spec not recognized"

**原因**：私钥格式不正确，可能是 `EC PRIVATE KEY` 格式而不是 `PKCS#8` 格式。

**解决方案**：
```bash
openssl pkcs8 -topk8 -nocrypt -in sm2.key -out sm2-pkcs8.key
```

### Q2: 报错 "Certificate chain not found"

**原因**：证书文件路径不正确或证书格式不支持。

**解决方案**：
- 检查证书文件是否存在
- 确保证书是 PEM 格式
- 验证证书内容：`openssl x509 -in sm2.crt -text -noout`

### Q3: 如何在 CI/CD 中使用？

**Jenkins Pipeline**：
```groovy
pipeline {
    agent any
    environment {
        JAR_SIGN_KEY = credentials('jar-sign-key')
        JAR_SIGN_CERT = credentials('jar-sign-cert')
    }
    stages {
        stage('Build and Sign') {
            steps {
                sh '''
                    mvn clean package -Pprod \
                        -Djar.sign.keyfile=$JAR_SIGN_KEY \
                        -Djar.sign.certfile=$JAR_SIGN_CERT
                '''
            }
        }
    }
}
```

**GitLab CI**：
```yaml
build:
  stage: build
  script:
    - echo "$JAR_SIGN_KEY" > /tmp/sm2.key
    - echo "$JAR_SIGN_CERT" > /tmp/sm2.crt
    - openssl pkcs8 -topk8 -nocrypt -in /tmp/sm2.key -out /tmp/sm2-pkcs8.key
    - mvn clean package -Pprod
        -Djar.sign.keyfile=/tmp/sm2-pkcs8.key
        -Djar.sign.certfile=/tmp/sm2.crt
  artifacts:
    paths:
      - target/*.jar
```

### Q4: 如何验证签名是否成功？

**方法 1：自动验证（推荐）**

插件默认在签名后自动验证，查看构建日志：
```bash
mvn clean package -Pprod
```

如果看到以下输出，说明签名成功：
```
[INFO] ✓ 签名验证通过 - JAR包已正确签名
```

**方法 2：使用插件的 verify goal**
```bash
mvn com.github.xsluck:sm2-jar-sign-maven-plugin:0.0.1:verify \
    -DjarFile=target/your-app.jar \
    -Dverbose=true
```

**方法 3：使用 jarsigner**
```bash
jarsigner -verify -verbose target/your-app.jar
```

**方法 4：检查 META-INF 目录**
```bash
jar -tf target/your-app.jar | grep META-INF
# 应该看到：
# META-INF/MANIFEST.MF
# META-INF/sm2signer.SF
# META-INF/sm2signer.SM2
```

### Q5: 签名会影响性能吗？

签名过程会增加构建时间，通常增加 5-30 秒，取决于 JAR 包大小。建议：
- 开发环境跳过签名（`-Pdev`）
- 仅在测试和生产环境启用签名
- 使用 CI/CD 自动化签名过程

### Q6: 如何查看证书信息？

插件在验证签名时会自动显示证书信息，包括：
- 签名算法（SM3withSM2）
- 证书主题和颁发者
- 证书序列号
- 证书有效期
- 证书状态（有效/过期）
- 公钥算法和格式

如果证书将在 90 天内过期，会显示警告信息。

### Q7: 公钥存储在哪里？

公钥包含在 X.509 证书中，证书嵌入在 JAR 包内部的签名块文件（`META-INF/xxx.SM2`）中。

**结构：**
```
your-app.jar
└── META-INF/
    ├── MANIFEST.MF       # 文件摘要清单
    ├── sm2signer.SF      # 签名文件
    └── sm2signer.SM2     # 签名块（包含证书和签名）
                          #   ├─ X.509 证书（包含公钥）
                          #   └─ SM2 签名数据
```

运行时验证只需要 JAR 包本身，无需额外的公钥文件。

## 🎯 最佳实践

### 1. 密钥管理

```bash
# 为不同环境生成独立的密钥对
./generate-keys.sh dev
./generate-keys.sh test
./generate-keys.sh prod

# 生产密钥使用密码保护
gmssl sm2keygen -pass "strong_password" -out prod-sm2.key
```

### 2. 自动化构建

**方式 A：签名时自动验证（推荐）**

```xml
<execution>
    <id>sign-jar</id>
    <phase>package</phase>
    <goals>
        <goal>sign</goal>
    </goals>
    <configuration>
        <!-- 签名后自动验证（默认 true） -->
        <verify>true</verify>
    </configuration>
</execution>
```

**方式 B：签名和验证分开执行**

```xml
<!-- 在 package 阶段签名 -->
<execution>
    <id>sign-jar</id>
    <phase>package</phase>
    <goals>
        <goal>sign</goal>
    </goals>
    <configuration>
        <verify>false</verify>
    </configuration>
</execution>

<!-- 在 verify 阶段独立验证 -->
<execution>
    <id>verify-signature</id>
    <phase>verify</phase>
    <goals>
        <goal>verify</goal>
    </goals>
    <configuration>
        <verbose>true</verbose>
        <failOnError>true</failOnError>
    </configuration>
</execution>
```

### 3. 运行时验证

在应用启动时验证签名：

```java
public class Application {
    public static void main(String[] args) {
        // 启动时验证签名
        JarSignatureVerifier.checkSignatureOnStartup();
        
        // 继续正常启动
        SpringApplication.run(Application.class, args);
    }
}
```

### 4. 版本控制

```xml
<!-- 记录签名信息到 MANIFEST.MF -->
<manifestEntries>
    <Signature-Version>1.0</Signature-Version>
    <Signature-Algorithm>SM3withSM2</Signature-Algorithm>
    <Signature-Date>${maven.build.timestamp}</Signature-Date>
    <Signed-By>${user.name}</Signed-By>
</manifestEntries>
```

### 5. 监控和日志

插件会自动显示详细的签名和验证信息，包括：

- 签名时：
  - 处理的文件数量
  - 签名进度
  
- 验证时：
  - 证书详细信息（主题、颁发者、有效期等）
  - 公钥信息（算法、格式）
  - 文件完整性验证结果
  - 证书有效性检查
  - 证书过期提醒（90天内过期会警告）

### 6. 证书信息

验证时会自动显示以下证书信息：

```
证书信息:
  签名算法: SM3withSM2
  证书主题: CN=JAR Signer, OU=IT, O=MyOrg
  证书颁发者: CN=JAR Signer, OU=IT, O=MyOrg
  证书序列号: 1234567890
  证书有效期: 2024-01-01 至 2034-12-31
  证书状态: ✓ 有效
  公钥算法: EC
  公钥格式: X.509
```

**注意：** 公钥信息包含在证书中，证书嵌入在 JAR 包的签名块文件（`.SM2`）中，无需单独存储。

## 🔐 运行时签名验证

### 应用启动时验证签名

插件提供了运行时验证工具类 `JarSignatureVerifier.java`，可以在应用启动时验证 JAR 包签名。

#### 使用方法

**步骤 1：** 复制验证工具类到项目

```bash
cp src/main/java/com/github/xsluck/runtime/JarSignatureVerifier.java \
   your-project/src/main/java/com/yourpackage/security/
```

**步骤 2：** 添加 BouncyCastle 依赖

```xml
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcprov-jdk15on</artifactId>
    <version>1.70</version>
</dependency>
```

**步骤 3：** 在应用启动时调用

```java
public class Application {
    public static void main(String[] args) {
        // 启动时验证签名（非严格模式）
        JarSignatureVerifier.checkSignatureOnStartup(false);
        
        // 或严格模式（验证失败则退出）
        // JarSignatureVerifier.checkSignatureOnStartup(true);
        
        // 继续正常启动
        SpringApplication.run(Application.class, args);
    }
}
```

#### 验证原理

1. 从 JAR 包内部的签名块文件（`.SM2`）中提取 X.509 证书
2. 从证书中获取公钥
3. 使用公钥验证签名文件（`.SF`）的签名
4. 验证 MANIFEST.MF 的摘要
5. 验证所有文件的 SM3 摘要

**重点：** 公钥在证书中，证书在 JAR 包内部，无需外部文件！

详细使用说明请参考项目中的 `RUNTIME-VERIFICATION.md` 文档。

## 📚 相关资源

- [GmSSL 官方文档](http://gmssl.org/)
- [BouncyCastle 文档](https://www.bouncycastle.org/documentation.html)
- [国密算法标准](http://www.gmbz.org.cn/)
- [Maven 插件开发指南](https://maven.apache.org/plugin-developers/)
- [JAR 签名规范](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html#Signed_JAR_File)

## 📄 许可证

本项目采用 Apache License 2.0 许可证。

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📧 联系方式

- 项目主页：https://github.com/your-org/sm2-jar-sign-maven-plugin
- 问题反馈：https://github.com/your-org/sm2-jar-sign-maven-plugin/issues

---

## 📝 更新日志

### v0.0.2 (最新)
- ✨ 新增：签名时显示处理的文件数量统计
- ✨ 新增：验证时显示完整的证书信息（主题、颁发者、有效期等）
- ✨ 新增：证书有效期检查和过期提醒（90天内过期会警告）
- ✨ 新增：显示公钥算法和格式信息
- 🐛 修复：递归处理子目录文件的签名问题
- 🐛 修复：相对路径计算错误导致部分文件未签名的问题
- 🐛 修复：Windows 系统路径分隔符兼容性问题
- 📝 改进：更详细的日志输出和验证报告

### v0.0.1
- ✨ 基本的 SM2 JAR 签名功能
- ✨ 支持 SM3 摘要算法
- ✨ 自动验证签名完整性

---

**当前版本**: 0.0.2  
**最后更新**: 2025-11-20

