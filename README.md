<div align="center">
  <a href="https://central.sonatype.com/artifact/io.github.spannm/jackcess-encrypt"><img src="https://img.shields.io/maven-central/v/io.github.spannm/jackcess-encrypt?label=Maven%20Central&style=flat-square" alt="Maven Central Version"></a>
  <img src="https://img.shields.io/maven-central/last-update/io.github.spannm/jackcess-encrypt?label=Updated&style=flat-square&color=blue" alt="Maven Central Last Update">
  <a href="https://github.com/spannm/jackcess-encrypt/stargazers"><img src="https://img.shields.io/github/stars/spannm/jackcess-encrypt?logo=github&label=&logoColor=white&labelColor=555555&color=007ec6&style=flat-square" alt="GitHub Stars"></a>
  <br>
  <a href="https://github.com/spannm/jackcess-encrypt/actions/workflows/ci_jdk21_ubuntu.yml"><img src="https://img.shields.io/github/actions/workflow/status/spannm/jackcess-encrypt/ci_jdk21_ubuntu.yml?label=Build&style=flat-square" alt="GitHub Actions Workflow Status"></a>
  <a href="https://javadoc.io/doc/io.github.spannm/jackcess-encrypt"><img src="https://javadoc.io/badge2/io.github.spannm/jackcess-encrypt/javadoc.svg?style=flat-square" alt="Javadoc"></a>
</div>

<h1 align="center">Welcome to Jackcess Encrypt</h1>
<h3 align="center">Encryption Support for Jackcess</h3>

**Jackcess Encrypt** is an add-on library for [**Jackcess**](https://github.com/spannm/jackcess), the pure Java API for Microsoft Access databases. It adds support for reading and writing encrypted/password-protected `.mdb`, `.accdb` and Microsoft Money (`.mny`) files.

Jackcess itself deliberately ships without this functionality — the encryption schemes used by Access and Money rely on cryptographic primitives that are more sensibly maintained in a separate module with its own dependency on [Bouncy Castle](https://www.bouncycastle.org/). This project supplies that missing piece as a `CodecProvider` that plugs directly into Jackcess.

Jackcess Encrypt is not an application. There is no GUI. It's a library, intended for other developers to build Java applications on top of Jackcess.

<div align="center"> ──────────────────── </div>

## ✨ Key Features

* **Drop-in Codec**: Implements Jackcess's `CodecProvider` SPI — plug it into `DatabaseBuilder` and encrypted files just open.

* **Broad Format Coverage**: Supports classic Jet/MSISAM RC4 obfuscation, the RC4 CryptoAPI and binary document RC4 schemes, as well as modern Office/ECMA-376 standard and agile encryption (AES) used by `.accdb`. Extensible ("external provider") encryption is not supported, as it relies on arbitrary third-party providers.

* **Microsoft Money Support**: Reads password-protected and unprotected Money (`.mny`) files.

* **Flexible Password Retrieval**: Provide a password directly, or supply it lazily via a `Supplier<String>` / `PasswordCallback`, invoked only if the file actually requires one.

<p style="height: 20px;">&nbsp;</p>

## 🛠 Tech Stack & Dependencies

* **Java Version**: 11 or higher at runtime (LTS versions like Java 17 and 21 are fully supported and tested). Building the project itself requires JDK 17 or higher.

* **Main Dependencies**:
  * [Jackcess](https://github.com/spannm/jackcess) (the base library this project extends)
  * [Bouncy Castle](https://www.bouncycastle.org/) (`bcprov-jdk18on`, for the underlying cryptographic primitives)

* **Build Tool**: [Maven](https://maven.apache.org/)

* **Code Quality**: Enforced via Checkstyle and PMD.

<p style="height: 20px;">&nbsp;</p>

## 📦 Installation

Add Jackcess Encrypt alongside Jackcess itself.

### Maven (`pom.xml`)

```xml
<dependency>
    <groupId>io.github.spannm</groupId>
    <artifactId>jackcess</artifactId>
    <version>5.1.7</version>
</dependency>
<dependency>
    <groupId>io.github.spannm</groupId>
    <artifactId>jackcess-encrypt</artifactId>
    <version>5.1.6</version>
</dependency>
```

### Gradle (Groovy / `build.gradle`)

```groovy
implementation 'io.github.spannm:jackcess:5.1.7'
implementation 'io.github.spannm:jackcess-encrypt:5.1.6'
```

## 🚦 Usage Example

Register a `CryptCodecProvider` on the `DatabaseBuilder` before opening an encrypted database:

```java
import io.github.spannm.jackcess.*;
import io.github.spannm.jackcess.encrypt.CryptCodecProvider;

import java.io.File;

try (Database db = new DatabaseBuilder()
        .withFile(new File("encrypted.accdb"))
        .withCodecProvider(new CryptCodecProvider("myPassword"))
        .open()) {

    Table table = db.getTable("friends");
    for (Row row : table) {
        System.out.println("Friend Name: " + row.get("name"));
    }
}
```

Not every "encrypted" Access file actually requires a password — many older formats merely obfuscate the data with a key stored in the file itself. In that case `CryptCodecProvider` works without any password at all.

## ❤️ Origin & Maintenance

This project was forked from the original [Jackcess Encrypt project on SourceForge](https://sourceforge.net/projects/jackcessencrypt/), and is maintained as a companion to [Jackcess](https://github.com/spannm/jackcess) — the two projects are versioned and released in lockstep.

### ⚖️ License

Jackcess Encrypt is licensed under the **Apache License, Version 2.0**. See [LICENSE.txt](LICENSE.txt) for details.

<p style="height: 40px;">&nbsp;</p>

<div align="center">
<table style="border-collapse: collapse;">
  <tr>
    <td style="padding: 40px; border: 2px solid #3a82c2;">
      <strong>Enjoying Jackcess Encrypt? Please leave a 🌟 to support the project!</strong>
    </td>
  </tr>
</table>
</div>
