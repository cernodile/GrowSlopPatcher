package org.gtmodloader.sloppatcher

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import com.android.apksig.ApkSigner
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.jf.baksmali.Baksmali
import org.jf.baksmali.BaksmaliOptions
import org.jf.dexlib2.DexFileFactory
import org.jf.dexlib2.Opcodes
import org.jf.smali.Smali
import org.jf.smali.SmaliOptions
import java.io.*
import java.math.BigInteger
import java.security.*
import java.security.cert.X509Certificate
import java.util.*
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream
import org.apache.commons.compress.archivers.zip.*

object ModProcessor {

    init {
        Security.removeProvider("BC")
        Security.addProvider(BouncyCastleProvider())
    }

    private class CountingOutputStream(out: OutputStream) : FilterOutputStream(out) {
        private var count: Long = 0
        override fun write(b: Int) {
            out.write(b)
            count++
        }
        override fun write(b: ByteArray, off: Int, len: Int) {
            out.write(b, off, len)
            count += len.toLong()
        }
        fun getCount(): Long = count
    }

    fun process(
        context: Context,
        apkUri: Uri,
        soUri: Uri,
        soFileName: String,
        iconUri: Uri?,
        onProgress: (String) -> Unit,
        onComplete: (File) -> Unit,
        onError: (Exception) -> Unit
    ) {
        Thread {
            try {
                val workDir = File(context.cacheDir, "mod_work").apply {
                    deleteRecursively()
                    mkdirs()
                }
                val originalApk = File(workDir, "original.apk")
                val outputApk = File(workDir, "modified_unsigned.apk")
                val signedApk = File(context.getExternalFilesDir(null), "modded_app.apk")

                val libName = soFileName.substring(3, soFileName.length - 3)

                // 1. Copy APK to work dir
                onProgress("Copying APK...")
                context.contentResolver.openInputStream(apkUri)?.use { input ->
                    originalApk.outputStream().use { output -> input.copyTo(output) }
                }

                // 2. Extract classes.dex
                onProgress("Extracting classes.dex...")
                val dexFile = File(workDir, "classes.dex")
                ZipInputStream(originalApk.inputStream()).use { zis ->
                    var entry = zis.nextEntry
                    while (entry != null) {
                        if (entry.name == "classes.dex") {
                            dexFile.outputStream().use { zis.copyTo(it) }
                            break
                        }
                        entry = zis.nextEntry
                    }
                }

                if (!dexFile.exists()) throw Exception("classes.dex not found in APK")

                // 3. Decompile DEX to Smali
                onProgress("Decompiling DEX...")
                val smaliDir = File(workDir, "smali")
                val dexFileObj = DexFileFactory.loadDexFile(dexFile, Opcodes.getDefault())
                val baksmaliOptions = BaksmaliOptions()
                baksmaliOptions.apiLevel = 24
                Baksmali.disassembleDexFile(dexFileObj, smaliDir, Runtime.getRuntime().availableProcessors(), baksmaliOptions)

                // 4. Modify Smali
                onProgress("Modifying Smali...")
                val mainSmaliFile = File(smaliDir, "com/rtsoft/growtopia/Main.smali")
                if (mainSmaliFile.exists()) {
                    var content = mainSmaliFile.readText()
                    if (!content.contains("invoke-static {v2}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V")) {
                        val target = "sget-object v0, Lcom/rtsoft/growtopia/Main;->dllname:Ljava/lang/String;"
                        val patch = """
                            |    const-string v2, "$libName"
                            |
                            |    invoke-static {v2}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
                            |
                            |    sget-object v0, Lcom/rtsoft/growtopia/Main;->dllname:Ljava/lang/String;
                        """.trimMargin()

                        if (content.contains(target)) {
                            content = content.replace(target, patch)
                            mainSmaliFile.writeText(content)
                        } else {
                            onProgress("Warning: Target signature not found in Main.smali")
                        }
                    } else {
                        onProgress("Main.smali already patched, skipping.")
                    }
                } else {
                    onProgress("Warning: Main.smali not found at expected path.")
                }

                // 5. Recompile Smali to DEX
                onProgress("Recompiling Smali...")
                val modifiedDex = File(workDir, "classes_mod.dex")
                val smaliOptions = SmaliOptions()
                smaliOptions.outputDexFile = modifiedDex.absolutePath
                smaliOptions.apiLevel = 24
                smaliOptions.jobs = Runtime.getRuntime().availableProcessors()

                if (!Smali.assemble(smaliOptions, smaliDir.absolutePath)) {
                    throw Exception("Smali assembly failed")
                }

                // 6. Rebuild APK
                onProgress("Rebuilding APK...")
                val userIconBitmap = iconUri?.let { uri ->
                    context.contentResolver.openInputStream(uri)?.use {
                        BitmapFactory.decodeStream(it)
                    }
                }

                val iconTargetName = "icon.png" // Standard icon name
                val zos = ZipArchiveOutputStream(BufferedOutputStream(FileOutputStream(outputApk)))

                // Open the original APK as a ZipFile to preserve permissions/attributes
                val zipFile = ZipFile(originalApk)
                val entries = zipFile.entries

                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    val name = entry.name

                    // 1. Skip files we are replacing
                    val isIcon = userIconBitmap != null && name.contains("res/mipmap") && name.endsWith(iconTargetName)
                    if (name == "classes.dex" || name.startsWith("META-INF/") || isIcon) continue

                    // 2. Clone entry and preserve Unix attributes
                    val newEntry = ZipArchiveEntry(entry)

                    // Ensure .so files and directories have executable permissions (0755)
                    if (name.endsWith(".so") || entry.isDirectory) {
                        // Skip our library if it already exists
                        if (name.endsWith(soFileName))
                            continue
                        newEntry.unixMode = 493 // Octal 0755
                    } else {
                        newEntry.unixMode = 420 // Octal 0644
                    }

                    // 3. Handle alignment for STORED files (zipalign requirement)
                    if (newEntry.method == ZipArchiveEntry.STORED) {
                        newEntry.setAlignment(4)
                    }

                    zos.putArchiveEntry(newEntry)
                    if (!entry.isDirectory) {
                        zipFile.getInputStream(entry).use { it.copyTo(zos) }
                    }
                    zos.closeArchiveEntry()
                }

                // 4. Add Modified classes.dex
                val dexEntry = ZipArchiveEntry("classes.dex")
                dexEntry.unixMode = 420
                zos.putArchiveEntry(dexEntry)
                modifiedDex.inputStream().use { it.copyTo(zos) }
                zos.closeArchiveEntry()

                // 5. Replace ALL density icons
                if (userIconBitmap != null) {
                    val originalEntries = zipFile.entries
                    while (originalEntries.hasMoreElements()) {
                        val e = originalEntries.nextElement()
                        if (e.name.contains("res/mipmap") && e.name.endsWith(iconTargetName)) {
                            val iconEntry = ZipArchiveEntry(e.name)
                            iconEntry.unixMode = 420
                            zos.putArchiveEntry(iconEntry)
                            userIconBitmap.compress(Bitmap.CompressFormat.PNG, 100, zos)
                            zos.closeArchiveEntry()
                        }
                    }
                }

                // 6. Add new .so file
                onProgress("Injecting .so...")
                val soBytes = context.contentResolver.openInputStream(soUri)?.use { it.readBytes() }
                    ?: throw Exception("Cannot read .so file")

                val soEntry = ZipArchiveEntry("lib/arm64-v8a/$soFileName")
                soEntry.method = ZipArchiveEntry.STORED
                soEntry.size = soBytes.size.toLong()
                soEntry.unixMode = 493 // 0755
                soEntry.setAlignment(4)

                // Calculate CRC
                val crc = CRC32().apply { update(soBytes) }
                soEntry.crc = crc.value

                zos.putArchiveEntry(soEntry)
                zos.write(soBytes) // Write the bytes directly instead of reopening a stream
                zos.closeArchiveEntry()

                zipFile.close()
                zos.finish()
                zos.close()

                // 7. Sign APK
                onProgress("Signing APK...")
                signApk(context, outputApk, signedApk)

                onProgress("Process Complete!")
                onComplete(signedApk)

            } catch (e: Exception) {
                onError(e)
            }
        }.start()
    }

    private fun signApk(context: Context, input: File, output: File) {
        val keystoreFile = File(context.filesDir, "growmodder.p12")
        val (privateKey, cert) = if (keystoreFile.exists()) {
            loadKeyFromStorage(keystoreFile)
        } else {
            generateAndSaveKey(keystoreFile)
        }

        val signerConfig = ApkSigner.SignerConfig.Builder(
            "growmodder",
            privateKey,
            listOf(cert)
        ).build()

        ApkSigner.Builder(listOf(signerConfig))
            .setInputApk(input)
            .setOutputApk(output)
            .setV1SigningEnabled(true)
            .setV2SigningEnabled(true)
            .setV3SigningEnabled(true)
            .setV4SigningEnabled(false)
            .build()
            .sign()
    }

    private fun generateAndSaveKey(file: File): Pair<PrivateKey, X509Certificate> {
        // 1. Generate KeyPair and Certificate
        val keyPairGen = KeyPairGenerator.getInstance("RSA", "BC")
        keyPairGen.initialize(2048)
        val keyPair = keyPairGen.generateKeyPair()
        val cert = generateCertificate(keyPair)

        // 2. Create and Save Keystore
        val keyStore = KeyStore.getInstance("PKCS12")
        keyStore.load(null, null)
        keyStore.setKeyEntry("growmodder", keyPair.private, "insecure!".toCharArray(), arrayOf(cert))

        file.outputStream().use { fos ->
            keyStore.store(fos, "insecure!".toCharArray())
        }

        return Pair(keyPair.private, cert)
    }

    private fun loadKeyFromStorage(file: File): Pair<PrivateKey, X509Certificate> {
        val keyStore = KeyStore.getInstance("PKCS12")
        file.inputStream().use { fis ->
            keyStore.load(fis, "insecure!".toCharArray())
        }

        val privateKey = keyStore.getKey("growmodder", "insecure!".toCharArray()) as PrivateKey
        val cert = keyStore.getCertificate("growmodder") as X509Certificate
        return Pair(privateKey, cert)
    }

    private fun generateCertificate(keyPair: KeyPair): X509Certificate {
        val owner = X500Name("CN=GrowModder")
        val serial = BigInteger.valueOf(System.currentTimeMillis())
        val notBefore = Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24)
        val notAfter = Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 365 * 10)

        val certBuilder = JcaX509v3CertificateBuilder(
            owner, serial, notBefore, notAfter, owner, keyPair.public
        )

        val signer = JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(keyPair.private)
        return JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer))
    }
}
