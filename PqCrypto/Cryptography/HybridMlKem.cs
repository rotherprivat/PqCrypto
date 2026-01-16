using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;

namespace Rotherprivat.PqCrypto.Cryptography
{
    /// <summary>
    /// Ecnrypt and decrypt data, based on Post Quantum Key exchange algorithms.
    /// <list type="bullet">
    /// <item><description>ML-KEM: <a href="https://csrc.nist.gov/pubs/fips/203/final">FIPS 203</a></description></item>
    /// <item><description>CombinedMLKem: <a href="https://lamps-wg.github.io/draft-composite-kem/draft-ietf-lamps-pq-composite-kem.html">IETF draft</a></description></item>
    /// </list>
    /// </summary>
    public class HybridMlKem : IDisposable
    {
        #region Constructors
        public HybridMlKem(MLKem mlKem)
        {
            _PlainMlKem = mlKem;
        }

        public HybridMlKem(CompositeMLKem compositeMLKem) 
        {
            _CompositeMlKem  = compositeMLKem;
        }
        #endregion

        #region Public methods: Key handling
        public static HybridMlKem GenerateKey(MLKemAlgorithm mLKemAlgorithm)
        {
            return new HybridMlKem(MLKem.GenerateKey(mLKemAlgorithm));
        }

        public static HybridMlKem GenerateKey(CompositeMLKemAlgorithm compositeMLKemAlgorithm)
        {
            return new HybridMlKem(CompositeMLKem.GenerateKey(compositeMLKemAlgorithm));
        }

        public static HybridMlKem ImportSubjectPublicKeyInfo(byte[] publicKey)
        {
#pragma warning disable SYSLIB5006
            return GetKemTypeFromSubjectPublicKeyInfo(publicKey) switch
            {
                KemType.MLKem => new HybridMlKem(MLKem.ImportSubjectPublicKeyInfo(publicKey)),
                KemType.CompositeMLKem => new HybridMlKem(CompositeMLKem.ImportSubjectPublicKeyInfo(publicKey)),
                _ => throw new CryptographicException("Invalid key")
            };
#pragma warning restore SYSLIB5006

        }

        public static HybridMlKem ImportPrivateKey(MLKemAlgorithm algorithm, byte[] privateKey)
        {
            return new HybridMlKem(MLKem.ImportPrivateSeed(algorithm, privateKey));
        }

        public static HybridMlKem ImportPrivateKey(CompositeMLKemAlgorithm algorithm, byte[] privateKey)
        {
            return new HybridMlKem(CompositeMLKem.ImportPrivateKey(algorithm, privateKey));
        }


        public static HybridMlKem ImportPkcs8PrivateKey(byte[] pkcs8)
        {
#pragma warning disable SYSLIB5006
            return GetKemTypeFromPkcs8PrivateKey(pkcs8) switch
            {
                KemType.MLKem => new HybridMlKem(MLKem.ImportPkcs8PrivateKey(pkcs8)),
                KemType.CompositeMLKem => new HybridMlKem(CompositeMLKem.ImportPkcs8PrivateKey(pkcs8)),
                _ => throw new CryptographicException("Invalid key")
            };
#pragma warning restore SYSLIB5006
        }

        public static HybridMlKem ImportPkcs8PrivateKey(ReadOnlySpan<byte> pkcs8)
        {
            return ImportPkcs8PrivateKey(pkcs8.ToArray());
        }

        public static HybridMlKem ImportEncryptedPkcs8PrivateKey(ReadOnlySpan<byte> passwordBytes, byte[] pkcs8)
        {
#pragma warning disable SYSLIB5006
            return GetKemTypeFromPkcs8PrivateKey(passwordBytes, pkcs8) switch
            {
                KemType.MLKem => new HybridMlKem(MLKem.ImportEncryptedPkcs8PrivateKey(passwordBytes, pkcs8)),
                KemType.CompositeMLKem => new HybridMlKem(CompositeMLKem.ImportEncryptedPkcs8PrivateKey(passwordBytes, pkcs8)),
                _ => throw new CryptographicException("Invalid key")
            };
#pragma warning restore SYSLIB5006

        }

        public static HybridMlKem ImportEncryptedPkcs8PrivateKey(ReadOnlySpan<char> password, byte[] pkcs8)
        {
#pragma warning disable SYSLIB5006
            return GetKemTypeFromPkcs8PrivateKey(password, pkcs8) switch
            {
                KemType.MLKem => new HybridMlKem(MLKem.ImportEncryptedPkcs8PrivateKey(password, pkcs8)),
                KemType.CompositeMLKem => new HybridMlKem(CompositeMLKem.ImportEncryptedPkcs8PrivateKey(password, pkcs8)),
                _ => throw new CryptographicException("Invalid key")
            };
#pragma warning restore SYSLIB5006

        }

        public static HybridMlKem ImportEncryptedPkcs8PrivateKey(string password, byte[] pkcs8)
        {
            return ImportEncryptedPkcs8PrivateKey(password.AsSpan(), pkcs8);
        }

        public static HybridMlKem ImportEncapsulationKey(MLKemAlgorithm algorithm, byte[] encapsulationKey)
        {
            return new HybridMlKem(MLKem.ImportEncapsulationKey(algorithm, encapsulationKey));
        }

        public static HybridMlKem ImportEncapsulationKey(CompositeMLKemAlgorithm algorithm, byte[] encapsulationKey)
        {
            return new HybridMlKem(CompositeMLKem.ImportEncapsulationKey(algorithm, encapsulationKey));
        }

        public static HybridMlKem ImportSubjectPublicKeyInfo(ReadOnlySpan<byte> publicKey)
        {
#pragma warning disable SYSLIB5006
            return GetKemTypeFromSubjectPublicKeyInfo(publicKey.ToArray()) switch
            {
                KemType.MLKem => new HybridMlKem(MLKem.ImportSubjectPublicKeyInfo(publicKey)),
                KemType.CompositeMLKem => new HybridMlKem(CompositeMLKem.ImportSubjectPublicKeyInfo(publicKey)),
                _ => throw new CryptographicException("Invalid key")
            };
#pragma warning restore SYSLIB5006
        }

        public static HybridMlKem ImportFromPem(string pemKey)
        {
            var pem = PemEncoding.Find(pemKey);
            var label = pemKey[pem.Label];
            if (label != PemLabels.PublicKey)
                throw new CryptographicException("Invalid PEM-Type");

            var base64Data = pemKey[pem.Base64Data];

            var derData = Convert.FromBase64String(base64Data);

            return ImportSubjectPublicKeyInfo(derData);
        }

        public static HybridMlKem ImportFromPem(ReadOnlySpan<char> pemKey)
        {
            var pem = PemEncoding.Find(pemKey);
            var label = pemKey[pem.Label];
            if (label != PemLabels.PublicKey)
                throw new CryptographicException("Invalid PEM-Type");

            var base64Data = pemKey[pem.Base64Data].ToString();

            var derData = Convert.FromBase64String(base64Data);

            return ImportSubjectPublicKeyInfo(derData);
        }

        public byte[] ExportSubjectPublicKeyInfo()
        {
            EnsureValid();

#pragma warning disable SYSLIB5006
            if (_PlainMlKem != null)
                return _PlainMlKem.ExportSubjectPublicKeyInfo();
#pragma warning restore SYSLIB5006

            if (_CompositeMlKem != null)
                return _CompositeMlKem.ExportSubjectPublicKeyInfo();

            throw new CryptographicException("Invalid key configuration"); 
        }

        public byte[] ExportPkcs8PrivateKey()
        {
            EnsureValid();

            if (_PlainMlKem != null)
#pragma warning disable SYSLIB5006
                return _PlainMlKem.ExportPkcs8PrivateKey();

            if (_CompositeMlKem != null)
                return _CompositeMlKem.ExportPkcs8PrivateKey();
#pragma warning restore SYSLIB5006

            throw new CryptographicException("Invalid key configuration");
        }

        public byte[] ExportPrivateKey()
        {
            EnsureValid();

            if (_PlainMlKem != null)
                return _PlainMlKem.ExportPrivateSeed();

            if (_CompositeMlKem != null)
                return _CompositeMlKem.ExportPrivateKey();

            throw new CryptographicException("Invalid key configuration");
        }

        public void ExportPrivateKey(Span<byte> privateKey)
        {
            EnsureValid();

            _PlainMlKem?.ExportPrivateSeed(privateKey);

            _CompositeMlKem?.ExportPrivateKey(privateKey);

            throw new CryptographicException("Invalid key configuration");
        }

        public byte[] ExportEncryptedPkcs8PrivateKey(ReadOnlySpan<byte> passwordbytes, PbeParameters pbeParameters)
        {
            EnsureValid();

#pragma warning disable SYSLIB5006
            if (_PlainMlKem != null)
                return _PlainMlKem.ExportEncryptedPkcs8PrivateKey(passwordbytes, pbeParameters);
#pragma warning restore SYSLIB5006

            if (_CompositeMlKem != null)
                return _CompositeMlKem.ExportEncryptedPkcs8PrivateKey(passwordbytes, pbeParameters);

            throw new CryptographicException("Invalid key configuration");
        }

        public byte[] ExportEncryptedPkcs8PrivateKey(ReadOnlySpan<char> password, PbeParameters pbeParameters)
        {
            EnsureValid();

#pragma warning disable SYSLIB5006
            if (_PlainMlKem != null)
                return _PlainMlKem.ExportEncryptedPkcs8PrivateKey(password, pbeParameters);
#pragma warning restore SYSLIB5006

            if (_CompositeMlKem != null)
                return _CompositeMlKem.ExportEncryptedPkcs8PrivateKey(password, pbeParameters);

            throw new CryptographicException("Invalid key configuration");
        }

        public byte[] ExportEncryptedPkcs8PrivateKey(string password, PbeParameters pbeParameters)
        {
            return ExportEncryptedPkcs8PrivateKey(password.ToArray(), pbeParameters);
        }

        public byte[] ExportEncapsulationKey()
        {
            EnsureValid();

            if (_PlainMlKem != null)
                return _PlainMlKem.ExportEncapsulationKey();

            if (_CompositeMlKem != null)
                return _CompositeMlKem.ExportEncapsulationKey();

            throw new CryptographicException("Invalid key configuration");
        }

        public void ExportEncapsulationKey(Span<byte> keyBuffer)
        {
            EnsureValid();

            _PlainMlKem?.ExportEncapsulationKey(keyBuffer);

            _CompositeMlKem?.ExportEncapsulationKey(keyBuffer);

            throw new CryptographicException("Invalid key configuration");
        }

        public string ExportSubjectPublicKeyInfoPem()
        {
            var buffer = ExportSubjectPublicKeyInfo();
            return PemEncoding.WriteString(PemLabels.PublicKey, buffer);
        }
        #endregion

        #region Public methods:Encrypt / Decrypt
        public HybridMlKemCipherData? Encrypt(byte[] plaintext)
        {
            EnsureValid();

            // Encapsulate the symmetric key the cipherText is required for decryption
            Encapsulate(out byte[] cipherText, out byte[] key);

            // generate nonce and Encrypt the plaintext using AES-GCM
            var nonce = RandomNumberGenerator.GetBytes(12);
            var tag = new byte[16];
            var encryptedPlaintext = new byte[plaintext.Length];
            using var aes = new AesGcm(key, tag.Length);

            aes.Encrypt(nonce, plaintext, encryptedPlaintext, tag);

            return new HybridMlKemCipherData()
            {
                CipherText = cipherText,
                GcmNonce = nonce,
                EncryptedPlainText = encryptedPlaintext,
                GcmTag = tag
            };
        }

        public byte[] Decrypt(HybridMlKemCipherData cipherData)
        {
            EnsureValid();

            // Decapsulate the symmetric key
            var key = Decapsulate(cipherData.CipherText)
                ?? throw new CryptographicException("Decapsulate key failed");

            // decrypt the plaintext by AES-GCM using the parameters and EncryptedPayload from cipherData
            var plainText = new byte[cipherData.EncryptedPlainText.Length];

            using var aes = new AesGcm(key, cipherData.GcmTag.Length);

            aes.Decrypt(cipherData.GcmNonce, cipherData.EncryptedPlainText, cipherData.GcmTag, plainText);

            return plainText;
        }
        #endregion

        #region Encepsulate / Decapsulate abstraction
        private void Encapsulate(out byte[] cipherText, out byte[] key)
        {
            cipherText = key = [];
            _PlainMlKem?.Encapsulate(out cipherText, out key);
            _CompositeMlKem?.Encapsulate(out cipherText, out key);
        }

        private byte[]? Decapsulate(byte[] ciphertext)
        {
            if (_PlainMlKem != null)
                return _PlainMlKem.Decapsulate(ciphertext);

            if (_CompositeMlKem != null)
                return _CompositeMlKem.Decapsulate(ciphertext);

            return null;
        }
        #endregion

        #region Private implementation, types and fields
        private enum KemType
        {
            MLKem,
            CompositeMLKem
        };

        private static KemType GetKemTypeFromSubjectPublicKeyInfo(byte[] publicKey)
        {
            var asn1 = new AsnReader(publicKey, AsnEncodingRules.DER);
            var asnPk = asn1.ReadSequence();
            var ObjectId = asnPk.ReadSequence();
            var oid = ObjectId.ReadObjectIdentifier();

            if (CompositeMLKemAlgorithm.FromOid(oid) != null)
                return KemType.CompositeMLKem;
            else
                return KemType.MLKem;
        }

        private static KemType GetKemTypeFromPkcs8PrivateKey(byte[] pkcs8)
        {
            var pckcs8Info = Pkcs8PrivateKeyInfo.Decode(pkcs8, out _) ??
                throw new CryptographicException("Invalid PKCS#8 data");

            return GetKemTypeFromPkcs8Info(pckcs8Info);
        }

        private static KemType GetKemTypeFromPkcs8PrivateKey(ReadOnlySpan<byte> passwordBytes, byte[] pkcs8)
        {
            var pckcs8Info = Pkcs8PrivateKeyInfo.DecryptAndDecode(passwordBytes, pkcs8, out _) ??
                throw new CryptographicException("Invalid PKCS#8 data");

            return GetKemTypeFromPkcs8Info(pckcs8Info);
        }

        private static KemType GetKemTypeFromPkcs8PrivateKey(ReadOnlySpan<char> password, byte[] pkcs8)
        {
            var pckcs8Info = Pkcs8PrivateKeyInfo.DecryptAndDecode(password, pkcs8, out _) ??
                           throw new CryptographicException("Invalid PKCS#8 data");

            return GetKemTypeFromPkcs8Info(pckcs8Info);
        }

        private static KemType GetKemTypeFromPkcs8Info(Pkcs8PrivateKeyInfo pckcs8Info)
        {
            var oid = pckcs8Info.AlgorithmId.Value ??
                throw new CryptographicException("Invalid PKCS#8 data");

            if (CompositeMLKemAlgorithm.FromOid(oid) != null)
                return KemType.CompositeMLKem;
            else
                return KemType.MLKem;
        }

        private void EnsureValid()
        {
            if (_PlainMlKem == default && _CompositeMlKem == default)
                throw new CryptographicException("Not initialized");

            if (_PlainMlKem != default && _CompositeMlKem != default)
                throw new CryptographicException("Invalid key configuration");
        }

        private MLKem? _PlainMlKem  = default;
        private CompositeMLKem? _CompositeMlKem = default;
        #endregion

        #region IDisposable
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                _PlainMlKem?.Dispose();
                _CompositeMlKem?.Dispose(); 
            }

            _PlainMlKem = null;
            _CompositeMlKem = null;
        }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        #endregion
    }
}
