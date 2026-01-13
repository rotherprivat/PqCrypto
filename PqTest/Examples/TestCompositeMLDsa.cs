using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Rotherprivat.PqTest.Examples
{
    [TestClass]
    public sealed class TestCompositeMLDsa
    {
        [TestMethod]
        public void CompositeMLDsaSignVerifyOriginal()
        {
            var message = "The quick brown fox jumps over the lazy dog.";

#pragma warning disable SYSLIB5006
            // Sign the message
            using var mlDsaKey = CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.MLDsa87WithECDsaP521);
            var signature = mlDsaKey.SignData(Encoding.UTF8.GetBytes(message));

            var mlDsaPublicKeyInfo = mlDsaKey.ExportSubjectPublicKeyInfo();

            // Import public key
            using var mlDsaPubKey = CompositeMLDsa.ImportSubjectPublicKeyInfo(mlDsaPublicKeyInfo);
#pragma warning restore SYSLIB5006

            // Verify message by public key
            var isValid1 = mlDsaPubKey.VerifyData(Encoding.UTF8.GetBytes(message), signature);

            Assert.IsTrue(isValid1, "Verify original message = false, (expected true)");
        }

        [TestMethod]
        public void CompositeMLDsaSignVerifyTamperedWith()
        {
            var message = "The quick brown fox jumps over the lazy dog.";

#pragma warning disable SYSLIB5006
            // Sign the message
            using var mlDsaKey = CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.MLDsa87WithECDsaP521);
            var signature = mlDsaKey.SignData(Encoding.UTF8.GetBytes(message));

            var mlDsaPublicKeyInfo = mlDsaKey.ExportSubjectPublicKeyInfo();

            // Import public key
            using var mlDsaPubKey = CompositeMLDsa.ImportSubjectPublicKeyInfo(mlDsaPublicKeyInfo);
#pragma warning restore SYSLIB5006

            // Tampering with the message
            message = message.Replace("brown", "brOwn");
            var isValid2 = mlDsaPubKey.VerifyData(Encoding.UTF8.GetBytes(message), signature);

            Assert.IsFalse(isValid2, "Verify tampered with message = true, (expected false)");
        }

    }
}
