using System.Security.Cryptography;

namespace Rotherprivat.PqTest.Examples
{
    [TestClass]
    public sealed class TestMLKem
    {
        [TestMethod]
        public void MLKemExchangeKey()
        {            
            // Alice: Generate private- and public-key
            using var alice = MLKem.GenerateKey(MLKemAlgorithm.MLKem1024);
#pragma warning disable SYSLIB5006
            var pkcs8 = alice.ExportPkcs8PrivateKey();

            // Alice: Send public key to bob
            var pubKey = alice.ExportSubjectPublicKeyInfo();

            // Bob: Import public key
            using var bob = MLKem.ImportSubjectPublicKeyInfo(pubKey);
#pragma warning restore SYSLIB5006

            // Bob: encapsulate and get shared key 
            // Bob: send ciphertext to alice
            bob.Encapsulate(out byte[] ciphertext, out byte[] bobsSharedKey);

            // Alice: Decapsulate ciphertext and get shared key
            byte[] aliceSharedKey = alice.Decapsulate(ciphertext);

            // Validate keys
            Assert.IsTrue(aliceSharedKey.SequenceEqual(bobsSharedKey), "Key exchange failed, the shared keys are different");
        }
    }
}
