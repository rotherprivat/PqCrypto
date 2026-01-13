using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Reflection.Metadata.Ecma335;
using System.Text;

namespace Rotherprivat.PqCrypto.Cryptography
{
    internal static class PemLabels
    {
        public static string PublicKey => "PUBLIC KEY";
        public static string PrivateKey => "PRIVATE KEY";
    }
}
