using System;
using System.Collections.Generic;
using System.Text;

namespace System.Security.Cryptography
{
    internal static partial class Oids
    {
        // MLKEM768-RSA2048-SHA3-256 OID: 1.3.6.1.5.5.7.6.55
        // MLKEM768-RSA3072-SHA3-256 OID: 1.3.6.1.5.5.7.6.56
        // MLKEM768-RSA4096-SHA3-256 OID: 1.3.6.1.5.5.7.6.57
        // MLKEM768-X25519-SHA3-256 OID: 1.3.6.1.5.5.7.6.58

        // MLKEM768-ECDH-P256-SHA3-256 OID: 1.3.6.1.5.5.7.6.59
        internal const string KMKem768WithECDhP256Sha3 = "1.3.6.1.5.5.7.6.59";

        // MLKEM768-ECDH-P384-SHA3-256 OID: 1.3.6.1.5.5.7.6.60
        internal const string KMKem768WithECDhP384Sha3 = "1.3.6.1.5.5.7.6.60";

        // MLKEM768-ECDH-brainpoolP256r1-SHA3-256 OID: 1.3.6.1.5.5.7.6.61
        // MLKEM1024-RSA3072-SHA3-256 OID: 1.3.6.1.5.5.7.6.62

        // MLKEM1024-ECDH-P384-SHA3-256 OID: 1.3.6.1.5.5.7.6.63
        internal const string KMKem1024WithECDhP384Sha3 = "1.3.6.1.5.5.7.6.63";
        
        // MLKEM1024-ECDH-brainpoolP384r1-SHA3-256 OID: 1.3.6.1.5.5.7.6.64
        // MLKEM1024-X448-SHA3-256 OID: 1.3.6.1.5.5.7.6.65

        // MLKEM1024-ECDH-P521-SHA3-256 OID: 1.3.6.1.5.5.7.6.66
        internal const string KMKem1024WithECDhP521Sha3 = "1.3.6.1.5.5.7.6.66";
    }
}
