using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

namespace Rotherprivat.PqCrypto.Cryptography
{
    public sealed class CompositeMLKemAlgorithm
    {
        private static readonly CompositeMLKemAlgorithm[] _Algorithms =
        {
            new("MLKEM768-ECDH-P256-SHA3-256", "MLKEM768-P256", "1.3.6.1.5.5.7.6.59", MLKemAlgorithm.MLKem768, ECCurve.NamedCurves.nistP256),
            new ("MLKEM768-ECDH-P384-SHA3-256", "MLKEM768-P384", "1.3.6.1.5.5.7.6.60", MLKemAlgorithm.MLKem768, ECCurve.NamedCurves.nistP384),
            new ("MLKEM1024-ECDH-P384-SHA3-256", "MLKEM1024-P384", "1.3.6.1.5.5.7.6.63", MLKemAlgorithm.MLKem1024, ECCurve.NamedCurves.nistP384),
            new ("MLKEM1024-ECDH-P521-SHA3-256", "MLKEM1024-P521", "1.3.6.1.5.5.7.6.66", MLKemAlgorithm.MLKem1024, ECCurve.NamedCurves.nistP521)
        };

        public static CompositeMLKemAlgorithm KMKem768WithECDhP256Sha3 { get; } = _Algorithms[0];
        public static CompositeMLKemAlgorithm KMKem768WithECDhP384Sha3 { get; } = _Algorithms[1];
        public static CompositeMLKemAlgorithm KMKem1024WithECDhP384Sha3 { get; } = _Algorithms[2];
        public static CompositeMLKemAlgorithm KMKem1024WithECDhP521Sha3 { get; } = _Algorithms[3];

        public static CompositeMLKemAlgorithm? FromOid(string oid) => _Algorithms.FirstOrDefault(x => x.Oid == oid);

        private CompositeMLKemAlgorithm(string name, string label, string oid, MLKemAlgorithm mLKemAlgorithm, ECCurve eCCurve)
        {
            Name = name;
            Label = Encoding.ASCII.GetBytes(label);
            Oid = oid;
            MLKemAlgorithm = mLKemAlgorithm;
            ECCurve = eCCurve;
        }
        public override int GetHashCode() => Name.GetHashCode();

        public override string ToString() => Name;

        public string Name { get; }

        public string Oid { get; }

        internal MLKemAlgorithm MLKemAlgorithm { get; }

        internal ECCurve ECCurve { get; }

        internal byte[] Label { get; }

        internal int ECPointValueSizeInBytes => ECCurve.Oid.FriendlyName switch
        {
            "nistP256" => 32,
            "nistP384" => 48,
            "nistP521" => 66,
            _ => throw new CryptographicException("Invalid EC-Curve")
        };

        internal int ECPublicKeySizeInBytes => 2 * ECPointValueSizeInBytes + 1;


        internal int ECPrivateKeyDSizeInBytes => ECCurve.Oid.FriendlyName switch
        {
            "nistP256" => 51,
            "nistP384" => 64,
            "nistP521" => 82,
            _ => throw new CryptographicException("Invalid EC-Curve")
        };
    }
}
