using Jose;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApp1
{
    class EncyptionDecryption
    {
        public static JweAlgorithm KEY_MANAGEMENT_ALGORITHM = (JweAlgorithm)2;
        public static JweEncryption CONTENT_ENCRYPTION_ALGORITHM = (JweEncryption)5;
        private Dictionary<string, object> headers;
        private Dictionary<string, object> payload;

        public Dictionary<string, object> GetHeaders() => this.headers;

        public Dictionary<string, object> GetPayload() => this.payload;

        public string EncryptRequest(RSA rsaPublicKey, string payload, Dictionary<string, object> header)
        {

            RSA rsa = rsaPublicKey;
            JweAlgorithm managementAlgorithm = EncyptionDecryption.KEY_MANAGEMENT_ALGORITHM;
            JweEncryption encryptionAlgorithm = EncyptionDecryption.CONTENT_ENCRYPTION_ALGORITHM;
            IDictionary<string, object> headers = (IDictionary<string, object>)header;
            JweCompression? nullable = new JweCompression?();
            string str2 = JWT.Encode(payload, (object)rsa, managementAlgorithm, encryptionAlgorithm, nullable, headers, (JwtSettings)null);

            return str2;
        }

        public void DecryptRequest(RSA rsaPrivateKey, string EncryptedObject)
        {
            string str = EncryptedObject.ToString();
            this.payload = JWT.Decode<Dictionary<string, object>>(str, (object)rsaPrivateKey, (JwtSettings)null);
            this.headers = JWT.Headers<Dictionary<string, object>>(str, (JwtSettings)null);

        }


        public RSA GetRSAPublicKeyFromPem(string pemPath)
        {
            try
            {

                X509Certificate2 certificate = (X509Certificate2)null;
                certificate = new X509Certificate2(pemPath);
                return RSACertificateExtensions.GetRSAPublicKey(certificate);
            }
            catch (Exception ex)
            {
                throw new Exception("[PublicKey reading error] " + ex.Message.ToString());
            }
        }

        public RSA GetRSAPrivateKeyFromPem(string pemPath)
        {
            try
            {

                string str = File.ReadAllText(pemPath);

                using (TextReader textReader = (TextReader)new StringReader(str))
                    return DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)new PemReader(textReader).ReadObject());
            }
            catch (Exception ex)
            {
                throw new Exception("[PrivateKey reading error] " + ex);
            }


        }

    }
}
