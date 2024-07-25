using RSAEncryptionLib;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ServerInterface_RvtLic_Test
{
    internal class CryptoLib
    {
        //public static byte[] IV;
        public static byte[] EncryptString_AES(string text, byte[] key, byte[] IV)
        {
            if (text == null || text.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = IV;
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(text);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            return encrypted;
        }

        public static byte[] EncryptBytes_AES(byte[] data, byte[] m_Key, byte[] m_IV)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            using (var rijndaelManaged = new RijndaelManaged())
            {
                rijndaelManaged.KeySize = m_Key.Length * 8;
                rijndaelManaged.Key = m_Key;
                rijndaelManaged.BlockSize = m_IV.Length * 8;
                rijndaelManaged.IV = m_IV;

                using (var encryptor = rijndaelManaged.CreateEncryptor())
                using (var ms = new MemoryStream())
                using (var cryptoStream = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(data, 0, data.Length);
                    cryptoStream.FlushFinalBlock();

                    return ms.ToArray();
                }
            }
        }

        public static byte[] DecryptBytes_AES(byte[] cipher, byte[] m_Key, byte[] m_IV)
        {
            try
            {
                // Check arguments.
                if (cipher == null)
                {
                    throw new ArgumentNullException(nameof(cipher));
                }
                else if (cipher.Length == 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(cipher));
                }

                using (var rijndaelManaged = new RijndaelManaged())
                {
                    rijndaelManaged.KeySize = m_Key.Length * 8;
                    rijndaelManaged.Key = m_Key;
                    rijndaelManaged.BlockSize = m_IV.Length * 8;
                    rijndaelManaged.IV = m_IV;

                    using (var decryptor = rijndaelManaged.CreateDecryptor())
                    using (var ms = new MemoryStream(cipher))
                    using (var cryptoStream = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {

                        byte[] dycrypted = new byte[cipher.Length];
                        var bytesRead = cryptoStream.Read(dycrypted, 0, dycrypted.Length);
                        
                        return dycrypted.Take(bytesRead).ToArray();
                    }
                }
            }
            catch (Exception ex)
            { 
                Console.WriteLine(ex.Message);
                return null;
            }
            
        }

        public static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            string plaintext = null;
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return plaintext;
        }

        public static string DecryptStringFromBytes_AES_RSA(byte[] encrypted, AesCryptoServiceProvider AES, RSAEncryption RSA_Decryptor)
        {
            try
            {
                byte[] DecryptedData;
                DecryptedData = RSA_Decryptor.PrivateDecryption(DecryptBytes_AES(encrypted, AES.Key, AES.IV));
                return Encoding.UTF8.GetString(DecryptedData);
            }
            catch (Exception e) 
            {
                Console.WriteLine(e.Message);
                return null;
            }

            
            
        }
        public static byte[] EncryptBytes_RSA_AES(byte[] SourceFileBytes, byte[] SecretKeyForAES, string PublicOrPrivateKey_Path, bool PublicDec)
        {
            AesCryptoServiceProvider AES = new AesCryptoServiceProvider();
            AES.Key = SecretKeyForAES;
            AES.IV = File.ReadAllBytes(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) + "\\iv.bt");
            //RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            RSAEncryption myRsaEnc = new RSAEncryption();
            byte[] EncryptedDataByRSA;
            if (PublicDec)
            {
                myRsaEnc.LoadPublicFromXml(PublicOrPrivateKey_Path);
                EncryptedDataByRSA = myRsaEnc.PublicEncryption(SourceFileBytes);
            }
            else
            {
                myRsaEnc.LoadPrivateFromXml(PublicOrPrivateKey_Path);
                EncryptedDataByRSA = myRsaEnc.PrivateEncryption(SourceFileBytes);
            }


            return EncryptBytes_AES(EncryptedDataByRSA, AES.Key, AES.IV);
        }

        public static string CreateIdentifier(int length, List<string> ListToCheck)
        {
            string id = "";
            bool created = false;
            while (!created)
            {
                id = CreateIdentifier(length);
                if (!ListToCheck.Contains(id))
                    created = true;
            }

            return id;
        }

        public static string CreateIdentifier()
        {
            return CreateIdentifier(40);
        }
        public static string CreateIdentifier(int length)
        {
            const string valid = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
            StringBuilder res = new StringBuilder();
            Random rnd = new Random();
            while (0 < length--)
            {
                res.Append(valid[rnd.Next(valid.Length)]);
            }
            return res.ToString();
        }

    }


    
}
