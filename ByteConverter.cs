using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using System.Threading.Tasks;

namespace ServerInterface_RvtLic_Test
{
    internal class ByteConverter
    {
        public static byte[] StringToByteArray(string hex)
        {
            byte[] bytes = new byte[hex.Length];
            //char[] hexChars = hex.ToCharArray();
            for (int i = 0; i < hex.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex[i].ToString());
                //Console.WriteLine(bytes[i] + $" | {hex[i]}");
            }
            return bytes;
        }

        public static Object ByteArrayToObject(byte[] arrBytes)
        {
            MemoryStream memStream = new MemoryStream();
            BinaryFormatter binForm = new BinaryFormatter();
            memStream.Write(arrBytes, 0, arrBytes.Length);
            memStream.Seek(0, SeekOrigin.Begin);
            Object obj = (Object)binForm.Deserialize(memStream);
            return obj;
        }

        public static byte[] ObjectToByteArray(Object obj)
        {
            if (obj == null)
                return null;
            BinaryFormatter bf = new BinaryFormatter();
            MemoryStream ms = new MemoryStream();
            bf.Serialize(ms, obj);
            return ms.ToArray();
        }
    }
}
