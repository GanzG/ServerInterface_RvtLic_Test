using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using RSAEncryptionLib;
using System.Runtime.Serialization.Formatters.Binary;
using System.Net;

namespace ServerInterface_RvtLic_Test
{
    internal class Program
    {
        static void Main(string[] args)
        {
            HTTPServer server = new HTTPServer();
            server.Server_Start();
        }

    }
}
