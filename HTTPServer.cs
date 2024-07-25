using RSAEncryptionLib;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Net;
using Newtonsoft.Json;
using System.IO.Compression;


namespace ServerInterface_RvtLic_Test
{
    internal class HTTPServer
    {
        //private byte[] SecretKey_AES;
        private byte[] IV = File.ReadAllBytes(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) + "\\iv.bt");
        private string PrivateKey_RSA_Path = "F:\\User Files\\Documents\\PrivateKey_1024.xml";
        private RSAEncryption RSA_EncDec;
        private bool PermissionToActions = true;
        HttpListener HTTP_Server;
        List<PluginInformation> plugins;


        public class PluginInformation
        {
            public string NameEng;
            public string NameRus;
            public string Category;
            public string TypeOfButton;
            public string PulldownbuttonName;
            public string PulldownbuttonText;
            public string TypeOfPlugin;
            public Version Version;
        }

        public class HTTP_Client
        {


            public IPAddress IP_Address;
            public string Identifier;
            public AesCryptoServiceProvider AES;
        }


        public static List<HTTP_Client> ClientsPool = new List<HTTP_Client>();
        public static string Plugins_json;

        public static bool VeryfyID(string ID)
        {
            if (ClientsPool.Where(x => x.Identifier == ID).Count() > 0)
                return false;
            else return true;
        }

        public static bool CheckID(string ID)
        {
            if (ClientsPool.Where(x => x.Identifier == ID).Count() == 0)
                return false;
            else return true;
        }
        public void Server_Start()
        {
            plugins = new List<PluginInformation>();

            PluginInformation PlInfo = new PluginInformation();
            PlInfo.NameEng = "RVT_VRS";
            PlInfo.NameRus = "ВРС";
            PlInfo.Category = "Конструктив";
            PlInfo.TypeOfButton = "PushButton";
            PlInfo.TypeOfPlugin = "RVT";
            PlInfo.Version = Version.Parse("2023.1.0.5");
            plugins.Add(PlInfo);

            PlInfo = new PluginInformation();
            PlInfo.NameEng = "RVT_RebarFormAppoint";
            PlInfo.NameRus = "Назначение формы";
            PlInfo.Category = "Конструктив";
            PlInfo.TypeOfButton = "PushButton";
            PlInfo.TypeOfPlugin = "RVT";
            PlInfo.Version = Version.Parse("2023.1.1.1");
            plugins.Add(PlInfo);

            PlInfo = new PluginInformation();
            PlInfo.NameEng = "RVT_OpeningMonitoring";
            PlInfo.NameRus = "Мониторинг отверстий";
            PlInfo.Category = "Отверстия";
            PlInfo.TypeOfButton = "PulldownButton";
            PlInfo.PulldownbuttonName = "OpeningAnalysis";
            PlInfo.PulldownbuttonText = "Анализ отверстий";
            PlInfo.TypeOfPlugin = "RVT";
            PlInfo.Version = Version.Parse("1.0.0.0");
            plugins.Add(PlInfo);

            Plugins_json = JsonConvert.SerializeObject(plugins);

            RSA_EncDec = new RSAEncryption();
            RSA_EncDec.LoadPrivateFromXml(PrivateKey_RSA_Path);

            HTTP_Server = new HttpListener();
            HTTP_Server.Prefixes.Add("http://127.0.0.1:48795/");
            HTTP_Server.Start();

            Task.Factory.StartNew(() => { Listener(); });

            Console.ReadLine();

        }

        private void Server_Handshake(HttpListenerContext context, string ClientID)
        {
            Console.WriteLine("Need handshake with: " + context.Request.RemoteEndPoint.Address);

            ECDiffieHellmanCng server = new ECDiffieHellmanCng();
            server.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            server.HashAlgorithm = CngAlgorithm.Sha256;
            server.KeySize = 256;
            object ServerPublicKey = server.PublicKey;
            byte[] ServerPublicKey_bytes = ByteConverter.ObjectToByteArray(ServerPublicKey);
            byte[] ClientPublicKey_bytes = new byte[context.Request.ContentLength64];

            BinaryReader BR = new BinaryReader(context.Request.InputStream);
            ClientPublicKey_bytes = BR.ReadBytes(ClientPublicKey_bytes.Length);
            BR.Close();
            byte[] SecretKey = server.DeriveKeyMaterial(ByteConverter.ByteArrayToObject(ClientPublicKey_bytes) as ECDiffieHellmanCngPublicKey);

            var AES = new AesCryptoServiceProvider();
            AES.IV = IV;
            AES.Key = SecretKey;
            ClientsPool.Where(x => x.Identifier == ClientID).First().AES = AES;
            
            var ResponseToClient = context.Response;
            ResponseToClient.ContentLength64 = ServerPublicKey_bytes.Length;

            Stream ResponseWithServerPublicKey = ResponseToClient.OutputStream;
            ResponseWithServerPublicKey.Write(ServerPublicKey_bytes, 0, ServerPublicKey_bytes.Length);
            ResponseWithServerPublicKey.Flush();

            Console.WriteLine("AES key generated with: " + context.Request.RemoteEndPoint.Address);
        }
        private void Listener()
        {
            Console.WriteLine("Listener started");
            while (PermissionToActions)
            {
                var context = HTTP_Server.GetContextAsync().Result;
                IPAddress ClientIP = context.Request.RemoteEndPoint.Address;
                Console.WriteLine("Request from: " + ClientIP);
                string RawUrl = context.Request.RawUrl;

                switch(RawUrl)
                {
                    case "/start":
                        string ClientIdentifier = "";
                        bool ID_Correct = false;

                        while (!ID_Correct)
                        {
                            ClientIdentifier = CryptoLib.CreateIdentifier();
                            ID_Correct = VeryfyID(ClientIdentifier);
                        }
                        var Cl = new HTTP_Client();
                        Cl.Identifier = ClientIdentifier;
                        Cl.IP_Address = ClientIP;
                        ClientsPool.Add(Cl);

                        context.Response.StatusCode = 200;
                        context.Response.AddHeader("ID", ClientIdentifier);
                        ClientIdentifier = "";
                        context.Response.Close();
                        break;
                    
                    case "/handshake":
                        ClientIdentifier = context.Request.Headers.Get("ID");
                        
                        if (CheckID(ClientIdentifier))
                            //Task.Factory.StartNew(() => { Server_Handshake(context, ClientIdentifier); });
                            Server_Handshake(context, ClientIdentifier);
                        else
                        {
                            context.Response.StatusCode = 401;
                            ClientIdentifier = "";
                            context.Response.Close();
                            Console.WriteLine(ClientIP + " -> is unauthorized");
                        }
                        break;

                    case "/lic":
                        ClientIdentifier = context.Request.Headers.Get("ID");
                        if (CheckID(ClientIdentifier))
                            //Task.Factory.StartNew(() => { Responser_str(context, ClientIdentifier); });
                            Responser_str(context, ClientIdentifier);
                        else
                        {
                            context.Response.StatusCode = 401;
                            ClientIdentifier = "";
                            context.Response.Close();
                            Console.WriteLine(ClientIP + " -> is unauthorized");
                        }
                        break;

                    case "/ping":
                        ClientIdentifier = context.Request.Headers.Get("ID");
                        if (CheckID(ClientIdentifier))
                        {
                            context.Response.StatusCode = 200;
                            ClientIdentifier = "";
                            context.Response.Close();
                            Console.WriteLine(ClientIP + " -> is alive");
                        }
                        else
                        {
                            context.Response.StatusCode = 401;
                            ClientIdentifier = "";
                            context.Response.Close();
                            Console.WriteLine(ClientIP + " -> is unauthorized");
                        }
                        break;
                    case "/getavailablerepos":
                        ClientIdentifier = context.Request.Headers.Get("ID");
                        if (CheckID(ClientIdentifier))
                        {
                            //context.Response.StatusCode = 200;
                            //Task.Factory.StartNew(() => { Response_text(context, ClientIdentifier, Plugins_json); });
                            Response_text(context, ClientIdentifier, Plugins_json);
                            ClientIdentifier = "";
                        }
                        else
                        {
                            context.Response.StatusCode = 401;
                            ClientIdentifier = "";
                            context.Response.Close();
                            Console.WriteLine(ClientIP + " -> is unauthorized");
                        }
                        break;
                    case "/localbuilds":
                        ClientIdentifier = context.Request.Headers.Get("ID");
                        if (CheckID(ClientIdentifier))
                        {
                            context.Response.StatusCode = 200;
                            Task.Factory.StartNew(() => { GenerateArchiveAndDownloadToken(context, ClientIdentifier, true, null); });
                            //CheckLocalBuilds(context, ClientIdentifier);
                        }
                        else
                        {
                            context.Response.StatusCode = 401;
                            ClientIdentifier = "";
                            context.Response.Close();
                            Console.WriteLine(ClientIP + " -> is unauthorized");
                        }
                        break;
                    case "/download":
                        ClientIdentifier = context.Request.Headers.Get("ID");
                        if (CheckID(ClientIdentifier))
                        {
                            string DownloadToken = context.Request.Headers.Get("DownloadToken");
                            if (DownloadTokens.Keys.Contains(DownloadToken))
                            {
                                //Console.WriteLine("Токен есть");
                                context.Response.StatusCode = 200;
                                Task.Factory.StartNew(() => { SendArchive(context, ClientIdentifier, DownloadToken); });
                                
                            }
                            else
                            {
                                context.Response.StatusCode = 400;
                                ClientIdentifier = "";
                                context.Response.Close();
                            }
                            
                        }
                        else
                        {
                            context.Response.StatusCode = 401;
                            ClientIdentifier = "";
                            context.Response.Close();
                            Console.WriteLine(ClientIP + " -> is unauthorized");
                        }
                        break;
                    case "/downloadnecessarybuilds":
                        ClientIdentifier = context.Request.Headers.Get("ID");
                        if (CheckID(ClientIdentifier))
                        {
                            context.Response.StatusCode = 200;
                            string NecessaryBuilds_json = context.Request.Headers.Get("BuildsToDownload");
                            Task.Factory.StartNew(() => { GenerateArchiveAndDownloadToken(context, ClientIdentifier, false, NecessaryBuilds_json); });
                        }
                        else
                        {
                            context.Response.StatusCode = 401;
                            ClientIdentifier = "";
                            context.Response.Close();
                            Console.WriteLine(ClientIP + " -> is unauthorized");
                        }
                        break;

                }
            }
        }

        private void Responser_str(HttpListenerContext context, string ClientID)
        {
            try
            {
                byte[] ClientMessage = new byte[context.Request.ContentLength64];

                BinaryReader BR = new BinaryReader(context.Request.InputStream);
                ClientMessage = BR.ReadBytes(ClientMessage.Length);
                BR.Close();
                string Message = CryptoLib.DecryptStringFromBytes_AES_RSA(ClientMessage, ClientsPool.Where(x => x.Identifier == ClientID).First().AES, RSA_EncDec);
                Console.WriteLine($"Message from {context.Request.RemoteEndPoint.Address}: \n" + Message);
            }
            catch (Exception e) 
            {
                Console.WriteLine(e.Message);
            }
            
        }

        private void Response_text(HttpListenerContext context, string ClientID, string text)
        {
            byte[] text_bytes = CryptoLib.EncryptBytes_AES(Encoding.UTF8.GetBytes(text), ClientsPool.Where(x => x.Identifier == ClientID).First().AES.Key, IV);
            var ResponseToClient = context.Response;
            ResponseToClient.ContentLength64 = text_bytes.Length;

            Stream ResponseToClient_Stream = ResponseToClient.OutputStream;
            ResponseToClient_Stream.Write(text_bytes, 0, text_bytes.Length);
            ResponseToClient_Stream.Flush();
            ResponseToClient_Stream.Close();
        }

        Dictionary<string, string> DownloadTokens = new Dictionary<string, string>();
        private void GenerateArchiveAndDownloadToken(HttpListenerContext context, string ClientID, bool CheckLocalBuilds, string NecessaryBuilds_json)
        {
            List<string> DllFiles_buffer = new List<string>();
            string RVT_path = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + $"\\RvtSrv_LicenseManager\\RVT";

            if (CheckLocalBuilds)
            {
                byte[] LocalBuildsJson_bytes = new byte[context.Request.ContentLength64];

                BinaryReader BR = new BinaryReader(context.Request.InputStream);
                LocalBuildsJson_bytes = BR.ReadBytes(LocalBuildsJson_bytes.Length);
                BR.Dispose();
                BR.Close();
                string LocalBuilds_json = CryptoLib.DecryptStringFromBytes_Aes(LocalBuildsJson_bytes, ClientsPool.Where(x => x.Identifier == ClientID).First().AES.Key, IV);
                List<PluginInformation> LocalBuilds = JsonConvert.DeserializeObject<List<PluginInformation>>(LocalBuilds_json);
                
                foreach (PluginInformation l in LocalBuilds)
                {
                    Version ActualVersion = plugins.Where(x => x.NameEng == l.NameEng).First().Version;
                    if (ActualVersion.CompareTo(l.Version) > 0)
                        DllFiles_buffer.AddRange(Directory.GetFiles(RVT_path + $"\\{l.NameEng}").ToList());
                }
            }
            else
            {
                List<string> NecessaryBuilds = JsonConvert.DeserializeObject<List<string>>(NecessaryBuilds_json);
                foreach (var NecBuild_NameEng in NecessaryBuilds)
                {
                    DllFiles_buffer.AddRange(Directory.GetFiles(RVT_path + $"\\{NecBuild_NameEng}").ToList());
                }
            }


            if (DllFiles_buffer.Count > 0)
            {
                //context.Response.StatusCode = 302;
                string DownloadToken = CryptoLib.CreateIdentifier(128, DownloadTokens.Keys.ToList());
                var encToken = RSA_EncDec.PrivateEncryption(Encoding.UTF8.GetBytes(DownloadToken));
                string PacketsToSend_folder = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + $"\\RvtSrv_LicenseManager\\PacketsToSend";

                if (!Directory.Exists(PacketsToSend_folder))
                    Directory.CreateDirectory(PacketsToSend_folder);

                Directory.CreateDirectory(PacketsToSend_folder + $"\\{DownloadToken}");

                foreach (var Dll_path in DllFiles_buffer)
                    File.Copy(Dll_path, PacketsToSend_folder + $"\\{DownloadToken}\\{Path.GetFileName(Dll_path)}", true);

                DllFiles_buffer = null;

                ZipFile.CreateFromDirectory(PacketsToSend_folder + $"\\{DownloadToken}", PacketsToSend_folder + $"\\{DownloadToken}.zip");

                Directory.Delete(PacketsToSend_folder + $"\\{DownloadToken}", true);

                DownloadTokens.Add(DownloadToken, PacketsToSend_folder + $"\\{DownloadToken}.zip");

                var UpdateResponse = context.Response;

                Stream ResponseStream = UpdateResponse.OutputStream;
                ResponseStream.Write(encToken, 0, encToken.Length);
                context.Response.StatusCode = 200;
                ResponseStream.Flush();
                ResponseStream.Close();
            }
            else
            {
                context.Response.StatusCode = 204;
                context.Response.Close();
            }
        }

        private void SendArchive(HttpListenerContext context, string ClientID, string DownloadToken)
        {
            Console.WriteLine("SendArchive");
            string PacketsToSend_archive = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + $"\\RvtSrv_LicenseManager\\PacketsToSend\\{DownloadToken}.zip";

            byte[] Archive_bytes = File.ReadAllBytes(PacketsToSend_archive);
            byte[] EncryptedArchive = CryptoLib.EncryptBytes_AES(Archive_bytes, ClientsPool.Where(x => x.Identifier == ClientID).First().AES.Key, IV);
            Archive_bytes = null;
            var ResponseToClient = context.Response;
            ResponseToClient.ContentLength64 = EncryptedArchive.Length;

            Stream ResponseToClient_Stream = ResponseToClient.OutputStream;
            ResponseToClient_Stream.Write(EncryptedArchive, 0, EncryptedArchive.Length);
            EncryptedArchive = null;
            ResponseToClient_Stream.Flush();
            ResponseToClient_Stream.Close();
            DownloadTokens.Remove(DownloadToken);
            File.Delete(PacketsToSend_archive);

        }

    }
}
