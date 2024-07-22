using System;
using System.Globalization;
using System.IO;
using System.Net;
using System.Runtime.ConstrainedExecution;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Xml.Linq;
using LibTimeStamp;

namespace Demo
{
    
    class Program
    {
        static TSResponder tsResponder_SHA1;
        static TSResponder tsResponder_SHA256;
        static readonly string SHA1Path = @"/SHA1/";
        static readonly string SHA256Path = @"/SHA256/";
        static void Main(string[] args)
        {
            PrintDesc();
            Console.ReadKey();
            Console.Clear();
            try
            {
                tsResponder_SHA1 = new TSResponder(File.ReadAllBytes("SHA1.crt"), File.ReadAllBytes("SHA1.key"), "SHA1");
                tsResponder_SHA256 = new TSResponder(File.ReadAllBytes("SHA256.crt"), File.ReadAllBytes("SHA256.key"), "SHA256");
            }
            catch
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Please check your cert and key!");
                Console.ReadLine();
                return;
            }
            HttpListener listener = new HttpListener();
            try
            {
                listener.AuthenticationSchemes = AuthenticationSchemes.Anonymous;
                listener.Prefixes.Add(@"http://127.0.0.1:8080" + SHA1Path);
                listener.Prefixes.Add(@"http://127.0.0.1:8080" + SHA256Path);
                listener.Start();
            }
            catch
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Please run as administrator!");
                Console.ReadLine();
                return;
            }
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("HTTP Server and TimeStamp Responder started successfully!");
            Console.WriteLine("SHA1 TSResponder is available at \"http://127.0.0.1:8080/SHA1/\" or \"http://127.0.0.1:8080/SHA1/yyyy-MM-ddTHH:mm:ss\"");
            Console.WriteLine("SHA256 TSResponder is available at \"http://127.0.0.1:8080/SHA256/\" or \"http://127.0.0.1:8080/SHA256/yyyy-MM-ddTHH:mm:ss\"");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine();
            while (true)
            {
                HttpListenerContext ctx = listener.GetContext();
                ThreadPool.QueueUserWorkItem(new WaitCallback(TaskProc), ctx);
            }
        }

        static void PrintDesc()
        {
            Console.Title = "Local TimeStamp Responder";
            Console.WriteLine(
                "[Local TimeStamp Responder]\r\n" +
                "\r\n" +
                "Please put your SHA1 TSA cert chain and key in the same folder of this program and name them as \"SHA1.crt\" and \"SHA1.key\".\r\n" +
                "Put your SHA256 TSA cert chain and key in the same folder of this program and name them as \"SHA256.crt\" and \"SHA256.key\".\r\n" +
                "This program must run in administrator mode in order to start the local http server!\r\n" +
                "TSResponder accept UTC Time in the form of \"yyyy-MM-dd'T'HH:mm:ss\"  For example: \"2012-03-19T00:00:00\"\r\n" +
                "\r\n" +
                "Press any key to start server!"
                );
        }
        static void TaskProc(object o)
        {
            HttpListenerContext ctx = (HttpListenerContext)o;
            ctx.Response.StatusCode = 200;

            HttpListenerRequest request = ctx.Request;
            HttpListenerResponse response = ctx.Response;
            if (ctx.Request.HttpMethod != "POST")
            {
                StreamWriter writer = new StreamWriter(response.OutputStream, Encoding.ASCII);
                writer.WriteLine("TSA Server");
                writer.Close();
                ctx.Response.Close();
            }
            else
            {
                string log = "";
                string date = "";
                if (request.RawUrl.StartsWith(SHA1Path))
                {
                    date = request.RawUrl.Remove(0, SHA1Path.Length);
                }
                else
                {
                    date = request.RawUrl.Remove(0, SHA256Path.Length);
                }
                DateTime signTime;
                if (!DateTime.TryParseExact(date, "yyyy-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out signTime))
                    signTime = DateTime.UtcNow;

                BinaryReader reader = new BinaryReader(request.InputStream);
                byte[] bRequest = reader.ReadBytes((int)request.ContentLength64);

                bool RFC;
                byte[] bResponse;
                if (request.RawUrl.StartsWith(SHA1Path))
                {
                    bResponse = tsResponder_SHA1.GenResponse(bRequest, signTime, out RFC);
                }
                else
                {
                    bResponse = tsResponder_SHA256.GenResponse(bRequest, signTime, out RFC);
                }
                if (RFC)
                {
                    response.ContentType = "application/timestamp-reply";
                    log += "RFC3161     \t";
                }
                else
                {
                    response.ContentType = "application/octet-stream";
                    log += "Authenticode\t";
                }
                log += signTime;
                BinaryWriter writer = new BinaryWriter(response.OutputStream);
                writer.Write(bResponse);
                writer.Close();
                ctx.Response.Close();
                Console.WriteLine(log);
            }
        }
    }
}
