using System;
using System.IO;
using System.Reflection;

namespace FaultCasesInvoker
{
    internal static class Program
    {
        private static string targetDirectory = string.Empty;

        public static int Main(string[] args)
        {
            if (args.Length != 1)
            {
                Console.Error.WriteLine("Usage: FaultCasesInvoker.exe <FaultCases.dll>");
                return 2;
            }

            string targetPath = Path.GetFullPath(args[0]);
            targetDirectory = Path.GetDirectoryName(targetPath);
            AppDomain.CurrentDomain.AssemblyResolve += ResolveTargetDependency;

            try
            {
                Assembly assembly = Assembly.LoadFrom(targetPath);
                Type patterns = assembly.GetType("FaultCases.FaultPatterns", true);
                MethodInfo method = patterns.GetMethod("FaultFlow", BindingFlags.Public | BindingFlags.Static);
                FieldInfo state = patterns.GetField("LastFaultState", BindingFlags.Public | BindingFlags.Static);
                if (method == null || state == null)
                    throw new MissingMemberException(patterns.FullName, "FaultFlow state");

                int failures = 0;
                object normal = method.Invoke(null, new object[] { 0 });
                object normalState = state.GetValue(null);
                Console.WriteLine("Fault.Normal=" + normal + "|" + normalState);
                if (!object.Equals(normal, 10) || !object.Equals(normalState, 0))
                    failures++;

                Exception thrown = null;
                try
                {
                    method.Invoke(null, new object[] { 1 });
                }
                catch (TargetInvocationException ex)
                {
                    thrown = ex.InnerException;
                }
                object faultState = state.GetValue(null);
                string thrownText = thrown == null ? "<none>" : thrown.GetType().FullName + ":" + thrown.Message;
                Console.WriteLine("Fault.Exception=" + thrownText + "|" + faultState);
                if (thrown == null || thrown.GetType() != typeof(InvalidOperationException)
                    || thrown.Message != "fault-case" || !object.Equals(faultState, 77))
                    failures++;

                return failures == 0 ? 0 : 1;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.ToString());
                return 2;
            }
        }

        private static Assembly ResolveTargetDependency(object sender, ResolveEventArgs args)
        {
            string candidate = Path.Combine(targetDirectory, new AssemblyName(args.Name).Name + ".dll");
            return File.Exists(candidate) ? Assembly.LoadFrom(candidate) : null;
        }
    }
}
