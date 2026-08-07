using System;
using System.IO;
using System.Reflection;

internal static class Program
{
    private static string _baseDirectory = "";

    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length != 3 || !TrySelector(args[1], out int? uiToken)
            || !TrySelector(args[2], out int? curlToken))
        {
            Console.Error.WriteLine(
                "usage: FunctionPointerProbe <target.exe> <ui-method-token|auto> "
                + "<curl-method-token|auto>");
            return 2;
        }

        string target = Path.GetFullPath(args[0]);
        _baseDirectory = Path.GetDirectoryName(target) ?? Environment.CurrentDirectory;
        Environment.CurrentDirectory = _baseDirectory;
        AppDomain.CurrentDomain.AssemblyResolve += ResolveBesideTarget;
        try
        {
            var assembly = Assembly.LoadFrom(target);
            var ui = UiFunctionPointerProbe.Run(assembly, uiToken);
            try
            {
                Console.WriteLine(ui);
                var curl = CurlFunctionPointerProbe.Run(assembly, curlToken);
                Console.WriteLine(curl);
                return ui.Valid && curl.Valid ? 0 : 1;
            }
            finally
            {
                (ui.InitializedInstance as IDisposable)?.Dispose();
            }
        }
        catch (Exception exception)
        {
            while (exception is TargetInvocationException { InnerException: not null })
                exception = exception.InnerException;
            Console.Error.WriteLine($"{exception.GetType().FullName}: {exception.Message}");
            Console.Error.WriteLine(exception.StackTrace);
            return 1;
        }
    }

    private static Assembly? ResolveBesideTarget(object? _, ResolveEventArgs args)
    {
        string path = Path.Combine(_baseDirectory, new AssemblyName(args.Name).Name + ".dll");
        return File.Exists(path) ? Assembly.LoadFrom(path) : null;
    }

    private static bool TrySelector(string value, out int? token)
    {
        if (string.Equals(value, "auto", StringComparison.OrdinalIgnoreCase))
        {
            token = null;
            return true;
        }

        string normalized = value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? value.Substring(2) : value;
        if (int.TryParse(normalized, System.Globalization.NumberStyles.HexNumber,
            System.Globalization.CultureInfo.InvariantCulture, out int parsed))
        {
            token = parsed;
            return true;
        }

        token = null;
        return false;
    }
}
