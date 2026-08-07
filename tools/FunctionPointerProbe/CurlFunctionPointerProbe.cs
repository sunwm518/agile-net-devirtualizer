using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

internal sealed record CurlProbeResult(
    bool Valid,
    int FunctionPointers,
    int Requests,
    int RequestBytes,
    bool MarkerReturned)
{
    public override string ToString() =>
        $"CURL_VALID={Valid} LD_FTN={FunctionPointers} REQUESTS={Requests} "
        + $"REQUEST_BYTES={RequestBytes} MARKER={MarkerReturned}";
}

internal static class CurlFunctionPointerProbe
{
    private const string Marker = "agile-function-pointer-probe";

    public static CurlProbeResult Run(Assembly assembly, int? token)
    {
        var method = ResolveMethod(assembly, token);
        var parameters = method.GetParameters();
        if (method.IsStatic || method.ReturnType != typeof(string) || parameters.Length != 2
            || parameters.Any(parameter => parameter.ParameterType
                != typeof(Dictionary<string, string>)))
            throw new InvalidOperationException(
                "Curl probe requires an instance Dictionary<string,string> method");

        var pointers = IlTokenReader.FunctionPointers(method);
        if (pointers.Count != 1)
            return new CurlProbeResult(false, pointers.Count, 0, 0, false);
        RepairLocalCaBundleReference(assembly);
        object instance = Activator.CreateInstance(method.DeclaringType!, nonPublic: true)
            ?? throw new InvalidOperationException("could not construct Curl declaring type");
        string encodedResponse = EncodeLocalResponse(instance);
        var urlFields = IlTokenReader.StaticFieldLoads(method).Where(field =>
            field.FieldType == typeof(string)
            && field.GetValue(null) is string value
            && Uri.TryCreate(value, UriKind.Absolute, out var uri)
            && uri.Scheme is "http" or "https").ToArray();
        if (urlFields.Length != 1)
            throw new InvalidOperationException(
                $"expected one absolute URL field, found {urlFields.Length}");

        object? originalUrl = urlFields[0].GetValue(null);
        using var server = new LoopbackHttpServer(encodedResponse);

        try
        {
            server.Start();
            urlFields[0].SetValue(null, server.Prefix);
            var payload = new Dictionary<string, string> { ["probe"] = "payload" };
            var post = new Dictionary<string, string> { ["probe"] = "post" };
            string? result = method.Invoke(instance, new object[] { payload, post }) as string;
            server.Wait(TimeSpan.FromSeconds(10));
            bool markerReturned = result?.Contains(Marker) == true;
            return new CurlProbeResult(server.Requests == 1 && markerReturned,
                pointers.Count, server.Requests, server.RequestBytes, markerReturned);
        }
        finally
        {
            urlFields[0].SetValue(null, originalUrl);
            (instance as IDisposable)?.Dispose();
        }
    }

    private static MethodInfo ResolveMethod(Assembly assembly, int? token)
    {
        if (token is int metadataToken)
            return assembly.ManifestModule.ResolveMethod(metadataToken) as MethodInfo
                ?? throw new InvalidOperationException($"0x{metadataToken:X8} is not a method");

        var matches = assembly.GetTypes()
            .SelectMany(type => type.GetMethods(BindingFlags.Instance | BindingFlags.Public
                | BindingFlags.NonPublic | BindingFlags.DeclaredOnly))
            .Where(IsCandidate)
            .ToArray();
        return matches.Length == 1 ? matches[0] : throw new InvalidOperationException(
            $"automatic Curl function-pointer discovery found {matches.Length} candidates");
    }

    private static bool IsCandidate(MethodInfo method)
    {
        var parameters = method.GetParameters();
        if (method.IsAbstract || method.ReturnType != typeof(string) || parameters.Length != 2
            || parameters.Any(parameter => parameter.ParameterType
                != typeof(Dictionary<string, string>)))
            return false;
        try
        {
            return IlTokenReader.FunctionPointers(method).Count == 1;
        }
        catch (Exception exception) when (exception is InvalidOperationException
            or ArgumentException or BadImageFormatException)
        {
            return false;
        }
    }

    private static string EncodeLocalResponse(object instance)
    {
        object rsa = instance.GetType().GetFields(BindingFlags.Instance
                | BindingFlags.Public | BindingFlags.NonPublic)
            .Where(field => field.FieldType == typeof(RSA))
            .Select(field => field.GetValue(instance))
            .Single(value => value is not null)!;
        var jwtType = Assembly.Load("jose-jwt").GetType("Jose.JWT", throwOnError: true);
        var encode = jwtType.GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Single(candidate => candidate.Name == "Encode"
                && candidate.ReturnType == typeof(string)
                && candidate.GetParameters().Length == 7
                && candidate.GetParameters()[0].ParameterType == typeof(object)
                && candidate.GetParameters()[1].ParameterType == typeof(object));
        var parameters = encode.GetParameters();
        object algorithm = Enum.ToObject(parameters[2].ParameterType, 1);
        object encryption = Enum.ToObject(parameters[3].ParameterType, 5);
        object compression = Activator.CreateInstance(parameters[4].ParameterType);
        return (string)encode.Invoke(null, new[]
        {
            Marker, rsa, algorithm, encryption, compression, null, null,
        });
    }

    private static void RepairLocalCaBundleReference(Assembly assembly)
    {
        string localPath = Path.Combine(Environment.CurrentDirectory, "curl-ca-bundle.crt");
        if (!File.Exists(localPath))
            throw new FileNotFoundException("target has no local curl CA bundle", localPath);
        foreach (var field in assembly.GetTypes().SelectMany(type => type.GetFields(
            BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic))
            .Where(field => field.FieldType == typeof(FileInfo)))
        {
            if (field.GetValue(null) is not FileInfo file
                || !string.Equals(file.Name, "curl-ca-bundle.crt",
                    StringComparison.OrdinalIgnoreCase))
                continue;
            if (!file.Exists)
                field.SetValue(null, new FileInfo(localPath));
        }
    }
}
