using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Security.Cryptography;
using System.Text;

internal static class Program
{
    private static readonly Dictionary<ushort, OpCode> OpCodesByValue = BuildOpCodes();
    private static string _baseDirectory = "";

    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length != 2 || !TryToken(args[1], out int token))
        {
            Console.Error.WriteLine("usage: MethodStateProbe <target.exe> <method-token>");
            return 2;
        }

        string target = Path.GetFullPath(args[0]);
        _baseDirectory = Path.GetDirectoryName(target) ?? Environment.CurrentDirectory;
        Environment.CurrentDirectory = _baseDirectory;
        AppDomain.CurrentDomain.AssemblyResolve += ResolveBesideTarget;

        object? instance = null;
        try
        {
            var assembly = Assembly.LoadFrom(target);
            var method = assembly.ManifestModule.ResolveMethod(token) as MethodInfo
                ?? throw new InvalidOperationException($"0x{token:X8} is not a method");
            if (method.GetParameters().Length != 0)
                throw new InvalidOperationException("probe currently requires a parameterless method");
            if (!method.IsStatic)
            {
                var type = method.DeclaringType
                    ?? throw new InvalidOperationException("method has no declaring type");
                instance = Activator.CreateInstance(type, nonPublic: true)
                    ?? throw new InvalidOperationException("could not construct the declaring type");
            }

            method.Invoke(instance, null);
            var fields = WrittenStaticFields(method).OrderBy(field => field.MetadataToken).ToArray();
            Console.WriteLine($"METHOD=0x{token:X8} WRITTEN_STATIC_FIELDS={fields.Length}");
            foreach (var field in fields)
                Console.WriteLine($"0x{field.MetadataToken:X8}|{field.FieldType.FullName}|"
                    + Fingerprint(field.GetValue(null)));
            return 0;
        }
        catch (Exception exception)
        {
            while (exception is TargetInvocationException { InnerException: not null })
                exception = exception.InnerException;
            Console.Error.WriteLine($"{exception.GetType().FullName}: {exception.Message}");
            Console.Error.WriteLine(exception.StackTrace);
            return 1;
        }
        finally
        {
            (instance as IDisposable)?.Dispose();
        }
    }

    private static IEnumerable<FieldInfo> WrittenStaticFields(MethodInfo method)
    {
        byte[] il = method.GetMethodBody()?.GetILAsByteArray()
            ?? throw new InvalidOperationException("method has no CIL body");
        var fields = new Dictionary<int, FieldInfo>();
        for (int offset = 0; offset < il.Length;)
        {
            OpCode opcode = ReadOpCode(il, ref offset);
            int operandSize = OperandSize(opcode.OperandType, il, offset);
            if (opcode == OpCodes.Stsfld)
            {
                int fieldToken = BitConverter.ToInt32(il, offset);
                var field = method.Module.ResolveField(fieldToken,
                    method.DeclaringType?.GetGenericArguments(), method.GetGenericArguments());
                if (field.IsStatic)
                    fields[field.MetadataToken] = field;
            }
            offset += operandSize;
        }
        return fields.Values;
    }

    private static OpCode ReadOpCode(byte[] il, ref int offset)
    {
        ushort value = il[offset++];
        if (value == 0xFE)
            value = (ushort)(0xFE00 | il[offset++]);
        return OpCodesByValue.TryGetValue(value, out var opcode)
            ? opcode : throw new BadImageFormatException($"unknown opcode 0x{value:X4}");
    }

    private static int OperandSize(OperandType type, byte[] il, int offset) => type switch
    {
        OperandType.InlineNone => 0,
        OperandType.ShortInlineBrTarget or OperandType.ShortInlineI or OperandType.ShortInlineVar => 1,
        OperandType.InlineVar => 2,
        OperandType.InlineI or OperandType.InlineBrTarget or OperandType.InlineField
            or OperandType.InlineMethod or OperandType.InlineSig or OperandType.InlineString
            or OperandType.InlineTok or OperandType.InlineType or OperandType.ShortInlineR => 4,
        OperandType.InlineI8 or OperandType.InlineR => 8,
        OperandType.InlineSwitch => 4 + BitConverter.ToInt32(il, offset) * 4,
        _ => throw new BadImageFormatException($"unsupported operand type {type}"),
    };

    private static string Fingerprint(object? value)
    {
        if (value is null)
            return "null";
        if (value is string text)
            return $"string:{text.Length}:{Hash(Encoding.UTF8.GetBytes(text))}";
        if (value is byte[] bytes)
            return $"bytes:{bytes.Length}:{Hash(bytes)}";
        if (value is char[] chars)
            return $"chars:{chars.Length}:{Hash(Encoding.Unicode.GetBytes(chars))}";
        if (value is DateTime dateTime)
            return $"datetime:{dateTime.ToUniversalTime().Ticks}";
        if (value is Guid guid)
            return "guid:" + guid.ToString("D");
        var type = value.GetType();
        if (type.IsEnum)
            return "enum:" + Convert.ToUInt64(value, CultureInfo.InvariantCulture);
        if (value is IFormattable formattable && type.IsPrimitive)
            return "primitive:" + formattable.ToString(null, CultureInfo.InvariantCulture);
        return "object:" + type.FullName;
    }

    private static string Hash(byte[] bytes)
    {
        using var sha = SHA256.Create();
        return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "");
    }

    private static Assembly? ResolveBesideTarget(object? _, ResolveEventArgs args)
    {
        string path = Path.Combine(_baseDirectory, new AssemblyName(args.Name).Name + ".dll");
        return File.Exists(path) ? Assembly.LoadFrom(path) : null;
    }

    private static bool TryToken(string value, out int token)
    {
        string normalized = value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? value.Substring(2) : value;
        return int.TryParse(normalized, NumberStyles.HexNumber,
            CultureInfo.InvariantCulture, out token);
    }

    private static Dictionary<ushort, OpCode> BuildOpCodes() => typeof(OpCodes)
        .GetFields(BindingFlags.Public | BindingFlags.Static)
        .Where(field => field.FieldType == typeof(OpCode))
        .Select(field => (OpCode)field.GetValue(null))
        .ToDictionary(opcode => unchecked((ushort)opcode.Value));
}
