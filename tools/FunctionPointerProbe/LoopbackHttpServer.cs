using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

/// <summary>
/// Minimal one-request HTTP/1.1 server used by the runtime probe. TcpListener avoids the URL ACL,
/// HTTP.sys and platform-policy dependencies of HttpListener while keeping all traffic loopback.
/// </summary>
internal sealed class LoopbackHttpServer : IDisposable
{
    private readonly TcpListener _listener = new TcpListener(IPAddress.Loopback, 0);
    private readonly byte[] _response;
    private Thread? _thread;
    private Exception? _error;

    public LoopbackHttpServer(string response) => _response = Encoding.UTF8.GetBytes(response);

    public string Prefix { get; private set; } = "";
    public int Requests { get; private set; }
    public int RequestBytes { get; private set; }

    public void Start()
    {
        _listener.Start();
        int port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        Prefix = $"http://127.0.0.1:{port}/";
        _thread = new Thread(ServeOne) { IsBackground = true };
        _thread.Start();
    }

    public void Wait(TimeSpan timeout)
    {
        if (_thread is null || !_thread.Join(timeout))
            throw new TimeoutException("local HTTP server did not receive a complete request");
        if (_error is not null)
            throw new InvalidOperationException("local HTTP server failed", _error);
    }

    private void ServeOne()
    {
        try
        {
            using var client = _listener.AcceptTcpClient();
            client.ReceiveTimeout = 10_000;
            client.SendTimeout = 10_000;
            using NetworkStream stream = client.GetStream();
            byte[] headerBytes = ReadHeaders(stream);
            string headers = Encoding.ASCII.GetString(headerBytes);
            int contentLength = ParseContentLength(headers);
            if (headers.Split(new[] { "\r\n" }, StringSplitOptions.None).Any(line =>
                line.StartsWith("Expect:", StringComparison.OrdinalIgnoreCase)
                && line.IndexOf("100-continue", StringComparison.OrdinalIgnoreCase) >= 0))
            {
                byte[] interim = Encoding.ASCII.GetBytes("HTTP/1.1 100 Continue\r\n\r\n");
                stream.Write(interim, 0, interim.Length);
            }

            byte[] request = new byte[contentLength];
            int read = 0;
            while (read < request.Length)
            {
                int count = stream.Read(request, read, request.Length - read);
                if (count == 0)
                    throw new EndOfStreamException("HTTP request body ended early");
                read += count;
            }
            RequestBytes = read;
            Requests = 1;

            byte[] responseHeaders = Encoding.ASCII.GetBytes(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
                + _response.Length + "\r\nConnection: close\r\n\r\n");
            stream.Write(responseHeaders, 0, responseHeaders.Length);
            stream.Write(_response, 0, _response.Length);
            stream.Flush();
        }
        catch (Exception exception)
        {
            _error = exception;
        }
    }

    private static byte[] ReadHeaders(NetworkStream stream)
    {
        using var buffer = new MemoryStream();
        int matched = 0;
        byte[] marker = { 13, 10, 13, 10 };
        while (buffer.Length < 64 * 1024)
        {
            int value = stream.ReadByte();
            if (value < 0)
                throw new EndOfStreamException("HTTP request headers ended early");
            buffer.WriteByte((byte)value);
            matched = value == marker[matched] ? matched + 1 : value == marker[0] ? 1 : 0;
            if (matched == marker.Length)
                return buffer.ToArray();
        }
        throw new InvalidDataException("HTTP request headers exceed 64 KiB");
    }

    private static int ParseContentLength(string headers)
    {
        string? line = headers.Split(new[] { "\r\n" }, StringSplitOptions.None)
            .FirstOrDefault(item => item.StartsWith(
                "Content-Length:", StringComparison.OrdinalIgnoreCase));
        if (line is null || !int.TryParse(line.Substring(line.IndexOf(':') + 1).Trim(),
            out int length) || length < 0)
            throw new InvalidDataException("HTTP request has no valid Content-Length");
        return length;
    }

    public void Dispose()
    {
        _listener.Stop();
        if (_thread is { IsAlive: true })
            _thread.Join(TimeSpan.FromSeconds(1));
    }
}
