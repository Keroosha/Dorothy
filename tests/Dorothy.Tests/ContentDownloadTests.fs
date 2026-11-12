namespace Dorothy.Tests

open System
open System.IO
open System.Net
open System.Net.Http
open System.Text
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Dorothy.HostHelper
open NUnit.Framework

type private DownloadHandler(send: HttpRequestMessage -> CancellationToken -> Task<HttpResponseMessage>) =
    inherit HttpMessageHandler()
    override _.SendAsync(request, ct) = send request ct

type private StalledDownloadStream(started: ManualResetEventSlim) =
    inherit Stream()
    override _.CanRead = true
    override _.CanWrite = false
    override _.CanSeek = false
    override _.Length = raise (NotSupportedException())
    override _.Position with get () = raise (NotSupportedException()) and set _ = raise (NotSupportedException())
    override _.Flush() = ()
    override _.Seek(_, _) = raise (NotSupportedException())
    override _.SetLength(_) = raise (NotSupportedException())
    override _.Write(_, _, _) = raise (NotSupportedException())
    override _.Read(_, _, _) = failwith "The body must be read asynchronously with cancellation."
    override _.ReadAsync(_: Memory<byte>, ct: CancellationToken) =
        started.Set()
        ValueTask<int>(task {
            do! Task.Delay(Timeout.Infinite, ct)
            return 0
        })

[<TestFixture>]
type ContentDownloadTests() =
    let request () = JsonDocument.Parse("""{"url":"https://origin.example/start","headers":{"Authorization":"Bearer fixture-secret","X-Private":"fixture-private"}}""")
    let response status content = new HttpResponseMessage(status, Content = content)
    let finish (operation: Task) = operation.WaitAsync(TimeSpan.FromSeconds 5.).GetAwaiter().GetResult()

    [<TestCase("/asset", true)>]
    [<TestCase("https://origin.example/asset", true)>]
    [<TestCase("https://other.example/asset", false)>]
    [<TestCase("https://origin.example:8443/asset", false)>]
    member _.``Redirects forward credentials only to the original origin``(location: string, forward: bool) =
        use root = new TemporaryDirectory("dorothy-redirect-")
        use desired = request ()
        let observed = ResizeArray<Uri * bool * bool>()
        use handler = new DownloadHandler(fun message _ ->
            observed.Add(message.RequestUri, message.Headers.Contains "Authorization", message.Headers.Contains "X-Private")
            let result =
                if observed.Count = 1 then
                    let redirect = response HttpStatusCode.Found (new ByteArrayContent([||]))
                    redirect.Headers.Location <- Uri(location, UriKind.RelativeOrAbsolute)
                    redirect
                else response HttpStatusCode.OK (new ByteArrayContent(Encoding.UTF8.GetBytes "verified-body"))
            Task.FromResult result)
        use client = new HttpClient(handler, Timeout = Timeout.InfiniteTimeSpan)
        let destination = Path.Combine(root.Path, "download")
        Content.download client (TimeSpan.FromSeconds 3.) desired.RootElement destination |> finish
        Assert.That(File.ReadAllText destination, Is.EqualTo "verified-body")
        Assert.That(observed.Count, Is.EqualTo 2)
        let _, firstAuth, firstPrivate = observed[0]
        let target, nextAuth, nextPrivate = observed[1]
        Assert.That(firstAuth && firstPrivate, Is.True)
        Assert.That(target, Is.EqualTo(Uri(Uri "https://origin.example/start", location)))
        Assert.That(nextAuth, Is.EqualTo forward)
        Assert.That(nextPrivate, Is.EqualTo forward)

    [<Test>]
    member _.``TLS downgrade is rejected before issuing an insecure request``() =
        use root = new TemporaryDirectory("dorothy-downgrade-")
        use desired = request ()
        let observed = ResizeArray<Uri>()
        use handler = new DownloadHandler(fun message _ ->
            observed.Add message.RequestUri
            let redirect = response HttpStatusCode.Found (new ByteArrayContent([||]))
            redirect.Headers.Location <- Uri "http://origin.example/insecure"
            Task.FromResult redirect)
        use client = new HttpClient(handler, Timeout = Timeout.InfiniteTimeSpan)
        let destination = Path.Combine(root.Path, "download")
        Assert.Throws<Content.BackendError>(fun () -> Content.download client (TimeSpan.FromSeconds 3.) desired.RootElement destination |> finish) |> ignore
        Assert.That(observed.Count, Is.EqualTo 1)
        Assert.That(File.Exists destination, Is.False)

    [<Test>]
    member _.``Total deadline cancels a stalled response body after headers``() =
        use root = new TemporaryDirectory("dorothy-body-timeout-")
        use desired = request ()
        use started = new ManualResetEventSlim()
        use handler = new DownloadHandler(fun _ _ -> Task.FromResult(response HttpStatusCode.OK (new StreamContent(new StalledDownloadStream(started)))))
        use client = new HttpClient(handler, Timeout = Timeout.InfiniteTimeSpan)
        let destination = Path.Combine(root.Path, "download")
        let error = Assert.Throws<Content.BackendError>(fun () -> Content.download client (TimeSpan.FromMilliseconds 500.) desired.RootElement destination |> finish)
        Assert.That(started.IsSet, Is.True)
        Assert.That(error.Message, Does.Contain "timeout")
        Assert.That(error.Message, Does.Not.Contain "fixture-secret")
        // Cancellation must close the staging stream; acquire owns deleting this unpublished file.
        use exclusive = File.Open(destination, FileMode.Open, FileAccess.ReadWrite, FileShare.None)
        Assert.That(exclusive.Length, Is.Zero)

    [<Test>]
    member _.``Connection timeout bounds a connection that never completes``() =
        use root = new TemporaryDirectory("dorothy-connect-timeout-")
        use desired = request ()
        use started = new ManualResetEventSlim()
        use handler = new SocketsHttpHandler(AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromMilliseconds 500., UseProxy = false)
        handler.ConnectCallback <- Func<SocketsHttpConnectionContext, CancellationToken, ValueTask<Stream>>(fun _ ct ->
            started.Set()
            ValueTask<Stream>(task {
                do! Task.Delay(Timeout.Infinite, ct)
                return Stream.Null
            }))
        use client = new HttpClient(handler, Timeout = Timeout.InfiniteTimeSpan)
        let destination = Path.Combine(root.Path, "download")
        Assert.Throws<Content.BackendError>(fun () -> Content.download client (TimeSpan.FromSeconds 3.) desired.RootElement destination |> finish) |> ignore
        Assert.That(started.IsSet, Is.True)
        Assert.That(File.Exists destination, Is.False)
