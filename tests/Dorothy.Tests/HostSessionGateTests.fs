module Dorothy.Tests.HostSessionGateTests

open System
open System.Threading
open System.Threading.Tasks
open NUnit.Framework
open Dorothy.DSL.Provider

let private connection address port =
    { Address = address; User = "deploy"; Port = port; IdentityFile = None }

/// Starts `count` operations against the given connections and returns the peak number that ran at once per key.
let private peakConcurrency (targets: SshConnection list) =
    let active = Collections.Concurrent.ConcurrentDictionary<string, int ref>()
    let peaks = Collections.Concurrent.ConcurrentDictionary<string, int>()

    let operation (target: SshConnection) =
        let key = $"{target.Address.ToLowerInvariant()}:{target.Port}"
        HostSessionGate.run target CancellationToken.None (fun () ->
            task {
                let counter = active.GetOrAdd(key, fun _ -> ref 0)
                let now = Interlocked.Increment(&counter.contents)
                peaks.AddOrUpdate(key, now, fun _ previous -> max previous now) |> ignore
                do! Task.Delay 30
                Interlocked.Decrement(&counter.contents) |> ignore
                return key
            })

    let results = targets |> List.map operation |> Array.ofList |> Task.WhenAll
    results.Wait(TimeSpan.FromSeconds 30.) |> ignore
    Assert.That(results.IsCompletedSuccessfully, Is.True)
    peaks

[<TestFixture>]
type HostSessionGateTests() =
    [<Test>]
    member _.``limits concurrent SSH sessions to one host``() =
        let host = connection $"gate-one-{Guid.NewGuid():N}.test" 22
        let peaks = peakConcurrency (List.replicate 24 host)
        Assert.That(peaks.Values |> Seq.max, Is.EqualTo(HostSessionGate.MaxSessionsPerHost))

    [<Test>]
    member _.``gates hosts and ports independently but ignores address case``() =
        let suffix = Guid.NewGuid().ToString("N")
        let first = connection $"gate-a-{suffix}.test" 22
        let firstUpper = connection ($"gate-a-{suffix}.test".ToUpperInvariant()) 22
        let otherPort = connection $"gate-a-{suffix}.test" 2222
        let second = connection $"gate-b-{suffix}.test" 22
        let targets =
            List.replicate 6 first @ List.replicate 6 firstUpper @ List.replicate 12 otherPort @ List.replicate 12 second
        let peaks = peakConcurrency targets
        Assert.That(peaks.Count, Is.EqualTo(3))
        for peak in peaks.Values do
            Assert.That(peak, Is.EqualTo(HostSessionGate.MaxSessionsPerHost))

    [<Test>]
    member _.``releases the slot when an operation fails or a waiter is cancelled``() =
        let host = connection $"gate-release-{Guid.NewGuid():N}.test" 22

        for _ in 1 .. HostSessionGate.MaxSessionsPerHost + 1 do
            let failing = HostSessionGate.run host CancellationToken.None (fun () -> task { return failwith "boom" })
            Assert.Throws<AggregateException>(fun () -> failing.Wait()) |> ignore

        use holdAll = new SemaphoreSlim(0)
        let hold () =
            task {
                do! holdAll.WaitAsync()
                return 0
            }

        let holders =
            List.init HostSessionGate.MaxSessionsPerHost (fun _ -> HostSessionGate.run host CancellationToken.None hold)

        use cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds 100.)
        let waiter = HostSessionGate.run host cancellation.Token (fun () -> task { return 1 })
        Assert.Throws<AggregateException>(fun () -> waiter.Wait()) |> ignore
        Assert.That(waiter.IsCanceled, Is.True)

        holdAll.Release(HostSessionGate.MaxSessionsPerHost) |> ignore
        Task.WaitAll(holders |> List.map (fun holder -> holder :> Task) |> Array.ofList)
        let after = HostSessionGate.run host CancellationToken.None (fun () -> task { return 2 })
        Assert.That(after.Wait(TimeSpan.FromSeconds 5.), Is.True)
        Assert.That(after.Result, Is.EqualTo(2))
