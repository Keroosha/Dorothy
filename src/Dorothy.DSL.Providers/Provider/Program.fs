namespace Dorothy.DSL.Provider

open System
open System.Threading
open Pulumi.Experimental
open Pulumi.Experimental.Provider

module Program =
    [<EntryPoint>]
    let main argv =
        use cancellation = new CancellationTokenSource()
        Console.CancelKeyPress.Add(fun eventArgs ->
            eventArgs.Cancel <- true
            cancellation.Cancel())

        let factory = Func<IEngine, Pulumi.Experimental.Provider.Provider>(fun _ -> DorothyProvider() :> Pulumi.Experimental.Provider.Provider)
        Pulumi.Experimental.Provider.Provider.Serve(argv, DorothyProvider.Version, factory, cancellation.Token)
            .GetAwaiter()
            .GetResult()
        0
