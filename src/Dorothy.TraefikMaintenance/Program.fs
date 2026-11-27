module Dorothy.TraefikMaintenance.Program

open System
open Dorothy.HostHelper

[<EntryPoint>]
let main = function
    | [| "recover-stopped"; owner; digest |] ->
        try
            Environment.SetEnvironmentVariable("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            Traefik.maintainStopped owner digest
            Console.Out.WriteLine("Journal archived; owned service remains stopped. Verify the next managed Apply and its real traffic.")
            0
        with
        | :? Traefik.BackendError as error -> Console.Error.WriteLine(error.Message); 1
        | _ -> Console.Error.WriteLine("Stopped maintenance failed. Preserve the journal and its archive."); 1
    | _ ->
        Console.Error.WriteLine("Usage: dorothy-traefik-maintenance recover-stopped OWNER JOURNAL_SHA256")
        2
