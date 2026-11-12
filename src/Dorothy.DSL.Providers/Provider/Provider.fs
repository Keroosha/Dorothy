namespace Dorothy.DSL.Provider

open System
open System.IO
open System.Text
open System.Text.Json
open System.Threading
open Pulumi.Experimental
open Pulumi.Experimental.Provider

module private ProviderSchema =
    let combined =
        lazy
            use aptDocument = JsonDocument.Parse(AptProvider.Schema)
            use ufwDocument = JsonDocument.Parse(UfwProvider.Schema)
            use traefikDocument = JsonDocument.Parse(TraefikProvider.Schema)
            use dockerEngineDocument = JsonDocument.Parse(DockerEngineProvider.Schema)
            use sshdDocument = JsonDocument.Parse(SshdProvider.Schema)
            use fail2banDocument = JsonDocument.Parse(Fail2BanProvider.Schema)
            use swapfileDocument = JsonDocument.Parse(SwapfileProvider.Schema)
            use usersDocument = JsonDocument.Parse(UsersProvider.Schema)
            use sudoDocument = JsonDocument.Parse(SudoProvider.Schema)
            use contentServicesDocument = JsonDocument.Parse(ContentServicesProvider.Schema)
            use stream = new MemoryStream()
            use writer = new Utf8JsonWriter(stream)
            let documents = [ aptDocument; ufwDocument; traefikDocument; dockerEngineDocument; swapfileDocument; sshdDocument; fail2banDocument; usersDocument; sudoDocument; contentServicesDocument ]

            let writeMergedObject (propertyName: string) =
                writer.WritePropertyName(propertyName)
                writer.WriteStartObject()
                for document in documents do
                    let mutable section = Unchecked.defaultof<JsonElement>
                    if document.RootElement.TryGetProperty(propertyName, &section) then
                        for entry in section.EnumerateObject() do
                            entry.WriteTo(writer)
                writer.WriteEndObject()

            writer.WriteStartObject()
            for property in aptDocument.RootElement.EnumerateObject() do
                match property.Name with
                | "types"
                | "resources" -> writeMergedObject property.Name
                | _ -> property.WriteTo(writer)
            writer.WriteEndObject()
            writer.Flush()
            Encoding.UTF8.GetString(stream.GetBuffer(), 0, int stream.Length)

[<Sealed>]
type DorothyProvider() =
    inherit Pulumi.Experimental.Provider.Provider()

    let apt = AptProvider()
    let ufw = UfwProvider()
    let traefik = TraefikProvider()
    let dockerEngine = DockerEngineProvider()
    let swapfile = SwapfileProvider()
    let sshd = SshdProvider()
    let fail2ban = Fail2BanProvider()
    let users = UsersProvider()
    let sudo = SudoProvider()
    let contentServices = ContentServicesProvider()
    let isContentService token = token = ContentServicesProvider.ContentToken || token = ContentServicesProvider.ServiceToken

    static member Version = AptProvider.Version

    override _.GetSchema(_request: GetSchemaRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        let response = GetSchemaResponse()
        response.Schema <- ProviderSchema.combined.Value
        System.Threading.Tasks.Task.FromResult(response)

    override _.CheckConfig(request: CheckRequest, ct: CancellationToken) = apt.CheckConfig(request, ct)

    override _.DiffConfig(request: DiffRequest, ct: CancellationToken) = apt.DiffConfig(request, ct)

    override _.Configure(request: ConfigureRequest, ct: CancellationToken) = apt.Configure(request, ct)

    override _.Check(request: CheckRequest, ct: CancellationToken) =
        if request.Type = UfwProvider.ResourceToken then ufw.Check(request, ct)
        elif request.Type = TraefikProvider.ResourceToken then traefik.Check(request, ct)
        elif request.Type = DockerEngineProvider.ResourceToken then dockerEngine.Check(request, ct)
        elif request.Type = SwapfileProvider.ResourceToken then swapfile.Check(request, ct)
        elif request.Type = SshdProvider.ResourceToken then sshd.Check(request, ct)
        elif request.Type = Fail2BanProvider.ResourceToken then fail2ban.Check(request, ct)
        elif request.Type = UsersProvider.ResourceToken then users.Check(request, ct)
        elif request.Type = SudoProvider.ResourceToken then sudo.Check(request, ct)
        elif isContentService request.Type then contentServices.Check(request, ct)
        else apt.Check(request, ct)

    override _.Diff(request: DiffRequest, ct: CancellationToken) =
        if request.Type = UfwProvider.ResourceToken then ufw.Diff(request, ct)
        elif request.Type = TraefikProvider.ResourceToken then traefik.Diff(request, ct)
        elif request.Type = DockerEngineProvider.ResourceToken then dockerEngine.Diff(request, ct)
        elif request.Type = SwapfileProvider.ResourceToken then swapfile.Diff(request, ct)
        elif request.Type = SshdProvider.ResourceToken then sshd.Diff(request, ct)
        elif request.Type = Fail2BanProvider.ResourceToken then fail2ban.Diff(request, ct)
        elif request.Type = UsersProvider.ResourceToken then users.Diff(request, ct)
        elif request.Type = SudoProvider.ResourceToken then sudo.Diff(request, ct)
        elif isContentService request.Type then contentServices.Diff(request, ct)
        else apt.Diff(request, ct)

    override _.Create(request: CreateRequest, ct: CancellationToken) =
        if request.Type = UfwProvider.ResourceToken then ufw.Create(request, ct)
        elif request.Type = TraefikProvider.ResourceToken then traefik.Create(request, ct)
        elif request.Type = DockerEngineProvider.ResourceToken then dockerEngine.Create(request, ct)
        elif request.Type = SwapfileProvider.ResourceToken then swapfile.Create(request, ct)
        elif request.Type = SshdProvider.ResourceToken then sshd.Create(request, ct)
        elif request.Type = Fail2BanProvider.ResourceToken then fail2ban.Create(request, ct)
        elif request.Type = UsersProvider.ResourceToken then users.Create(request, ct)
        elif request.Type = SudoProvider.ResourceToken then sudo.Create(request, ct)
        elif isContentService request.Type then contentServices.Create(request, ct)
        else apt.Create(request, ct)

    override _.Read(request: ReadRequest, ct: CancellationToken) =
        if request.Type = UfwProvider.ResourceToken then ufw.Read(request, ct)
        elif request.Type = TraefikProvider.ResourceToken then traefik.Read(request, ct)
        elif request.Type = DockerEngineProvider.ResourceToken then dockerEngine.Read(request, ct)
        elif request.Type = SwapfileProvider.ResourceToken then swapfile.Read(request, ct)
        elif request.Type = SshdProvider.ResourceToken then sshd.Read(request, ct)
        elif request.Type = Fail2BanProvider.ResourceToken then fail2ban.Read(request, ct)
        elif request.Type = UsersProvider.ResourceToken then users.Read(request, ct)
        elif request.Type = SudoProvider.ResourceToken then sudo.Read(request, ct)
        elif isContentService request.Type then contentServices.Read(request, ct)
        else apt.Read(request, ct)

    override _.Update(request: UpdateRequest, ct: CancellationToken) =
        if request.Type = UfwProvider.ResourceToken then ufw.Update(request, ct)
        elif request.Type = TraefikProvider.ResourceToken then traefik.Update(request, ct)
        elif request.Type = DockerEngineProvider.ResourceToken then dockerEngine.Update(request, ct)
        elif request.Type = SwapfileProvider.ResourceToken then swapfile.Update(request, ct)
        elif request.Type = SshdProvider.ResourceToken then sshd.Update(request, ct)
        elif request.Type = Fail2BanProvider.ResourceToken then fail2ban.Update(request, ct)
        elif request.Type = UsersProvider.ResourceToken then users.Update(request, ct)
        elif request.Type = SudoProvider.ResourceToken then sudo.Update(request, ct)
        elif isContentService request.Type then contentServices.Update(request, ct)
        else apt.Update(request, ct)

    override _.Delete(request: DeleteRequest, ct: CancellationToken) =
        if request.Type = UfwProvider.ResourceToken then ufw.Delete(request, ct)
        elif request.Type = TraefikProvider.ResourceToken then traefik.Delete(request, ct)
        elif request.Type = DockerEngineProvider.ResourceToken then dockerEngine.Delete(request, ct)
        elif request.Type = SwapfileProvider.ResourceToken then swapfile.Delete(request, ct)
        elif request.Type = SshdProvider.ResourceToken then sshd.Delete(request, ct)
        elif request.Type = Fail2BanProvider.ResourceToken then fail2ban.Delete(request, ct)
        elif request.Type = UsersProvider.ResourceToken then users.Delete(request, ct)
        elif request.Type = SudoProvider.ResourceToken then sudo.Delete(request, ct)
        elif isContentService request.Type then contentServices.Delete(request, ct)
        else apt.Delete(request, ct)
