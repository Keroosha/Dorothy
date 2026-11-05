namespace Dorothy.HostHelper

open System
open System.Globalization
open System.IO
open System.Numerics
open System.Text
open System.Text.Json
open System.Text.RegularExpressions

module internal Fail2BanCliData =
    [<StructuralEquality; StructuralComparison>]
    type PythonLiteral =
        | PyNone
        | PyBoolean of bool
        | PyInteger of BigInteger
        | PyFloat of float
        | PyString of string
        | PyList of PythonLiteral list
        | PyTuple of PythonLiteral list
        | PyDictionary of (PythonLiteral * PythonLiteral) list

    let private invalidDump () =
        raise (FormatException("Invalid fail2ban-client dump."))

    let private appendCodePoint (builder: StringBuilder) (codePoint: int64) =
        if codePoint < 0L || codePoint > 0x10FFFFL then
            invalidDump ()

        if codePoint <= 0xFFFFL then
            builder.Append(char (int codePoint)) |> ignore
        else
            let adjusted = int (codePoint - 0x10000L)
            builder.Append(char (0xD800 + (adjusted >>> 10))) |> ignore
            builder.Append(char (0xDC00 + (adjusted &&& 0x3FF))) |> ignore

    let private parseLiteral (source: string) =
        let mutable position = 0
        let sourceLength = source.Length

        let fail () = invalidDump ()

        let peek () =
            if position < sourceLength then Some source[position] else None

        let skipWhitespace () =
            while position < sourceLength && Char.IsWhiteSpace(source[position]) do
                position <- position + 1

        let readDigits () =
            let start = position
            while position < sourceLength && source[position] >= '0' && source[position] <= '9' do
                position <- position + 1
            position - start

        let parseHexadecimalDigits count =
            let mutable value = 0L

            for _ in 1 .. count do
                if position >= sourceLength then
                    fail ()

                let digit =
                    match source[position] with
                    | c when c >= '0' && c <= '9' -> int c - int '0'
                    | c when c >= 'a' && c <= 'f' -> int c - int 'a' + 10
                    | c when c >= 'A' && c <= 'F' -> int c - int 'A' + 10
                    | _ -> fail ()

                value <- value * 16L + int64 digit
                position <- position + 1

            value

        let rec parseValue () =
            skipWhitespace ()

            match peek () with
            | Some '[' -> parseList ()
            | Some '(' -> parseTuple ()
            | Some '{' -> parseDictionary ()
            | Some '\''
            | Some '"' -> parseString ()
            | Some 'N' -> parseWord "None" PyNone
            | Some 'T' -> parseWord "True" (PyBoolean true)
            | Some 'F' -> parseWord "False" (PyBoolean false)
            | Some '-' -> parseNumber ()
            | Some 'i' -> parseWord "inf" (PyFloat Double.PositiveInfinity)
            | Some 'n' -> parseWord "nan" (PyFloat Double.NaN)
            | Some character when (character >= '0' && character <= '9') || character = '.' -> parseNumber ()
            | _ -> fail ()

        and parseWord word value =
            if position + word.Length > sourceLength
               || String.CompareOrdinal(source, position, word, 0, word.Length) <> 0 then
                fail ()

            position <- position + word.Length
            value

        and parseString () =
            let quote = source[position]
            position <- position + 1
            let builder = StringBuilder()
            let mutable closed = false

            while position < sourceLength && not closed do
                let current = source[position]
                position <- position + 1

                if current = quote then
                    closed <- true
                elif current = '\\' then
                    if position >= sourceLength then
                        fail ()

                    let escape = source[position]
                    position <- position + 1

                    match escape with
                    | '\\' -> builder.Append('\\') |> ignore
                    | '\'' -> builder.Append('\'') |> ignore
                    | '"' -> builder.Append('"') |> ignore
                    | 'a' -> builder.Append('\u0007') |> ignore
                    | 'b' -> builder.Append('\b') |> ignore
                    | 'f' -> builder.Append('\f') |> ignore
                    | 'n' -> builder.Append('\n') |> ignore
                    | 'r' -> builder.Append('\r') |> ignore
                    | 't' -> builder.Append('\t') |> ignore
                    | 'v' -> builder.Append('\u000B') |> ignore
                    | 'x' -> parseHexadecimalDigits 2 |> appendCodePoint builder
                    | 'u' -> parseHexadecimalDigits 4 |> appendCodePoint builder
                    | 'U' -> parseHexadecimalDigits 8 |> appendCodePoint builder
                    | c when c >= '0' && c <= '7' ->
                        let mutable value = int64 (int c - int '0')
                        let mutable digitCount = 1

                        while digitCount < 3
                              && position < sourceLength
                              && source[position] >= '0'
                              && source[position] <= '7' do
                            value <- value * 8L + int64 (int source[position] - int '0')
                            digitCount <- digitCount + 1
                            position <- position + 1

                        appendCodePoint builder value
                    | _ -> fail ()
                elif current = '\n' || current = '\r' then
                    fail ()
                else
                    builder.Append(current) |> ignore

            if not closed then
                fail ()

            PyString(builder.ToString())

        and parseNumber () =
            let start = position
            let isNegative = peek () = Some '-'

            if isNegative then
                position <- position + 1

            if isNegative
               && position + 3 <= sourceLength
               && String.CompareOrdinal(source, position, "inf", 0, 3) = 0 then
                position <- position + 3
                PyFloat Double.NegativeInfinity
            else
                let integerStart = position
                let integerDigits = readDigits ()
                let mutable hasFraction = false
                let mutable fractionDigits = 0

                if peek () = Some '.' then
                    hasFraction <- true
                    position <- position + 1
                    fractionDigits <- readDigits ()

                if integerDigits = 0 && fractionDigits = 0 then
                    fail ()

                let mutable hasExponent = false

                match peek () with
                | Some 'e'
                | Some 'E' ->
                    hasExponent <- true
                    position <- position + 1

                    if peek () = Some '+' || peek () = Some '-' then
                        position <- position + 1

                    if readDigits () = 0 then
                        fail ()
                | _ -> ()

                let isFloat = hasFraction || hasExponent

                if not isFloat && integerDigits > 1 && source[integerStart] = '0' then
                    fail ()

                let token = source.Substring(start, position - start)

                if isFloat then
                    let mutable value = 0.0

                    if not (Double.TryParse(token, NumberStyles.Float, CultureInfo.InvariantCulture, &value)) then
                        fail ()

                    PyFloat value
                else
                    let mutable value = BigInteger.Zero

                    if not (BigInteger.TryParse(token, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, &value)) then
                        fail ()

                    PyInteger value
        and parseList () =
            position <- position + 1
            skipWhitespace ()

            if peek () = Some ']' then
                position <- position + 1
                PyList []
            else
                let values = ResizeArray<PythonLiteral>()
                let mutable complete = false

                while not complete do
                    values.Add(parseValue ())
                    skipWhitespace ()

                    match peek () with
                    | Some ',' ->
                        position <- position + 1
                        skipWhitespace ()

                        if peek () = Some ']' then
                            position <- position + 1
                            complete <- true
                    | Some ']' ->
                        position <- position + 1
                        complete <- true
                    | _ -> fail ()

                PyList(List.ofSeq values)

        and parseTuple () =
            position <- position + 1
            skipWhitespace ()

            if peek () = Some ')' then
                position <- position + 1
                PyTuple []
            else
                let first = parseValue ()
                skipWhitespace ()

                if peek () <> Some ',' then
                    fail ()

                position <- position + 1
                skipWhitespace ()
                let values = ResizeArray<PythonLiteral>()
                values.Add(first)
                let mutable complete = false

                while not complete do
                    if peek () = Some ')' then
                        position <- position + 1
                        complete <- true
                    else
                        values.Add(parseValue ())
                        skipWhitespace ()

                        match peek () with
                        | Some ',' ->
                            position <- position + 1
                            skipWhitespace ()
                        | Some ')' ->
                            position <- position + 1
                            complete <- true
                        | _ -> fail ()

                PyTuple(List.ofSeq values)

        and parseDictionary () =
            position <- position + 1
            skipWhitespace ()

            if peek () = Some '}' then
                position <- position + 1
                PyDictionary []
            else
                let entries = ResizeArray<PythonLiteral * PythonLiteral>()
                let mutable complete = false

                while not complete do
                    let key = parseValue ()
                    skipWhitespace ()

                    if peek () <> Some ':' then
                        fail ()

                    position <- position + 1
                    let value = parseValue ()
                    entries.Add(key, value)
                    skipWhitespace ()

                    match peek () with
                    | Some ',' ->
                        position <- position + 1
                        skipWhitespace ()

                        if peek () = Some '}' then
                            position <- position + 1
                            complete <- true
                    | Some '}' ->
                        position <- position + 1
                        complete <- true
                    | _ -> fail ()

                PyDictionary(List.ofSeq entries)

        skipWhitespace ()
        let value = parseValue ()
        skipWhitespace ()

        if position <> sourceLength then
            fail ()

        value

    let tryParseResponse (response: string) =
        try
            if isNull response then
                None
            else
                Some(parseLiteral response)
        with _ ->
            None

    let parseDump (dump: string) =
        try
            if isNull dump then
                invalidDump ()

            use reader = new StringReader(dump)
            let commands = ResizeArray<PythonLiteral>()
            let mutable line = reader.ReadLine()

            while not (isNull line) do
                if not (String.IsNullOrWhiteSpace line) then
                    match tryParseResponse line with
                    | Some(PyList _ as command)
                    | Some(PyTuple _ as command) -> commands.Add command
                    | _ -> invalidDump ()

                line <- reader.ReadLine()

            if commands.Count = 0 then
                invalidDump ()

            List.ofSeq commands
        with _ ->
            invalidDump ()

    let private timestampDiagnosticPattern =
        Regex(
            @"^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]{3} (?<logger>[^\s]+)[ \t]+\[[0-9]+\]: (?<level>[A-Z]+)[ \t]+(?<message>.*)\z",
            RegexOptions.CultureInvariant
        )

    let private traceDiagnosticPattern =
        Regex(
            @"^ \+[ \t]+[0-9]+[ \t]+[0-9A-Fa-f]+[ \t]+(?<logger>[^\s]+)[ \t]+(?<level>[A-Z]+)[ \t]+(?<message>.*)\z",
            RegexOptions.CultureInvariant
        )

    let tryDiagnosticMessage (logger: string) (level: string) (line: string) =
        if isNull logger || isNull level || isNull line then
            None
        else
            let timestampMatch = timestampDiagnosticPattern.Match line
            let matchValue =
                if timestampMatch.Success then
                    timestampMatch
                else
                    traceDiagnosticPattern.Match line

            if matchValue.Success
               && String.Equals(matchValue.Groups["logger"].Value, logger, StringComparison.Ordinal)
               && String.Equals(matchValue.Groups["level"].Value, level, StringComparison.Ordinal) then
                Some matchValue.Groups["message"].Value
            else
                None

    let private pidLoggingBoundary =
        Regex(@", \[[^\]\r\n]+\] logging to ", RegexOptions.CultureInvariant)

    let tryEndpointFromDiagnostics (diagnostics: string) =
        if isNull diagnostics then
            None
        else
            let socketStem = "Using socket file"
            let socketMarker = socketStem + " "
            let pidStem = "Using pid file"
            let pidMarker = pidStem + " "
            let mutable socketCount = 0
            let mutable pidCount = 0
            let mutable socketPath: string option = None
            let mutable pidPath: string option = None
            let mutable malformed = false

            for rawLine in diagnostics.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries) do
                let line = rawLine.TrimEnd()

                match tryDiagnosticMessage "fail2ban" "INFO" line with
                | Some message ->
                    if message.StartsWith(socketStem, StringComparison.Ordinal) then
                        socketCount <- socketCount + 1

                        if not (message.StartsWith(socketMarker, StringComparison.Ordinal)) || socketPath.IsSome then
                            malformed <- true
                        else
                            let path = message.Substring(socketMarker.Length)

                            if String.IsNullOrWhiteSpace path then
                                malformed <- true
                            else
                                socketPath <- Some path

                    if message.StartsWith(pidStem, StringComparison.Ordinal) then
                        pidCount <- pidCount + 1

                        if not (message.StartsWith(pidMarker, StringComparison.Ordinal)) || pidPath.IsSome then
                            malformed <- true
                        else
                            let value = message.Substring(pidMarker.Length)
                            let boundaries = pidLoggingBoundary.Matches value

                            if boundaries.Count <> 1 || boundaries.[0].Index <= 0 then
                                malformed <- true
                            else
                                let boundary = boundaries.[0]
                                let path = value.Substring(0, boundary.Index)
                                let logPath = value.Substring(boundary.Index + boundary.Length)

                                if String.IsNullOrWhiteSpace path || String.IsNullOrWhiteSpace logPath then
                                    malformed <- true
                                else
                                    pidPath <- Some path
                | None -> ()

            match socketPath, pidPath with
            | Some socket, Some pid when socketCount = 1 && pidCount = 1 && not malformed -> Some(socket, pid)
            | _ -> None

    let private normalizedRoot (root: string) =
        Path.TrimEndingDirectorySeparator(Path.GetFullPath root)

    let private normalizeString (source: string) (value: string) =
        if source = Path.GetPathRoot source then
            value
        else
            let result = StringBuilder(value.Length)
            let mutable cursor = 0
            let mutable searching = true

            while searching do
                let start = value.IndexOf(source, cursor, StringComparison.Ordinal)

                if start < 0 then
                    result.Append(value, cursor, value.Length - cursor) |> ignore
                    searching <- false
                else
                    let finish = start + source.Length
                    let beforeIsBoundary =
                        start = 0
                        || not (
                            Char.IsLetterOrDigit(value[start - 1])
                            || value[start - 1] = '_'
                            || value[start - 1] = '.'
                            || value[start - 1] = '-'
                        )

                    let afterIsBoundary =
                        finish = value.Length
                        || (match value[finish] with
                            | '/' | '\\' | ' ' | '\t' | '\r' | '\n' | '\'' | '"' | '=' | ':' | ',' | ';' | ')' | ']' | '}' | '>' -> true
                            | _ -> false)

                    if beforeIsBoundary && afterIsBoundary then
                        result.Append(value, cursor, start - cursor) |> ignore
                        result.Append("/etc/fail2ban") |> ignore
                        cursor <- finish
                    else
                        result.Append(value, cursor, finish - cursor) |> ignore
                        cursor <- finish

            result.ToString()

    let normalizeRoot (root: string) (value: string) =
        normalizeString (normalizedRoot root) value

    let normalizeLiteral (root: string) (literal: PythonLiteral) =
        let source = normalizedRoot root

        let rec normalize = function
            | PyString value -> PyString(normalizeString source value)
            | PyList values -> PyList(List.map normalize values)
            | PyTuple values -> PyTuple(List.map normalize values)
            | PyDictionary entries ->
                PyDictionary(entries |> List.map (fun (key, value) -> normalize key, normalize value))
            | value -> value

        normalize literal

    let rec writeLiteral (writer: Utf8JsonWriter) (literal: PythonLiteral) =
        writer.WriteStartArray()

        match literal with
        | PyNone -> writer.WriteStringValue("none")
        | PyBoolean value ->
            writer.WriteStringValue("boolean")
            writer.WriteBooleanValue(value)
        | PyInteger value ->
            writer.WriteStringValue("integer")
            writer.WriteRawValue(value.ToString(CultureInfo.InvariantCulture), false)
        | PyFloat value ->
            writer.WriteStringValue("float")

            if Double.IsNaN value then
                writer.WriteStringValue("nan")
            elif Double.IsPositiveInfinity value then
                writer.WriteStringValue("inf")
            elif Double.IsNegativeInfinity value then
                writer.WriteStringValue("-inf")
            else
                writer.WriteRawValue(value.ToString("R", CultureInfo.InvariantCulture), false)
        | PyString value ->
            writer.WriteStringValue("string")
            writer.WriteStringValue(value)
        | PyList values ->
            writer.WriteStringValue("list")

            for value in values do
                writeLiteral writer value
        | PyTuple values ->
            writer.WriteStringValue("tuple")

            for value in values do
                writeLiteral writer value
        | PyDictionary entries ->
            writer.WriteStringValue("dictionary")

            for key, value in List.sortBy fst entries do
                writer.WriteStartArray()
                writeLiteral writer key
                writeLiteral writer value
                writer.WriteEndArray()

        writer.WriteEndArray()

    let sequenceValues = function
        | PyList values
        | PyTuple values -> Some values
        | _ -> None

    let stringValue = function
        | PyString value -> Some value
        | _ -> None

    let valueText = function
        | PyString value -> Some value
        | PyInteger value -> Some(value.ToString(CultureInfo.InvariantCulture))
        | PyFloat value when Double.IsNaN value -> Some "nan"
        | PyFloat value when Double.IsPositiveInfinity value -> Some "inf"
        | PyFloat value when Double.IsNegativeInfinity value -> Some "-inf"
        | PyFloat value -> Some(value.ToString("R", CultureInfo.InvariantCulture))
        | PyBoolean true -> Some "True"
        | PyBoolean false -> Some "False"
        | PyNone -> Some "None"
        | _ -> None

    let indexedString (values: PythonLiteral list) (index: int) =
        values |> List.tryItem index |> Option.bind stringValue

    let commandFields literal =
        sequenceValues literal
