#if HOST_HELPER
namespace Dorothy.HostHelper
#else
namespace Dorothy.DSL
#endif

open System

/// Shared, allocation-free validation for canonical Traefik path subtrees.
module TraefikPathModel =
    let isCanonicalSubtree (value: string) =
        if isNull value || value.Length < 2 || value.Length > 128 || value[0] <> '/' || value[value.Length - 1] = '/' then
            false
        else
            let mutable index = 1
            let mutable segmentHasCharacter = false
            let mutable valid = true

            while index < value.Length && valid do
                let character = value[index]
                if character = '/' then
                    if not segmentHasCharacter then valid <- false
                    segmentHasCharacter <- false
                elif Char.IsAsciiLetterOrDigit character || character = '_' || character = '-' then
                    segmentHasCharacter <- true
                else
                    valid <- false
                index <- index + 1

            valid && segmentHasCharacter
