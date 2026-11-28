#!/usr/bin/env bash
# Guest-only: capture the pinned daemon's effective graph with and without a model, and an
# otherwise-identical daemon with different live policy. No production host paths or credentials.
set -euo pipefail
umask 077
curl() { command curl --disable --noproxy '*' "$@"; }
fixture=$(realpath -e -- "${1:?guest fixture directory required}")
[[ "$fixture" =~ ^/var/tmp/dorothy-traefik-acceptance\.[[:alnum:]]+$ && -f "$fixture/.owner" && $(<"$fixture/.owner") == dorothy-traefik-acceptance-guest-v1 ]]
exe="$fixture/bin/traefik"
[[ $(sha256sum "$exe" | awk '{ print $1 }') == 86ee2b427888d24475051fc5f5bcca94cf4fa033b6fa54205b7eb0de6914f31e ]] \
    || { printf 'Pinned Traefik executable digest mismatch.\n' >&2; exit 1; }
out=$(mktemp -d "$fixture/effective-graph.XXXXXXXX"); pid=
stop(){ if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || :; wait "$pid" || :; pid=; fi; }
trap stop EXIT
for mode in base model drift rank rank-zero rank-stale chain chain-reverse tcp-middleware; do
    dir="$out/$mode"; mkdir "$dir"
    jq -n --arg filename "$dir/dynamic.yml" '{entryPoints:{"keroosha-admin":{address:"127.0.0.1:38307"},a:{address:"127.0.0.1:38308",forwardedHeaders:{trustedIPs:["127.0.0.1/32"]}},b:{address:"127.0.0.1:38309"},t:{address:"127.0.0.1:38310"}},providers:{file:{filename:$filename,watch:true}},api:{dashboard:true}}' > "$dir/static.yml"
    cat > "$dir/dynamic.yml" <<'JSON'
{"http":{"routers":{"keroosha-admin":{"entryPoints":["keroosha-admin"],"rule":"PathPrefix(`/api`) || PathPrefix(`/dashboard`)","service":"api@internal","priority":1000000},"app":{"entryPoints":["a","b"],"rule":"Host(`app.test`)","service":"app","middlewares":["mark"]}},"services":{"app":{"loadBalancer":{"servers":[{"url":"http://127.0.0.1:8080"}]}}},"middlewares":{"mark":{"headers":{"customRequestHeaders":{"middlewares":"literal-value"}}}}}}
JSON
    if [[ "$mode" == model ]]; then
        jq '.entryPoints.a.http={middlewares:["mark@file"]}|.entryPoints.b.http={middlewares:["mark@file"]}' "$dir/static.yml" > "$dir/x"; mv "$dir/x" "$dir/static.yml"
        jq '.http.routers.app.middlewares=["chain"]|.http.middlewares.prefix={addPrefix:{prefix:"/first"}}|.http.middlewares.chain={chain:{middlewares:["prefix","mark"]}}|.http.routers.parent={entryPoints:["a","b"],rule:"Host(`parent.test`)",middlewares:["mark"]}|.http.routers.child={parentRefs:["parent"],rule:"Header(`middlewares`,`literal-value`)",service:"app"}|.tcp={routers:{echo:{entryPoints:["t"],rule:"HostSNI(`*`)",middlewares:["one"],service:"echo"}},middlewares:{one:{ipAllowList:{sourceRange:["127.0.0.1/32"]}}},services:{echo:{loadBalancer:{servers:[{address:"127.0.0.1:19001"}]}}}}' "$dir/dynamic.yml" > "$dir/x"; mv "$dir/x" "$dir/dynamic.yml"
    elif [[ "$mode" == drift ]]; then
        jq '.entryPoints.a.forwardedHeaders.trustedIPs=["127.0.0.2/32"]' "$dir/static.yml" > "$dir/x"; mv "$dir/x" "$dir/static.yml"
        jq '.http.routers.app.priority=1|.http.middlewares.mark.headers.customRequestHeaders["X-Extra"]="stale"' "$dir/dynamic.yml" > "$dir/x"; mv "$dir/x" "$dir/dynamic.yml"
    elif [[ "$mode" == rank* ]]; then
        jq --arg mode "$mode" 'del(.http.middlewares,.http.routers.app.middlewares)
          | .http.routers.app.entryPoints=["a"]
          | .http.routers.rival={entryPoints:["a"],rule:"Host(`app.test`) && PathPrefix(`/probe`)",service:"other"}
          | .http.services.other={loadBalancer:{servers:[{url:"http://127.0.0.1:8082"}]}}
          | if $mode=="rank-stale" then .http.routers.app.priority=1000 elif $mode=="rank-zero" then .http.routers.app.priority=0 else . end' "$dir/dynamic.yml" > "$dir/x"; mv "$dir/x" "$dir/dynamic.yml"
    elif [[ "$mode" == chain* ]]; then
        jq --arg m "$mode" '.http.routers.app.entryPoints=["a"] | .http.routers.app.middlewares=["both"]
            | .http.middlewares={first:{addPrefix:{prefix:"/one"}},second:{addPrefix:{prefix:"/two"}},both:{chain:{middlewares:(if $m=="chain" then ["first","second"] else ["second","first"] end)}}}' "$dir/dynamic.yml" > "$dir/x"; mv "$dir/x" "$dir/dynamic.yml"
    elif [[ "$mode" == tcp-middleware ]]; then
        jq 'del(.http.middlewares,.http.routers.app.middlewares)|.http.routers.app.entryPoints=["a"]
            | .tcp={routers:{echo:{entryPoints:["t"],rule:"HostSNI(`*`)",middlewares:["allow"],service:"echo"}},middlewares:{allow:{ipAllowList:{sourceRange:["127.0.0.1/32"]}}},services:{echo:{loadBalancer:{servers:[{address:"127.0.0.1:19001"}]}}}}' "$dir/dynamic.yml" > "$dir/x"; mv "$dir/x" "$dir/dynamic.yml"
    fi
    "$fixture/guest-local-issuers.sh" check "$dir/static.yml" > "$dir/local-issuer-check.log"
    env -i PATH=/usr/bin:/bin LANG=C "$exe" --configFile="$dir/static.yml" > "$dir/daemon.log" 2>&1 & pid=$!
    for _ in $(seq 1 60); do
        if curl -fsS --max-time 1 http://127.0.0.1:38307/api/rawdata > "$dir/rawdata.json" 2>/dev/null && jq -e '.services["app@file"].status=="enabled"' "$dir/rawdata.json" >/dev/null; then break; fi
        sleep 0.1
    done
    jq -e '.services["app@file"].status=="enabled"' "$dir/rawdata.json" >/dev/null
    curl -fsS --max-time 2 'http://127.0.0.1:38307/api/entrypoints?per_page=100' > "$dir/entrypoints.json"
    curl -fsS --max-time 2 http://127.0.0.1:38307/api/version > "$dir/version.json"
    # Strip machine paths before retention; the expected-file provider location is not compared.
    jq '.providers.file.filename="fixture/dynamic.yml"' "$dir/static.yml" > "$dir/static.json"
    if [[ "$mode" == model ]]; then
        curl -fsS --max-time 3 -H 'Host: app.test' http://127.0.0.1:38308/result | grep -Fq 'http-backend:/first/result'
        curl -fsS --max-time 3 -H 'Host: parent.test' http://127.0.0.1:38308/result | grep -Fq 'http-backend:/result'
    elif [[ "$mode" == rank* ]]; then
        expected=other-backend; [[ "$mode" != rank-stale ]] || expected=http-backend
        curl -fsS --max-time 3 -H 'Host: app.test' http://127.0.0.1:38308/probe | grep -Fq "$expected:/probe"
    elif [[ "$mode" == chain* ]]; then
        path=/two/one/probe; [[ "$mode" != chain-reverse ]] || path=/one/two/probe
        curl -fsS --max-time 3 -H 'Host: app.test' http://127.0.0.1:38308/probe | grep -Fq "http-backend:$path"
    elif [[ "$mode" == tcp-middleware ]]; then
        timeout 8 perl -MIO::Socket::INET -e '
            use strict; use warnings;
            for my $ip (qw(127.0.0.1 127.0.0.2)) {
                my $s=IO::Socket::INET->new(PeerAddr=>"127.0.0.1",PeerPort=>38310,LocalAddr=>$ip,Proto=>"tcp",Timeout=>2) or die "no TCP listener";
                my $msg="finite TCP echo for middleware decision.\r\n";
                syswrite($s,$msg)==length($msg) or die "write";
                my $reply=""; while(length($reply)<length($msg)) { my $n=sysread($s,my $b,1024); last unless $n; $reply.=$b; }
                die "wrong source decision" unless ($ip eq "127.0.0.1" ? $reply eq $msg : $reply eq "");
            }'
    else
        forwarded=$(curl -fsS --max-time 2 --interface 127.0.0.1 -H 'Host: app.test' \
          -H 'X-Forwarded-For: 192.0.2.77' http://127.0.0.1:38308/trust)
        [[ "$forwarded" == http-backend:/trust* ]]
        if [[ "$mode" == base ]]; then
            [[ "$forwarded" == *192.0.2.77* ]]
        else
            [[ "$forwarded" != *192.0.2.77* ]]
        fi
    fi
    stop
done
printf '%s\n' "$out"
