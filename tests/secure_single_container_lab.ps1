param(
    [string]$GuardianImage = "npm-guardian:1.0.4",
    [string]$NpmImage = "jc21/nginx-proxy-manager:2.15.1@sha256:52b2c59994f3d36acfcf70a1626f29734df0ed8c71bacc0269f78b6f939858bb"
)

$ErrorActionPreference = "Stop"
$labId = [Guid]::NewGuid().ToString("N").Substring(0, 12)
$prefix = "npmg-single-lab-$labId"
$labLabel = "io.ezr43l.test-run=$labId"
$network = $prefix
$npm = "$prefix-npm"
$guardian = "$prefix-guardian"
$dataVolume = "$prefix-data"
$leVolume = "$prefix-letsencrypt"
$guardianVolume = "$prefix-guardian-data"

function Invoke-Docker {
    $dockerArguments = @($args)
    & docker @dockerArguments
    if ($LASTEXITCODE -ne 0) {
        throw "docker $($dockerArguments -join ' ') terminó con $LASTEXITCODE"
    }
}

function Test-Docker {
    $dockerArguments = @($args)
    $previousErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    & docker @dockerArguments 2>$null | Out-Null
    $ok = $LASTEXITCODE -eq 0
    $ErrorActionPreference = $previousErrorAction
    return $ok
}

function Remove-Lab {
    $previousErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    $ownedContainers = @(& docker ps -aq --filter "label=$labLabel" 2>$null)
    if ($ownedContainers.Count -gt 0) {
        & docker rm -f @ownedContainers 2>$null | Out-Null
    }
    $ownedNetworks = @(& docker network ls -q --filter "label=$labLabel" 2>$null)
    if ($ownedNetworks.Count -gt 0) {
        & docker network rm @ownedNetworks 2>$null | Out-Null
    }
    $ownedVolumes = @(& docker volume ls -q --filter "label=$labLabel" 2>$null)
    if ($ownedVolumes.Count -gt 0) {
        & docker volume rm @ownedVolumes 2>$null | Out-Null
    }
    $ErrorActionPreference = $previousErrorAction
}

try {
    Invoke-Docker pull $NpmImage
    Invoke-Docker network create --label $labLabel $network
    Invoke-Docker volume create --label $labLabel $dataVolume
    Invoke-Docker volume create --label $labLabel $leVolume
    Invoke-Docker volume create --label $labLabel $guardianVolume

    Invoke-Docker run -d --name $npm --label $labLabel --network $network `
        -e DISABLE_IPV6=true -v "${dataVolume}:/data" `
        -v "${leVolume}:/etc/letsencrypt" $NpmImage

    $npmReady = $false
    foreach ($attempt in 1..90) {
        if (Test-Docker exec $npm /bin/sh -c `
                'test -s /run/nginx/nginx.pid && /usr/sbin/nginx -t') {
            $npmReady = $true
            break
        }
        Start-Sleep -Seconds 2
    }
    if (-not $npmReady) {
        Invoke-Docker logs $npm
        throw "NPM no llegó a una configuración Nginx válida"
    }

    Invoke-Docker run -d --name $guardian --label $labLabel `
        --label io.ezr43l.test-role=guardian --network $network --read-only `
        --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 256 `
        --tmpfs "/tmp:rw,noexec,nosuid,nodev,size=64m" `
        -v "${dataVolume}:/npm" -v "${leVolume}:/npm-letsencrypt" `
        -v "${guardianVolume}:/datos" `
        -v /var/run/docker.sock:/var/run/docker.sock:rw $GuardianImage

    $setupReady = $false
    foreach ($attempt in 1..30) {
        if (Test-Docker exec $guardian python3 -c `
                "import json,urllib.request; assert json.load(urllib.request.urlopen('http://127.0.0.1:6061/api/health',timeout=2))['status']=='setup-required'") {
            $setupReady = $true
            break
        }
        Start-Sleep -Seconds 1
    }
    if (-not $setupReady) {
        Invoke-Docker logs $guardian
        throw "NPM Guardian no sirvió el asistente inicial"
    }

    # Nginx can be ready a few seconds before NPM finishes every SQLite
    # migration. Wait for the exact schema contract queried by Guardian.
    $npmSchemaReady = $false
    foreach ($attempt in 1..90) {
        if (Test-Docker exec $guardian python3 -c `
                "import sqlite3; c=sqlite3.connect('file:/npm/database.sqlite?mode=ro',uri=True,timeout=2); c.execute('select id,nice_name,provider,expires_on,meta,domain_names,is_deleted from certificate limit 0'); c.execute('select id,domain_names,forward_scheme,forward_host,forward_port,certificate_id,enabled,is_deleted from proxy_host limit 0')") {
            $npmSchemaReady = $true
            break
        }
        Start-Sleep -Seconds 2
    }
    if (-not $npmSchemaReady) {
        Invoke-Docker logs $npm
        throw "NPM did not finish preparing the required SQLite schema"
    }

    $setup = @{
        node = "lab-node"
        standalone = $true
        enrollment_code = ""
        members = @(@{ name = "lab-node"; address = $npm; guardian_url = "" })
        keepalived = @{ url = ""; service = ""; token = ""; allow_http = $false }
        portal = @{ public_url = ""; trusted_proxies = ""; allow_http = $true }
        npm = @{ container = $npm; scheme = "http"; api_port = 81; https_port = 443; allow_http = $true }
    } | ConvertTo-Json -Compress -Depth 6
    $setup64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($setup))
    Invoke-Docker exec $guardian python3 -c `
        "import base64,urllib.request; b=base64.b64decode('$setup64'); r=urllib.request.Request('http://127.0.0.1:6061/api/bootstrap',data=b,headers={'Content-Type':'application/json'},method='POST'); assert __import__('json').load(urllib.request.urlopen(r,timeout=3))['ok']"

    $guardianReady = $false
    foreach ($attempt in 1..30) {
        if (Test-Docker exec $guardian python3 -c `
                "import json,urllib.request; assert json.load(urllib.request.urlopen('http://127.0.0.1:6061/api/health',timeout=2))['status']=='ok'") {
            $guardianReady = $true
            break
        }
        Start-Sleep -Seconds 1
    }
    if (-not $guardianReady) {
        Invoke-Docker logs $guardian
        throw "NPM Guardian no arrancó después del asistente"
    }
    Invoke-Docker exec $guardian /bin/sh -c `
        "test -s /datos/node.json && test -s /datos/secrets/session-secret && test -s /datos/secrets/cluster-token"
    Invoke-Docker exec $guardian python3 -c `
        "import json,urllib.request; s=json.load(urllib.request.urlopen('http://127.0.0.1:6061/api/public/status',timeout=5)); assert s['node']=='lab-node' and s['health']['npm_container']['existe'],s"

    $guardians = @(& docker ps -a --filter "label=io.ezr43l.test-role=guardian" `
        --filter "label=$labLabel" --format '{{.Names}}')
    if ($guardians.Count -ne 1 -or $guardians[0] -ne $guardian) {
        throw "la aplicación NPM Guardian no se ejecutó como un único contenedor"
    }

    $mounts = & docker inspect -f '{{json .Mounts}}' $guardian | ConvertFrom-Json
    $socketMounts = @($mounts | Where-Object { $_.Destination -eq "/var/run/docker.sock" })
    if ($socketMounts.Count -ne 1) {
        throw "el único Guardian debe montar docker.sock exactamente una vez"
    }
    $readOnly = (& docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' $guardian).Trim()
    if ($readOnly -ne "true") {
        throw "el rootfs de Guardian no es de sólo lectura"
    }

    $exercise = @"
import sys
sys.path.insert(0, '/opt/panel')
import dockerd
estado = dockerd.estado('$npm')
assert estado['existe'] and estado['corriendo'], estado
resultado = dockerd.recargar_nginx('$npm')
assert resultado == {'ok': True, 'config_tested': True, 'reloaded': True}, resultado
try:
    dockerd.estado('contenedor-ajeno')
except dockerd.ErrorDocker:
    pass
else:
    raise AssertionError('la lista blanca aceptó un contenedor ajeno')
"@
    # docker exec crea un proceso con el entorno original del contenedor; se
    # declara la misma allowlist persistida para ejercitar el cliente aislado.
    Invoke-Docker exec -e NPMG_NPM_CONTAINER=$npm $guardian python3 -c $exercise

    Invoke-Docker exec -e NPMG_NPM_CONTAINER=$npm $guardian python3 -c `
        "import sys; sys.path.insert(0,'/opt/panel'); import dockerd; assert dockerd.parar('$npm',20)"
    if ((& docker inspect -f '{{.State.Running}}' $npm).Trim() -ne "false") {
        throw "NPM siguió corriendo después de stop"
    }
    Invoke-Docker exec -e NPMG_NPM_CONTAINER=$npm $guardian python3 -c `
        "import sys; sys.path.insert(0,'/opt/panel'); import dockerd; assert dockerd.arrancar('$npm')"
    if ((& docker inspect -f '{{.State.Running}}' $npm).Trim() -ne "true") {
        throw "NPM no volvió a arrancar"
    }

    Write-Host "LAB OK: un NPM Guardian $GuardianImage frente a NPM $NpmImage"
}
finally {
    Remove-Lab
}
