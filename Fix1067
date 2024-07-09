# Verificar se o sistema operacional é Windows 11
$OSVersion = (Get-WmiObject -Class Win32_OperatingSystem).Version
if ($OSVersion -like "10.0.22*") {
    $revert = [bool]::Parse('False')
    echo $revert

    if ($revert -eq $false) {

        # Verificar se o TPM 2.0 está habilitado
        $tpm = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm
        if ($tpm) {
            $specVersion = $tpm.SpecVersion
            if ($specVersion -match "2.0") {
                Write-Output "TPM 2.0 está habilitado."
            } else {
                Write-Output "TPM 2.0 não está habilitado. Especificação atual: $specVersion"
            }
        } else {
            Write-Output "Nenhum TPM encontrado."
        }

        # Verificar se o Secure Boot está habilitado
        $SecureBoot = Confirm-SecureBootUEFI
        if ($SecureBoot -eq $true) {
            Write-Output "Secure Boot está habilitado."
        } else {
            Write-Output "Secure Boot não está habilitado."
        }

        # Verificar e habilitar a opção "Usar Unicode UTF-8 para suporte de linguagem mundial"
        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Nls\CodePage"
        $utf8Enabled = Get-ItemProperty -Path $registryPath -Name $registryName -ErrorAction SilentlyContinue

        if ($utf8Enabled.ACP -eq "65001") {
            Write-Output "A opção 'Usar Unicode UTF-8 para suporte de linguagem mundial' está habilitada."
        } else {
            Write-Output "A opção 'Usar Unicode UTF-8 para suporte de linguagem mundial' não está habilitada. Habilitando agora..."
            #Ainda não sei reverter via PowerShell habilitar na mão
            #Set-ItemProperty -Path $registryPath -Name 'ACP' -Value "65001"
            #Set-ItemProperty -Path $registryPath -Name 'OEMCP' -Value "65001"
            #Set-ItemProperty -Path $registryPath -Name 'MACCP' -Value "65001"
        }

        # Função para encontrar o caminho de instalação do programa
        function Get-InstalledProgramPath {
            param (
                [string]$programName
            )
            $programs = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" |
                        Get-ItemProperty |
                        Where-Object { $_.DisplayName -like "*$programName*" }
            return $programs.InstallLocation
        }

        # Função para apagar arquivos em C:\ProgramData\Package Cache
        function Clear-PackageCache {
            $cachePath = "C:\ProgramData\Package Cache"
            if (Test-Path $cachePath) {
                Remove-Item "$cachePath\*" -Recurse -Force
                Write-Output "Arquivos no caminho $cachePath foram apagados."
            } else {
                Write-Output "Caminho $cachePath não encontrado."
            }
        }

        # Função para alterar DNS para Cloudflare
        function Set-DnsCloudflare {
            # DNS IPv4
            $dnsServersIPv4 = @("1.1.1.1", "1.0.0.1")
            # DNS IPv6
            $dnsServersIPv6 = @("2606:4700:4700::1111", "2606:4700:4700::1001")
            # DNS sobre HTTPS
            $dnsOverHttpsIPv4 = "https://one.one.one.one/dns-query"
            $dnsOverHttpsIPv6 = "https://cloudflare-dns.com/dns-query"

            # Obter adaptadores de rede
            $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }

            foreach ($adapter in $adapters) {
                Write-Output "Configurando DNS para adaptador: $($adapter.Name)"

                # Configurar DNS IPv4
                Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $dnsServersIPv4
                Write-Output "DNS IPv4 configurado para $($adapter.Name)."

                # Configurar DNS IPv6
                Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $dnsServersIPv6 -AddressFamily IPv6
                Write-Output "DNS IPv6 configurado para $($adapter.Name)."
            }

            # Adicionando configuração de DNS sobre HTTPS
            Write-Output "Configurando DNS sobre HTTPS para IPv4 e IPv6."
            netsh dns add encryption server=$dnsServersIPv4[0] dothttps=$dnsOverHttpsIPv4
            netsh dns add encryption server=$dnsServersIPv4[1] dothttps=$dnsOverHttpsIPv4
            netsh dns add encryption server=$dnsServersIPv6[0] dothttps=$dnsOverHttpsIPv6
            netsh dns add encryption server=$dnsServersIPv6[1] dothttps=$dnsOverHttpsIPv6

            Write-Output "DNS configurado para Cloudflare."
            
            Write-Output "Limpando o DNS Cache"
            netsh winsock reset
            netsh int ip reset
            ipconfig /release 
            ipconfig /renew 
            ipconfig /flushdns
            Write-Output "Cache DNS Apagado."

        }

        # Reiniciar o serviço VGC e definir como Automático
        $serviceName = "vgc"
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

        if ($service) {
            Set-Service -Name $serviceName -StartupType Automatic
            Restart-Service -Name $serviceName
            Write-Output "Serviço 'vgc' reiniciado e definido como Automático."
        } else {
            Write-Output "Serviço 'vgc' não encontrado."
        }

        
        # Buscar caminho de instalação do Riot Vanguard
        $riotVanguardPath = Get-InstalledProgramPath "Riot Vanguard"
        
        # Desinstalar e reinstalar o Riot Vanguard
        if ($riotVanguardPath) {
            Get-WmiObject -Query "SELECT * FROM Win32_Product WHERE Name = 'Riot Vanguard'" | ForEach-Object { $_.Uninstall() }
            Write-Output "Riot Vanguard desinstalado."
            Start-Sleep -Seconds 10

            # Apagar Logs do Vanguard
            Write-Output "Limpando residuos de Logs do Vanguard"
            if (Test-Path "$riotVanguardPath\Logs") {
                Write-Output "Há logs"
                Remove-Item "$riotVanguardPath\Logs\*" -Recurse -Force
                Write-Output "Arquivos no caminho $riotVanguardPath\Logs foram apagados."
            }
            
            Write-Output "Reinstalando Riot Vanguard..."
            $riotClientPath = Get-InstalledProgramPath "Riot Client"
            if ($riotClientPath) {
                Start-Process -FilePath "$riotClientPath\RiotClientServices.exe" -ArgumentList "--launch-product=valorant --launch-patchline=live" -Wait
                Write-Output "Riot Vanguard reinstalado."
            } else {
                Write-Output "Riot Client não encontrado."
            }
        } else {
            Write-Output "Riot Vanguard não encontrado."
        }

        # Passo 5: Adicionar exceções no firewall para Riot Vanguard e Valorant
        $valorantPath = Get-InstalledProgramPath "VALORANT"
        if ($riotVanguardPath -and $valorantPath) {
            $apps = @(
                "$riotVanguardPath\vanguard.exe",
                "$valorantPath\live\VALORANT.exe"
            )

            foreach ($app in $apps) {
                New-NetFirewallRule -DisplayName "Allow $app" -Direction Inbound -Program $app -Action Allow -Profile Any
                New-NetFirewallRule -DisplayName "Allow $app" -Direction Outbound -Program $app -Action Allow -Profile Any
                Write-Output "Exceção de firewall adicionada para $app."
            }
        } else {
            Write-Output "Caminhos do Riot Vanguard ou Valorant não encontrados."
        }

        # Melhorando a Detecção de Dispositivos USB como KVM
        Write-Output "Verificando dispositivos USB como KVM..."
        $usbDevices = Get-PnpDevice | Where-Object { $_.Class -eq "USB" }

        foreach ($device in $usbDevices) {
            $deviceDescription = $device.FriendlyName
            if ($deviceDescription -match "KVM|HUB|Switch|Adapter") {
                Write-Output "Dispositivo USB suspeito encontrado: $($deviceDescription)"
            }
        }

        # Apagar arquivos em C:\ProgramData\Package Cache
        Clear-PackageCache

        # Alterar DNS para Cloudflare
        Set-DnsCloudflare

    } else {
        Write-Output "Revertendo mudanças relacionadas ao SO."
        function Revert-DNS() {
            # Remover configuração de DNS sobre HTTPS para Cloudflare

            # Remover DNS sobre HTTPS para IPv4
            netsh dns delete encryption server=1.1.1.1
            netsh dns delete encryption server=1.0.0.1

            # Remover DNS sobre HTTPS para IPv6
            netsh dns delete encryption server=2606:4700:4700::1111
            netsh dns delete encryption server=2606:4700:4700::1001

            # Restaurar configuração automática de DNS
            Get-NetAdapter | ForEach-Object {
                Write-Output "Restaurando configurações de DNS automático para $($_.Name)"
                Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses
            }

            Write-Output "Configurações de DNS restauradas para o padrão automático."
        }

        function Revert-Beta-UTF8() {
            #TODO
            # Aparentemente é só apagar as chaves, mas melhor fazer um bkp e testar antes.
            # https://gist.github.com/nad2000/904a24464fb32f60c66b0e95653ea837
        }

        function Revert-Firewall() {
            $valorantPath = Get-InstalledProgramPath "VALORANT"
            if ($riotVanguardPath -and $valorantPath) {
                $apps = @(
                    "$riotVanguardPath\vanguard.exe",
                    "$valorantPath\live\VALORANT.exe"
                )

                foreach ($app in $apps) {
                    # Procurar a regra no firewall pelo nome
                    $rule = Get-NetFirewallRule -DisplayName "Allow $app" -ErrorAction SilentlyContinue

                    if ($rule) {
                        # Remover a regra do firewall
                        Remove-NetFirewallRule -DisplayName $RuleDisplayName
                        Write-Output "Exceção de firewall '$RuleDisplayName' removida com sucesso."
                    } else {
                        Write-Output "Exceção de firewall '$RuleDisplayName' não encontrada."
                    }
                }
            } else {
                Write-Output "Caminhos do Riot Vanguard ou Valorant não encontrados."
            }
        }

        Revert-DNS
        Revert-Beta-UTF8
        Revert-Firewall

        
    }
    
    Write-Output "Script concluído. Reiniciando o sistema em 5 segundos..."
    Restart-Computer -Force -Wait -Timeout 5

} else {
    Write-Output "Este script é destinado ao Windows 11."
}
