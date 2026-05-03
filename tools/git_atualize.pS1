$repoPath = "P:\Pentest\ip-tools\apps\br-phish-feed\get-feed-certstream\"
Set-Location $repoPath

# Verifica se existe alguma alteração no repositório (arquivos novos ou modificados)
$status = git status --porcelain

if ($status) {
    # Pega a data e hora atual para o nome do commit
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Executa o fluxo do Git
    git add .
    git commit -m "Auto-update feed: $timestamp"
    
    # Altere 'main' para 'master' se a sua branch principal tiver o nome antigo
    git push origin main
    
    # Opcional: Registra no log do Windows que rodou com sucesso
    Write-Output "[+] Push realizado com sucesso em $timestamp" | Out-File ".\auto-push.log" -Append
} else {
    # Se não houver nada de novo, não faz commits vazios
    Write-Output "[-] Nenhuma alteração detectada em $(Get-Date)" | Out-File ".\auto-push.log" -Append
}