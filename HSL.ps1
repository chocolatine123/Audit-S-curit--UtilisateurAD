###############################################################
########## Voir détails de sécurité d'un utilisateur ##########
####################  Pierre-Alban Maurin  ####################
###############################################################

######################################################################################
####################### Prérequis 1 : Module Active Directory ########################
# Add-WindowsCapability –Online –Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" #
######################################################################################
######################################################################################

Import-Module ActiveDirectory
$ErrorActionPreference = 'SilentlyContinue'

### Choisir l'utilisateur
Write-Host "Veuillez entrer le nom de votre utilisateur : " -ForegroundColor yellow -NoNewLine
$utilisateur = Read-Host
Write-Host "L'utilisateur que vous avez selectionné est : " -ForegroundColor yellow -NoNewLine

## Vérifier si le nom est correct
$error.clear()
try { Get-ADUser -Identity $utilisateur -Properties * | Select-Object -ExpandProperty Name }
catch {
    "Le nom d'utilisateur n'est pas reconnu." 
    break
}
if (!$error) {}


$nomcomplet = Get-ADUser -Identity $utilisateur -Properties * | Select-Object -ExpandProperty Name
$san = Get-ADUser -Identity $utilisateur -Properties * | Select-Object -ExpandProperty SamAccountName
$upn = Get-ADUser -Identity $utilisateur -Properties * | Select-Object -ExpandProperty UserPrincipalName


#########################################
### Groupes rattachés à l'utilisateur ###
#########################################
Write-Host "Groupes rattachés à l'utilisateur : " -ForegroundColor yellow  
$groupes = Get-ADUser -Identity $utilisateur -Properties * | Select-Object -ExpandProperty MemberOf
$groupes

###################################
### Dernière heure de connexion ###
###################################

$timestamp = Get-ADUser -Identity $utilisateur -Properties * | Select-Object -ExpandProperty lastLogonTimestamp
$timestampDef = [datetime]::FromFileTime($timestamp)
$dateclassique = Get-ADUser -Identity $utilisateur -Properties * | Select-Object -ExpandProperty lastLogonDate

if ($timestampDef -eq $dateclassique)
{
    Write-Host "Heure de sa dernière connexion : " -ForegroundColor yellow -NoNewLine  
    Write-host $dateclassique 
}
Else
{
    Write-Host "Le lastLogonTimestamp et le lastLogonDate sont différents" -ForegroundColor yellow
    Write-Host "Le lastLogonDate (sans réplications entre les DC) date du " $dateclassique
    Write-Host "Le lastLogonTimestamp (réplication entre tous les DC) date du" $timestampDef
}

#####################################
### Vulnérable à l'AS_REP Roasting ##
#####################################
## Pour tester :
## Set-ADAccountControl -Identity "utilisateur" -DoesNotRequirePreAuth $true
## Puis remplacer $true par $false pour nettoyer

Write-Host "L'utilisateur est vulnérable à l'AS_REP Roasting : " -ForegroundColor yellow -NoNewLine

$asreproast = Get-ADUser -Identity $utilisateur -Properties * | Select-Object -ExpandProperty DoesNotRequirePreAuth
if ($asreproast -eq $true)
{
    Write-Host "Vrai." -ForegroundColor Red
}
Else
{
    Write-Host "Faux."  
}


###################################
### Vulnérable au Kerberoasting ###
###################################
## Pour tester :
## Set-ADUser -Identity "utilisateur" -ServicePrincipalNames @{Add='HTTP/webserver'}
## Puis remplacer add par remove pour nettoyer

Write-Host "L'utilisateur est vulnérable au Kerberoasting : " -ForegroundColor yellow -NoNewLine

$kerberoast = Get-ADUser -Identity $utilisateur -Properties * | Select-Object -ExpandProperty ServicePrincipalNames
if ($kerberoast)
{
    Write-Host "Vrai." -ForegroundColor Red
    Write-Host $kerberoast
    $kerber = $kerberoast
}
Else
{
    Write-Host "Faux."  
    $kerber = "Faux"
}

#################################
### Vulnérable au relais NTLM ###
#################################

Write-Host "L'utilisateur peut utiliser NTLM : " -ForegroundColor yellow -NoNewLine
$groupe = 'Protected Users'
 $user = Get-ADGroupMember -Identity $groupe | Where-Object {$_.SamAccountName -eq $utilisateur}
 if($user){
     Write-Host 'Non.'
     $ntlm = "Non"
 }
 else{ 
     Write-Host 'Oui.' -ForegroundColor Red
     $ntlm = "Oui"
 }

###########################################
### Vérification du Security Descriptor ###
###########################################

Write-Host "Liste des ACL à surveiller : " -ForegroundColor yellow -NoNewLine
$dossier = $env:TEMP 
Get-ADUser $utilisateur | %{(Get-ACL "AD:$($_.distinguishedname)").access} | Select IdentityReference,AccessControlType,ActiveDirectoryRights > $dossier\auditutilisateurtemp1.txt
### Trions les ACL :
### On supprime de notre selection les administrateurs du domaine qui ont déjà de façon intrinsèque un GenericAll sur l'utilisateur
### On supprime également les comptes NT
Get-Content $dossier\auditutilisateurtemp1.txt | Where-Object {$_ -notmatch "NT AUTHORITY"} |Out-File $dossier\auditutilisateurtemp2.txt
Get-Content $dossier\auditutilisateurtemp2.txt | Where-Object {$_ -notmatch "AUTORITE NT"} |Out-File $dossier\auditutilisateurtemp3.txt
Get-Content $dossier\auditutilisateurtemp3.txt | Where-Object {$_ -notmatch "S-1-5-32"} |Out-File $dossier\auditutilisateurtemp4.txt
Get-Content $dossier\auditutilisateurtemp4.txt | Where-Object {$_ -notmatch "Éditeurs de certificats"} |Out-File $dossier\auditutilisateurtemp5.txt
Get-Content $dossier\auditutilisateurtemp5.txt | Where-Object {$_ -notmatch "Cert Publishers"} |Out-File $dossier\auditutilisateurtemp6.txt
Get-Content $dossier\auditutilisateurtemp6.txt | Where-Object {$_ -notmatch "Administrat"} |Out-File $dossier\auditutilisateurtemp7.txt
Get-Content $dossier\auditutilisateurtemp7.txt | Where-Object {$_ -notmatch "Admins du domaine"} |Out-File $dossier\auditutilisateurtemp8.txt
Get-Content $dossier\auditutilisateurtemp8.txt | Where-Object {$_ -notmatch "Domain Admins"} |Out-File $dossier\auditutilisateurtemp9.txt
Get-Content $dossier\auditutilisateurtemp9.txt | Where-Object {$_ -notmatch "Administrateurs de l'entreprise"} |Out-File $dossier\auditutilisateurtemp10.txt
Get-Content $dossier\auditutilisateurtemp10.txt | Where-Object {$_ -notmatch "Enterprise Admins"} |Out-File $dossier\auditutilisateurtemp11.txt
Get-Content $dossier\auditutilisateurtemp11.txt | Where-Object {$_ -notmatch "key"} |Out-File $dossier\auditutilisateurtemp12.txt
Get-Content $dossier\auditutilisateurtemp12.txt | Where-Object {$_ -notmatch "clé"} |Out-File $dossier\auditutilisateurtemp13.txt
Get-Content $dossier\auditutilisateurtemp13.txt | Where-Object {$_ -notmatch "DOMAIN CONTROLLERS"} |Out-File $dossier\auditutilisateurtemp14.txt
Get-Content $dossier\auditutilisateurtemp14.txt | Where-Object {$_ -notmatch "Contrôleurs de domaine"} |Out-File $dossier\auditutilisateurtemp15.txt
#Get-Content $dossier\auditutilisateurtemp15.txt | Where-Object {$_ -notmatch "Tout le monde"} |Out-File $dossier\auditutilisateurtemp16.txt
#Get-Content $dossier\auditutilisateurtemp16.txt | Where-Object {$_ -notmatch "Everybody"} |Out-File $dossier\auditutilisateurtemp17.txt
Get-Content $dossier\auditutilisateurtemp15.txt | Where-Object {$_ -notmatch "ReadProperty"} |Out-File $dossier\auditutilisateurtemp16.txt
Get-Content $dossier\auditutilisateurtemp16.txt | Where-Object {$_ -notmatch "self"} |Out-File $dossier\auditutilisateurtemp17.txt
$acluser = Get-Content $dossier\auditutilisateurtemp17.txt
$acluser_epure = Get-Content $dossier\auditutilisateurtemp17.txt | Select-Object -Skip 3
if ($acluser_epure){
     $acluser
 }
 else{ 
     Write-Host 'Rien à signaler.'
 }
 rm  $dossier\auditutilisateurtemp*

#####################################
### Lieu de la heure de connexion ###
#####################################

Write-Host "Sessions en cours par l'utilisateur : " -ForegroundColor yellow -NoNewLine
### version simple
## On recherche pour ce faire les LastLogonDate des ordis du domaine sans les secondes (toujours un petit décalage probablement dû au fait que pour l'ordi ça correspond au WinLoad.exe et pour l'utilisateur au winit.exe)
# Cette méthode est donc approximative
$logonuser = Get-ADUser -Identity $utilisateur -Properties * | Select-Object -ExpandProperty LastLogonDate
$logonuser = $logonuser -replace ".$"
$logonuser = $logonuser-replace ".$"
$logonuser = $logonuser-replace ".$"
$Ordis =  Get-ADComputer  -Filter {(enabled -eq "true")} | Select-Object -ExpandProperty Name
$tota = 0
ForEach($ordi in $Ordis) {
    $logonordi = Get-ADComputer -Identity $ordi -Properties * | Select-Object -ExpandProperty LastLogonDate
    $logonordi = $logonordi -replace ".$"
    $logonordi = $logonordi -replace ".$"
    $logonordi = $logonordi -replace ".$"
    if ($logonordi -eq $logonuser)
    {
        Write-Host $ordi
        $sessionuser = $ordi
        $tota = 1
    }
}
if ($tota -eq 0)
{
    Write-Host "Désolé, nous n'avons pas trouvé de correspondance."
    $sessionuser = "Pas de correspondance"
}
elseif ($tota = 1)
{
    #$sessionuser
}
else
{
    Write-Host "Erreur..."
}

### version plus poussée avec query user
# Plus sûre mais très longue
Write-Host "Voulez-vous passer à une recherche de sessions ouvertes plus avancée (peut être long) ? o/n :" -ForegroundColor blue -NoNewline
$reponse = Read-Host

function check_session_utilisateur {
    $Ordis =  Get-ADComputer  -Filter {(enabled -eq "true")} | Select-Object -ExpandProperty Name
    $toto = 0
    ForEach($ordi in $Ordis) { 
        $utilisateurconnecte = query user /server:$ordi | Write-Output -WarningAction SilentlyContinue
        $Parsed_user = $utilisateurconnecte -split '\s+'
        if ($utilisateur -eq $Parsed_user[10])
        {
            Write-Host "Sessions en cours par l'utilisateur : " -ForegroundColor yellow -NoNewline
            $ordi
            $sessionuser += $ordi
            $toto = 1
        }
    }
    if ($toto -eq 0)
    {
        Write-Host "Désolé, nous n'avons pas trouvé de correspondance."
        $sessionuser = "Pas de correspondance"
    }
    elseif($toto -eq 1)
    {
        #$toto
        #Write-Host "ok ça marche"
        #$sessionuser
    }
    else
    {
        Write-Host "Erreur..."
    }
}



while ($reponse -ne "o" -or $reponse -ne "n")
{
    if ($reponse -eq "o")
    {
        
        $sessionuser = check_session_utilisateur
        break
    }
    elseif ($reponse -eq "n")
    {
        $titi = 1
        break
    }
    else
    {
    Write-Host "Veuillez selectionner o pour oui ou n pour non en réponse s'il vous plait :" -ForegroundColor blue -NoNewline
    $reponse = Read-Host
    }
}

if ($titi -eq 1)
{
    Write-Host "Très bien, continuons"
}

#################################################
### Vérification des délégations de contrôles ###
#################################################

Write-Host "Vérification des délégations de contrôles : " -ForegroundColor yellow

<#
## Solution avec Quest qui est top mais proprietaire
[System.Reflection.Assembly]::LoadWithPartialName("Quest.ActiveRoles.ADManagement")
Add-PSSnapin Quest.ActiveRoles.ADManagement -ErrorAction Stop

$Deleg = Get-QADObject -SecurityMask Dacl -SizeLimit 0 | Get-QADPermission -Account ($utilisateur) -Inherited -SchemaDefault -Verbose -UseTokenGroups
$Deleg | FT Account,TargetObject,Rights,RightsDisplay
## ou bien
Get-QADUser $utilisateur -SecurityMask Dacl | Get-QADPermission -Rights 'WriteProperty' -UseExtendedMatch -Inherited -SchemaDefault -Verbose -Allow -Property ('sAMAccountName','name')
#>
function Check_Deleg
{
    $titi = 0

    $ListeOU = Get-ADOrganizationalUnit -Filter * | Select-Object -ExpandProperty DistinguishedName
    foreach ($ou in $ListeOU)
    {
        $Deleg = dsacls.exe $ou | Select-String $utilisateur
        if ($Deleg)
        {
            Write-Host "Correspondances trouvées pour " $ou -ForegroundColor Red -NoNewline
            $Deleg | Select-Object -Unique
            $titi = 1
        }
    }

    ## Check à la racine du domaine
    $DNDomaine = Get-ADDomain | Select-Object -ExpandProperty DistinguishedName
    $Deleg = dsacls.exe $DNDomaine | Select-String $utilisateur
    if ($Deleg)
    {
        Write-Host "Correspondances trouvées pour " $DNDomaine -ForegroundColor Red 
        $Deleg | Select-Object -Unique
        $titi = 1
    }

    # check des délégations pour les containers :
    # Builtin
    $Builtin = "CN=Builtin,"+ $DNDomaine
    $Deleg = dsacls.exe $Builtin | Select-String $utilisateur
    if ($Deleg)
    {
        Write-Host "Correspondances trouvées pour " $Builtin -ForegroundColor Red 
        $Deleg | Select-Object -Uniquer
        $titi = 1
    }

    # Computers
    $Computers = "CN=Computers,"+ $DNDomaine
    $Deleg = dsacls.exe $Computers | Select-String $utilisateur
    if ($Deleg)
    {
        Write-Host "Correspondances trouvées pour " $Computers -ForegroundColor Red 
        $Deleg | Select-Object -Unique
        $titi = 1
    }

    # ForeignSecurityPrincipals
    $ForeignSecurityPrincipals = "CN=ForeignSecurityPrincipals,"+ $DNDomaine
    $Deleg = dsacls.exe $ForeignSecurityPrincipals | Select-String $utilisateur
    if ($Deleg)
    {
        Write-Host "Correspondances trouvées pour " $ForeignSecurityPrincipals -ForegroundColor Red 
        $Deleg | Select-Object -Unique
        $titi = 1
    }

    # Managed Service Accounts
    $Managed = "CN=Managed Service Accounts,"+ $DNDomaine
    $Deleg = dsacls.exe $Managed | Select-String $utilisateur
    if ($Deleg)
    {
        Write-Host "Correspondances trouvées pour " $Managed -ForegroundColor Red 
        $Deleg | Select-Object -Unique
        $titi = 1
    }

    # Users
    $Users = "CN=Users,"+ $DNDomaine
    $Deleg = dsacls.exe $Users | Select-String $utilisateur
    if ($Deleg)
    {
        Write-Host "Correspondances trouvées pour " $Users -ForegroundColor Red 
        $Deleg | Select-Object -Unique
        $titi = 1
    }



    if ($titi -eq 0)
    {
        Write-Host "Rien à signaler."
        $Deleg = "Rien à signaler"
    }
}
$delega = Check_Deleg
$delega


################ Exportation du rapport en HTML ################
Write-Host "`nExportation du rapport en HTML" -BackgroundColor Red


$header=@"
<head>
<title>Rapport de sécurité pour $utilisateur</title>
</head><body>
<table>

<colgroup><col/><col/><col/><col/></colgroup>
<tr><th>Mesures de sécurité</th><th>Résultats</th></tr>

<style>
h1, h5, th { text-align: center; font-family: Segoe UI; }
table { margin: auto; font-family: Segoe UI; box-shadow: 10px 10px 5px #888; border: thin ridge grey; }
th { background: #0046c3; color: #fff; max-width: 400px; padding: 5px 10px; }
td { font-size: 11px; padding: 5px 20px; color: #000; }
tr { background: #b8d1f3; }
tr:nth-child(even) { background: #dae5f4; }
tr:nth-child(odd) { background: #b8d1f3; }
</style>

"@
$footer=@"
</table>
</body></html>
"@

$body=@"
<h1>Rapport de sécurité pour $nomcomplet</h1>
<h5>Généré le $(Get-Date)

"@
$body+="<tr><td>SAN & UPN :</td><td>$san & $upn</td></tr>"
$body+="<tr><td>Groupes rattachés à l'utilisateur :</td><td>$groupes</td></tr>"
$body+="<tr><td>Heure de sa dernière connexion :</td><td>$dateclassique</td></tr>"
$body+="<tr><td>Vulnérable à l'AS_REP Roasting :</td><td>$asreproast</td></tr>"
$body+="<tr><td>Vulnérable au Kerberoasting :</td><td>$kerber</td></tr>"
$body+="<tr><td>L'utilisateur peut utiliser NTLM :</td><td>$ntlm</td></tr>"
$body+="<tr><td>Liste des ACL à surveiller :</td><td>$acluser_epure</td></tr>"
$body+="<tr><td>Sessions en cours par l'utilisateur :</td><td>$sessionuser</td></tr>"
$body+="<tr><td>Vérification des délégations de contrôles :</td><td>$delega</td></tr>"
"

"


-join $header,$body,$footer | Out-File $env:UserProfile\Desktop\Rapport_$utilisateur.html
Invoke-Expression .\RapportAudit.html
Write-Host "Le rapport final se trouve sur votre bureau" -BackgroundColor Black
##>

Write-Host "Fin"
###### FIN ###### 
