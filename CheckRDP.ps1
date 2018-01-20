# Author: Saleh Bin Muhaysin
# Github: https://github.com/salehmuhaysin
# Blog: https://salehsecurity.wordpress.com/
# Powershell Script used to parse Windows Event logs (.evtx) files to find if there was a Remote Desktop Connection
# file could be used:
# 	Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
# 	Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
# 	Security
# 	Microsoft-Windows-TerminalServices-RDPClient/Operational
# 	Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational

# How to use:
# 	.\CheckRDP.ps1 input-evtx-file [output-csv-file]

param (
   [string]$file = "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
   [string]$csvfile = "$($file).csv"
)

Write-Host "
                            *&                             
                          *****                            
                       /**********&                        
                 &(********************#                   
   ******************************************/////////     
   *****************************************//////////     
   ***************************************////////////     
   **************************************/////////////     
   ************************************///////////////     
   ***********************************////////////////     
   *********************,       .***//////////////////     
   *******************             ///////////////////     
   ******************     *****.    ,/////////////////     
   *****************    ,******//    /////////////////     
   *****************    ******///    /////////////////     
   *****************    ****/////    /////////////////     
   *****************    ***//////    /////////////////     
   **************.                      //////////////     
   **************.                      //////////////     
   **************.                      //////////////     
   **************.  Saleh Bin Muhaysin  //////////////     
   **************.                      //////////////     
   /*************.                      //////////////     
    ************/.                      /////////////(     
    (*********////,....................*//////////////      
     /****   https://github.com/salehmuhaysin   /////       
       ****///////////////////////////////////////(        
        /////////////////////////////////////////      
          /////////////////////////////////////            
            #////////////////////////////////              
               ///////////////////////////                 
                  /////////////////////(                   
                     ///////////////#                      
                        /////////                          
=========================================================="

Write-Host "[+] Checking file: " $file


# =====================================================
# Checking: Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
# =====================================================
if($file -like "*Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx"){

	$Events = Get-WinEvent -FilterHashtable @{ Path =$file; Id=25,24} 	# get only event id 25 and 24
	$EventsCSV = New-Object System.Collections.ArrayList				# store all remote connection objects to be exported to csv

	ForEach ($Event in $Events) {   
		$eventXML = [xml]$Event.ToXml()   	# convert the winevent object ot xml
		$datetime = Get-Date $eventXML.Event.System.TimeCreated.GetAttribute("SystemTime") -format G # Convert the datetime format
		
		
		if($eventXML.Event.UserData.EventXML.Address -ne "LOCAL"){	# exclude LOCAL connections
			[void]$EventsCSV.Add($Event)
			# Event ID 25: established connection
			# Event ID 24: disconnection
			if($eventXML.Event.System.EventID -eq 25){
				Write-Host  "Remote Desktop Connection: EID[" $eventXML.Event.System.EventID "] `t Source:" $eventXML.Event.UserData.EventXML.Address " `t at " $datetime " -> Connected"
			} elseif ($eventXML.Event.System.EventID -eq 24){
				Write-Host  "Remote Desktop Connection: EID[" $eventXML.Event.System.EventID "] `t Source:" $eventXML.Event.UserData.EventXML.Address " `t at " $datetime " -> DisConnected"

			}
		}
		
	}
	$EventsCSV | Export-CSV -Path $csvfile	# export the results to CSV file

} 

# =====================================================
# Checking: Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
# =====================================================
if($file -like "*Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx"){

	$Events = Get-WinEvent -FilterHashtable @{ Path =$file; Id=261,1149} 	# get only event id 261 and 1149
	$EventsCSV = New-Object System.Collections.ArrayList					# store all remote connection objects to be exported to csv

	ForEach ($Event in $Events) {   
		$eventXML = [xml]$Event.ToXml()   	# convert the winevent object ot xml
		$datetime = Get-Date $eventXML.Event.System.TimeCreated.GetAttribute("SystemTime") -format G # Convert the datetime format
		
		
		[void]$EventsCSV.Add($Event)
		# Event ID 261: successful or failed received RDP connection
		# Event ID 1149: successful RDP Authentication
		if($eventXML.Event.System.EventID -eq 261){
			Write-Host  "Remote Desktop Connection: EID[" $eventXML.Event.System.EventID "] `t at " $datetime " `t-> Trying connect"
		} elseif ($eventXML.Event.System.EventID -eq 1149){
			Write-Host  "Remote Desktop Connection: EID[" $eventXML.Event.System.EventID "] `t at " $datetime " `t-> Successful Authentication, `tSource:" $eventXML.Event.UserData.EventXML.Param3 
		}
		
		
	}
	$EventsCSV | Export-CSV -Path $csvfile	# export the results to CSV file

} 

# =====================================================
# Checking: Security
# =====================================================
if($file -like "*Security.evtx"){
	$Events = Get-WinEvent -FilterHashtable @{ Path =$file; Id=4624,4634} 	# get only event id 4624 and 4634
	$EventsCSV = New-Object System.Collections.ArrayList					# store all remote connection objects to be exported to csv
	
	ForEach ($Event in $Events) {   
		$eventXML = [xml]$Event.ToXml()   	# convert the winevent object ot xml
		$datetime = Get-Date $eventXML.Event.System.TimeCreated.GetAttribute("SystemTime") -format G # Convert the datetime format
		
		# Event ID 4624: RDP logon
		# Check Event ID 4634 and compare Logon ID to know when logoff happen
		if($eventXML.Event.System.EventID -eq 4624){
			$eventXML.Event.EventData.Data | ForEach {
				if ($_.Name -eq "IpAddress" -and $_.InnerText -ne "127.0.0.1" -and $_.InnerText -ne "-" ) { # exclude local logon
					[void]$EventsCSV.Add($Event) # add the event to CSV
					Write-Host "Remote Desktop Connection: EID[" $eventXML.Event.System.EventID "] `tSource: $($_.InnerText) `t at " $datetime " `t-> successful RDP connection logon"
				}					
			}
			
		}
		
		
	}
	$EventsCSV | Export-CSV -Path $csvfile	# export the results to CSV file
}







# =====================================================
# Checking: Microsoft-Windows-TerminalServices-RDPClient/Operational
# Only Windows-10
# =====================================================
if($file -like "*Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx"){
	$Events = Get-WinEvent -FilterHashtable @{ Path =$file; Id=1024,1027 } 	# get only event id 1024 and 1027
	$EventsCSV = New-Object System.Collections.ArrayList				# store all remote connection objects to be exported to csv
	
	ForEach ($Event in $Events) {   
		$eventXML = [xml]$Event.ToXml()   	# convert the winevent object ot xml
		$datetime = Get-Date $eventXML.Event.System.TimeCreated.GetAttribute("SystemTime") -format G # Convert the datetime format
		
		# Event ID 1024: If the current machine tryied to connect to other using RDP (success or fail)
		if($eventXML.Event.System.EventID -eq 1024){
			$eventXML.Event.EventData.Data | ForEach {
				if ($_.Name -eq "Value") {
					[void]$EventsCSV.Add($Event) # add the event to CSV
					Write-Host "Remote Desktop Connection: EID[" $eventXML.Event.System.EventID "] `t at " $datetime " `t-> Trying to connect to $($_.InnerText) "
				}					
			}
			
		}
		
		# Event ID 1027: If the current machine connected to another computer (only success)
		if ($eventXML.Event.System.EventID -eq 1027){
			$eventXML.Event.EventData.Data | ForEach {
				if ($_.Name -eq "DomainName") {
					[void]$EventsCSV.Add($Event) # add the event to CSV
					Write-Host "Remote Desktop Connection: EID[" $eventXML.Event.System.EventID "] `t at " $datetime " `t-> Successful connected to $($_.InnerText) "
				}					
			}
		}
		
	}
	$EventsCSV | Export-CSV -Path $csvfile	# export the results to CSV file
}




# =====================================================
# Checking: Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational
# =====================================================
if($file -like "*Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx"){
	$Events = Get-WinEvent -FilterHashtable @{ Path =$file; Id=131,140 } 	# get only event id 131 and 140
	$EventsCSV = New-Object System.Collections.ArrayList					# store all remote connection objects to be exported to csv
	
	ForEach ($Event in $Events) {   
		$eventXML = [xml]$Event.ToXml()   	# convert the winevent object ot xml
		$datetime = Get-Date $eventXML.Event.System.TimeCreated.GetAttribute("SystemTime") -format G # Convert the datetime format
		
		# Event ID 131: successful or failed received RDP connection
		if($eventXML.Event.System.EventID -eq 131){
			$eventXML.Event.EventData.Data | ForEach {
				if ($_.Name -eq "ClientIP") {
					[void]$EventsCSV.Add($Event) # add the event to CSV
					Write-Host "Remote Desktop Connection: EID[" $eventXML.Event.System.EventID "] `t Source:$($_.InnerText) `t at " $datetime " -> Trying connected"
				}					
			}
			
		}
		# Event ID 140: if client used wrong username and password to connect
		if ($eventXML.Event.System.EventID -eq 140){
			$eventXML.Event.EventData.Data | ForEach {
				if ($_.Name -eq "IPString") {
					[void]$EventsCSV.Add($Event) # add the event to CSV
					Write-Host "Remote Desktop Connection: EID[" $eventXML.Event.System.EventID "] `t Source:$($_.InnerText) `t`t at " $datetime " -> Trying connected (Username/Password Failed)"
				}					
			}
		}
		
	}
	$EventsCSV | Export-CSV -Path $csvfile	# export the results to CSV file
}
