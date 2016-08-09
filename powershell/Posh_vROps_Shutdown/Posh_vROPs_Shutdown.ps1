
    Add-PSSnapin VMware.VimAutomation.Core

    # Setting up some variables
    # v 0.8
    Clear-Host 
    $ErrorActionPreference = "Stop"
    $VerbosePreference = "Silent"
    $Error.Clear()
    $strScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
    $strRootFolder = Split-Path -Parent $strScriptPath
    $strDataFile = $strScriptPath + "\vROPs_Shutdown_XML.xml"

    # Bypassing SSL errors with self-signed certificates
    add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem) {
                return true;
            }
        }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

    # This function will append log data to the specified log file as well as print to the console
    function fnLogData ($strDataToLog, $strLogFile){
        if ($strDataToLog -and (Test-Path -LiteralPath $strLogFile)){
            Write-Host $strDataToLog
            $strDataToLog | Out-File $strLogFile -Append
        } # end if
    } # end fnLogData

    # This function will create a timestamped log file or use an existing log
    function fnCreateLog ($rootPath){
        if (!$rootPath){ throw "ERROR - No path passed to fnCreateLog" }
        if (Test-Path $rootPath){
            $dateStamp = Get-Date -Format yyyy-MM-dd_-_hh_mm
            $logfileName = "vROps_Shutdown_Log_$dateStamp.txt"
            if (Test-Path -LiteralPath "$strScriptPath\$logfileName"){
                # If there is already a log with this name we'll use append to it
                $logfilePath = "$strScriptPath\$logfileName"
            } else {
                # If there is no log with this name we'll make one here
                $objLogfile = New-Item "$strScriptPath\$logfileName" -ItemType file | Out-Null
                $logfilePath = "$strScriptPath\$logfileName"
                fnLogData "INFO - Log file $logfile created at $(Get-Date)" $logFilePath
            } # end if
            return $logfilePath
        } else {
            throw "ERROR - Invalid path passed to fnCreateLog"
        } # end if
    } # end fnCreateLog

    # This function will return the current cluster status. If a node href is passed in we'll use that. Timeout is optional, default is 30s
    function fnClusterStatus ($strvROpsHost, $objCreds, $strNode, $intTimeoutInSeconds){
        if (!$strvROpsHost -and !$strNode) { $msg = "ERROR - fnClusterStatus called with no vROps Host or Node href"; fnLogData $msg $logfile; throw $msg }
        if (!$objCreds -and $objCreds.GetType().Name -ne "PSCredential") { $msg = "ERROR - Invalid fnClusterStatus called with invalid credentials"; fnLogData $msg $logfile; throw $msg }
        if (!$intTimeoutInSeconds) { $intTimeoutInSeconds = 30 }
        # Setting the Uri of our REST call. We can pass a full uri in $strNode or use the vROps hostname and build the uri
        if ($strNode){
            $strvROpsUri = $strNode
        } else {
            $strvROpsUri = "https://$strvROpsHost/casa/sysadmin/cluster/online_state"
        } # end if
        try {
            # Making the REST call
            $objClusterState = Invoke-RestMethod -Uri $strvROPsUri -ContentType "application/json" -Credential $objCreds -TimeoutSec $intTimeoutInSeconds
        } catch {
            $strHostSplit = $strvROpsUri.Split("/")[2]
            $strHostSplit = $strHostSplit.Replace(":443", "")
            fnLogData "WARN - $strHostSplit is currently unavailable" $logfile
        } # end try/catch
        return $objClusterState
    } # end fnClusterStatus

    # This function will attempt a graceful shutdown of a VM using the $intSleepTimeInMinutes wait timeout between polls
    Function fnShutdownVM ($objVM, $objvCenter, $intSleepTimeInMinutes){
        # Setting a default sleep time of 1 minute if nothing is specified
        if (!$intSleepTimeInMinutes) { $intSleepTimeInMinutes = 1 }
        $strVMName = $objVM.Name
        # First we'll get the PowerState. There's no point sending the shutdown command if the VM is already off
        $strCurrentPowerState = $objVM.PowerState
        if ($strCurrentPowerState -eq "PoweredOff") { return "INFO - $($objVM.Name) was already in $strCurrentPowerState PowerState. No action was performed on this VM" }
        fnLogData "INFO - Shutting down $($objVM.Name)" $logfile
        # Sending the initial shutdown command
        try {
            $shutdownResult = Stop-VMGuest -VM $objVM -Server $objvCenter -Confirm:$False
        } catch {
            fnLogData "ERROR - Unable to send shutdown command to $($objVM.Name)" $logfile
        } # end try/catch
        # Waiting until the power state is off
        do {
            $objTempVM = Get-VM -Name $strVMName -Server $objvCenter
            $strTempPowerState = $objTempVM.PowerState
            if ($strTempPowerState -eq "PoweredOff") { break }
            fnLogData "INFO - $strVMName current PowerState is: $strTempPowerState. Waiting $intSleepTimeInMinutes minute(s) for: PoweredOff State" $logfile
            Start-Sleep ($intSleepTimeInMinutes * 60)
        } while ($strTempPowerState -ne "PoweredOff")
        return "INFO - Shutdown successful for VM: $strVMName. VM is now in PowerState: $($objTempVM.PowerState)"
    } # end fnShutdownVM

    # This function will startup a vROps VM and wait for it to reach OFFLINE state in the vROps cluster
    Function fnStartupvROpsVM ($objStartupVM, $objvCenter, $objInputvROpsCreds, $strvROpsMasterName, $intSleepTimeInMinutes){
        fnLogData "INFO - Attempting to start VM: $($objStartupVM.Name)" $logfile
        # First we'll process the startup command for the VM(s)
        try {
            if ($objStartupVM.PowerState -eq "PoweredOff"){
                Start-VM -VM $objStartupVM -Server $objvCenter -Confirm:$False
                fnLogData "INFO - Startup command sent to VM $($objStartupVM.Name)" $logfile
            } else {
                fnLogData "WARN - VM: $($objStartupVM.Name) was in power state: $($objStartupVM.PowerState)" $logfile
            } # end if
        } catch {
            $strStartupResult = "ERROR - Unable to start VM: $($objStartupVM.Name)"
        } # end try/catch
        # We need the IP address of the VM to check the cluster state in vROps
        $strCurrentIP = $Null
        do {
            # Powered off VM's have null entries for Guest.IPAddress so we need to wait for that
            $objTempVM = Get-VM -Name $objStartupVM.Name
            $strCurrentIP = $objTempVM.Guest.IPAddress[0]
            if ($strCurrentIP.Length -lt 1){
                fnLogData "INFO - Waiting 30 seconds for $($objStartupVM.Name) VMware tools to display an IP" $logfile
                Start-Sleep 30
            } # end if
        } while ($strCurrentIP.Length -lt 1)
        fnLogData "INFO - Node IP retrieved as: $strCurrentIP" $logfile
        # Once the VM has been powered on we'll need to examine the vROps cluster status to figure out if it's ready/online
        $blSliceReady = $False
        do {
            # First we'll get the current state of the cluster
            $strTempClusterState = fnClusterStatus $strHostnameMaster $objInputvROpsCreds
            try {
              $objSliceState = $strTempClusterState.slice_online_states | Where slice_online_state -eq "OFFLINE"
               $arrSliceAddresses = $objSliceState.sliceAddresses
            } catch {
                # If the Master Node is being brought online we won't get the cluster state right away
            } # end try/catch
            if ($arrSliceAddresses -contains $strCurrentIP){
                $blSliceReady = $True
            } else {
                fnLogData "INFO - Waiting $intSleepTimeInMinutes minute(s) for $($objStartupVM.Name) to return to OFFLINE state in vROps cluster" $logfile
                Start-Sleep ($intSleepTimeInMinutes * 60)
            } # end if
        } while ($blSliceReady -ne $True)
        return $True
    } # end fnStartupvROPsVM

    # This function will connect to the vCenter specified in the parameters
    # If $objCreds contains a credential object it will be used instead of $strUserName and $strPassword
    Function fnConnectvCenter ($strvCenterHost, $objCreds, $strUserName, $strPassword){
        if ($strvCenterHost -eq $Null){fnLogData "ERROR - Invalid vCenter host passed" $logfile;Return}
        if ($objCreds -eq $Null -and ($strUserName -and $strPassword -eq $Null)){
            $msg = "ERROR - Invalid vCenter credentials passed to fnConnectvCenter for host: $strvCenterHost"
            fnLogData $msg $logfile
            throw $msg
        } # end if
        try {
            fnLogData "INFO - Connecting to $strvCenterHost" $logfile
            # Checking if we're already connected
            $colConnectedServers = ($global:DefaultVIServers | Select-Object Name).Name
            if ($colConnectedServers -notcontains $strvCenterHost){
                $blConnected = $True
                # Using PSCredential object if one is available or reverting to plaintext username and password
                if ($objCreds.GetType().Name -eq "PSCredential"){
                    $objvCenter = Connect-VIServer -Server $strvCenterHost -Credential $objCreds -WarningAction SilentlyContinue
                } else {
                    $objvCenter = Connect-VIServer -Server $strvCenterHost -User $strUserName -Password $strPassword -WarningAction SilentlyContinue
                } # end if
                fnLogData "INFO - Connected to $strvCenterHost successfully" $logfile
            } else {
                $objvCenter = $global:DefaultVIServers | Where Name -eq $strvCenterHost
                fnLogData "INFO - $strvCenterHost is already connected" $logfile
            } # end if
            return $objvCenter
        } catch {
            fnLogData "ERROR - Unable to connect to $strvCenterHost" $logfile
            fnLogData $Error $logfile
        } # end try/catch
        return
    } # end fnConnectvCenter

    # This function will disconnect from a single vCenter if one is specified otherwise it disconnects all currently connected VI-Servers
    Function fnDisconnectvCenter ($strvCenterHost) {
        try {
            $colConnectedServers = ($global:DefaultVIServers | Select-Object Name).Name
            if ($strvCenterHost -ne $null){
                if ($colConnectedServers -contains $strvCenterHost){
                    Disconnect-VIServer -Server $strvCenterHost -Force -Confirm:$False
                    fnLogData "INFO - Disconnect from vCenter: $strvCenterHost successfully" $logfile
                } else {
                    fnLogData "WARN - Not connected to $strvCenterHost" $logfile
                } # end if
            } else {
                try {
                    foreach ($objVC in $colConnectedServers){
                        Disconnect-VIServer -Force -Confirm:$False
                    } # end foreach
                    fnLogData "INFO - Disconnected all vCenter Servers successfully" $logfile
                } catch {
                    fnLogData "ERROR - Unable to disconnect from all vCenter Servers" $logfile
                } # end try/catch
            } # end if
        } catch {
            fnLogData "ERROR - There was a problem disconnecting one or more vCenter Servers" $logfile
        } # end try/catch
    } # end fnDisconnectvCenter

    # This function will get the encryption key we'll use to store and retrieve the passwords in the XML file
    function fnGetEncryptionKey(){
        # Getting a 16 digit (128bit AES) encryption key
        do {
            $strPInput = Read-Host -AsSecureString "Enter a 16 digit encryption key"
        } until ($strPInput.Length -eq 16)
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($strPInput)
        $strPInput = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        return $strPInput
    } # end fnGetEncryptionKey

    # This function will get an Xml Node from the XML Object using $strNodePath
    function fnGetXmlNode ($objXMLData, $strNodePath){
        if (!$objXMLData) { $msg = "ERROR - No XML Object passed to fnGetXmlNode"; fnLogData $msg $logfile; throw $msg }
        try {
            $objXmlNsMgr = New-Object System.Xml.XmlNamespaceManager($objXMLData.NameTable)
            $objXmlNsMgr.AddNamespace("ns", $objXMLData.DocumentElement.NamespaceURI)
            $XmlFqdn = "/ns:$($strNodePath.Replace($('.'), '/ns:'))"
            $objNode = $objXMLData.SelectSingleNode($XmlFqdn, $objXmlNsMgr)
            return $objNode
        } catch {
            fnLogData "ERROR - Unable to retrieve XML Node at path: $strNodePath" $logfile
        } # end try/catch
        return $Null
    } # end fnGetXmlNode

    # This function will request a password and store it in the specified XML Node of the XML file specified and return a SecureString
    function fnGetAndStorePassword($strGetSaveUsername, $strGetSaveHostname, $strEncKey, $objXMLInputData, $strNodePath, $strXMLDataFile){
        do {
            $strPasswordInput = Read-Host -AsSecureString "Enter password for user: $strGetSaveUsername to system: $strGetSaveHostname"
            [string]$strPasswordEnc = $strPasswordInput | ConvertFrom-SecureString -Key $strEncKey
            # First we need to find the right Xml Node to update
            $objRetNode = fnGetXmlNode $objXMLInputData $strNodePath
            $objRetNode.InnerText = $strPasswordEnc
            # Saving the encrypted password back to the XML
            $objXMLInputData.Save($strXMLDataFile)
        } until ($strPasswordInput.Length -gt 0)
        return $strPasswordInput
    } # end fnGetAndStorePassword
    
    # This function will return the current cluster status
    function fnClusterStatus ($strvROpsHost, $objCreds){
        if (!$strvROpsHost) { $msg = "ERROR - fnClusterStatus called with no vROps Host"; fnLogData $msg $logfile; throw $msg }
        if (!$objCreds -and $objCreds.GetType().Name -ne "PSCredential") { $msg = "ERROR - Invalid fnClusterStatus called with invalid credentials"; fnLogData $msg $logfile; throw $msg }
        # Setting the Uri of our REST call
        $strvROpsUri = "https://$strvROpsHost/casa/sysadmin/cluster/online_state"
        $objClusterState = Invoke-RestMethod -Uri $strvROPsUri -ContentType "application/json" -Credential $objCreds
        return $objClusterState
    } # end fnClusterStatus

    # Function to sleep IE while it's busy
    Function fnIESleeper($IEInstance, $intTimeoutInSeconds){
        if ($IEInstance){
            # Setting a default timeout of 5s if no value is specified
            if (!$intTimeoutInSeconds){ $intTimeoutInSeconds = 5 }
            While ($IEInstance.Busy -eq $True){
                fnLogData "INFO - Waiting $intTimeoutInSeconds seconds for IE" $logfile
                Start-Sleep -Seconds $intTimeoutInSeconds
            } # end While
        } else {
            fnLogData "ERROR - No IE Instance passed to fnIESleeper" $logfile
        } # end if
    } # end fnIESleeper

    # This function will take  the vROPs Cluster Offline or bring it Online based on the parameters passed
    function fnClusterOps ($strvROPsHost, $strOperation, $objCreds, $intTimeoutInMinutes) {
        if (!$strvROPsHost) { $msg = "ERROR - fnClusterOps called with no vROps Host"; fnLogData $msg $logfile; throw $msg }
        if ( (!$strOperation) -or ($strOperation -ne "ONLINE") -and ($strOperation -ne "OFFLINE") ) { $msg = "ERROR - fnClusterOps called with invalid Operation"; fnLogData $msg $logfile; throw $msg }
        if (!$objCreds -and $objCreds.GetType().Name -ne "PSCredential") { $msg = "ERROR - Invalid fnClusterOps called with invalid credentials"; fnLogData $msg $logfile; throw $msg }
        if (!$intTimeoutInMinutes) { $intTimeoutInMinutes = 1 }
        $strOperation = $strOperation.ToUpper()
        $strContentType = "application/json"
        $strvROPsUri = "https://$strvROPsHost/casa/sysadmin/cluster/online_state"
        # Checking what state the Cluster is currently in before we do anything
        $objCurrentStatus = Invoke-RestMethod -Method "GET" -Uri $strvROPsUri -ContentType $strContentType -Credential $objCreds
        if ($objCurrentStatus.cluster_online_state_snapshot -eq $strOperation){
            fnLogData "INFO - Cluster was already in $strOperation state" $logfile
            return $objCurrentStatus
        } # end if
        # Sending the REST call to perform the initial operation
        fnLogData "INFO - Cluster $strOperation operation is being processed" $logfile
        $strBody = "{""online_state"": ""$strOperation"", ""online_state_reason"": ""vROps Automated Task - Posh""}"
        $strClusterCommand = Invoke-RestMethod -Method "POST" -Uri $strvROPsUri -ContentType $strContentType -Credential $objCreds -Body $strBody
        $strCurrentState = ""
        do {
            # Checking the Cluster State until it returns to either ONLINE or OFFLINE
            $strClusterCheckState = Invoke-RestMethod -Uri $strvROPsUri -ContentType "application/json" -Credential $objCreds
            $strCurrentState = $strClusterCheckState.cluster_online_state_snapshot
            if ($strCurrentState -eq $strOperation) { return $strClusterCheckState }
            fnLogData "INFO - Cluster Status currently: $strCurrentState. Sleeping $intTimeoutInMinutes minute(s). Waiting for status: $strOperation" $logfile
            Start-Sleep -Seconds (60 * $intTimeoutInMinutes)
        } while ($strCurrentState -ne $strOperation)
        fnLogData "INFO - Cluster status is now: $strCurrentState" $logfile
        return $strClusterCheckState
    } # end fnClusterOps

    ##############
    ### main() ###
    ##############

    # Creating the log file
    $logfile = fnCreateLog $strScriptPath
    # Logging the time we start
    fnLogData "INFO - Script started at $(Get-Date)" $logfile
    # PowerCLI Version check. We need v6 installed to use the new Stop-VMGuest cmdlet
    $strPowerCLIError = "ERROR - You do not have v6+ of PowerCLI. Please update the host and run again"
    try {
        if ((Get-PowerCLIVersion).Major -lt 6){ fnLogData $strPowerCLIError $logfile; throw $strPowerCLIError } else { fnLogData "INFO - PowerCLI Major Version confirmed as: $((Get-PowerCLIVersion).Major)" $logfile }
    } catch {
        fnLogData $strPowerCLIError $logfile
        throw $strPowerCLIError
    } # end try/catch

    #########################
    # Validating vROPs data #
    #########################

    # Importing the xml file
    if (!(Test-Path $strDataFile)) { $msg = "ERROR - Unable to find xml file at location: $strDataFile"; fnLogData $msg $logfile; throw $msg }
    [xml]$objRawData = Get-Content $strDataFile
    # Getting the requested Cluster Operation
    $arrScriptReqs = @($objRawData.vrops.scriptOperations.scriptOp | Where requested -eq true)
    if ($arrScriptReqs.Length -ne 1) { $msg = "ERROR - Too many/few requested scriptOps in XML file. Requested number of ops: $($arrScriptReqs.Length)"; fnLogData $msg $logfile; throw $msg }
    $strRequestedClusterOp = $arrScriptReqs.clusterOp
    # Getting the vROPs username
    $strUsernamevROPs = $objRawData.vrops.vropsMain.username
    if (!$strUsernamevROPs) { $msg = "ERROR - XML - No username set for vropsMain"; fnLogData $msg $logfile; throw $msg }
    # Checking to see if the encryption key is stored insecurely
    $strPInput = $objRawData.vrops.vropsInsecureStorage.password
    if (!$strPInput){
        # Getting a 16 digit (128bit AES) encryption key
        $strPInput = fnGetEncryptionKey
    } # end if
    $arrEnkey = $strPInput.ToString().ToCharArray()
    [Byte[]] $byteArrayKey = $arrEnkey
    # Checking for vROPs password
    $strPasswordvROPs = $objRawData.vrops.vropsMain.password
    if (!$strPasswordvROPs){
        $strvROPsInput = fnGetAndStorePassword $strUsernamevROPs "vROPs Main Password" $byteArrayKey $objRawData "vrops.vropsMain.password" $strDataFile
    } else {
        # An error here usually means an invalid encryption key was specified
        try {
            $strvROPsInput = $strPasswordvROPs | ConvertTo-SecureString -Key $byteArrayKey
        } catch {
            $msg = "ERROR - An invalid encryption key was specified"
            fnLogData $msg $logfile
            throw $msg
        } # end try/catch
    } # end if
    # Making a PSCredential Object for vROPs
    $objvROPsCreds = New-Object System.Management.Automation.PSCredential($strUsernamevROPs, $strvROPsInput)
    #$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($strvROPsInput)
    #$strvRopsInsInput = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    # Getting the Master Node hostname
    $strHostnameMaster = $objRawData.vrops.mainNodes.masterNode.hostname
    if (!$strHostnameMaster) { $msg = "ERROR - XML - No hostname set for masterNode"; fnLogData $msg $logfile; throw $msg }

    ######################
    # Cluster Operations #
    ######################

    # All operations related to stopping/starting/restarting and initial offline (for Node restart) of the vROPs Cluster happen here
    fnLogData "INFO - Requested Cluster Operation: $strRequestedClusterOp" $logfile
    $blStopProcessing = $False
    if ($strRequestedClusterOp -eq "Online_Cluster"){
        # Attempting to bring the Cluster Online
        $strClusterFinalState = fnClusterOps $strHostnameMaster "ONLINE" $objvROPsCreds $Null
        fnLogData "END - Cluster State is: $($strClusterFinalState.cluster_online_state_snapshot)" $logfile
        $blStopProcessing = $True
    } elseif ($strRequestedClusterOp -eq "Offline_Cluster"){
        # Taking the Cluster Offline
        $strClusterFinalState = fnClusterOps $strHostnameMaster "OFFLINE" $objvROPsCreds $Null
        fnLogData "END - Cluster State is: $($strClusterFinalState.cluster_online_state_snapshot)" $logfile
        $blStopProcessing = $True
    } elseif ($strRequestedClusterOp -eq "Restart_Cluster"){
        # Restarting the Cluster
        $strClusterOfflineState = fnClusterOps $strHostnameMaster "OFFLINE" $objvROPsCreds $Null
        if ($strClusterOfflineState.cluster_online_state_snapshot -eq "OFFLINE"){
            fnLogData "INFO - Cluster State is now: $($strClusterOfflineState.cluster_online_state_snapshot)" $logfile
            $strClusterFinalState = fnClusterOps $strHostnameMaster "ONLINE" $objvROPsCreds $Null
            if ($strClusterFinalState.cluster_online_state_snapshot -eq "ONLINE"){ fnLogData "END - vROPs Cluster restarted successfully" $logfile }
        } else {
            fnLogData "ERROR - Unable to bring Cluster Online. Current state of Cluster is: $($strClusterFinalState.cluster_online_state_snapshot)" $logfile
        } # end if
        $blStopProcessing = $True
    } elseif (($strRequestedClusterOp -match "Reboot") -or ($strRequestedClusterOp -match "Shutdown")){
        # Taking the Cluster Offline but continuing processing of the script
        $strClusterFinalState = fnClusterOps $strHostnameMaster "OFFLINE" $objvROPsCreds $Null
        fnLogData "INFO - Current State of Cluster is: $($strClusterFinalState.cluster_online_state_snapshot)" $logfile
    } # end if
    # If there is no reboot operation pending we will end the script here
    if($blStopProcessing) { return }

    ################################
    # Processing Reboot Operations #
    ################################

    # Making an array to store our list of VM hostnames along with their role and vCenter
    $arrAllVMs = @()
    # Getting the Main vCenter hostname
    $strHostnameVCMain = $objRawData.vrops.vcenterMain.vchostname
    if (!$strHostnameVCMain) { $msg = "ERROR - XML - No hostname set for vCenterMain"; fnLogData $msg $logfile; throw $msg }
    # Adding the vROPs Master node
    $arrAllVMs += New-Object -TypeName PSObject -Property @{hostname = $strHostnameMaster; vCenter = $strHostnameVCMain; role = "master"}
    # Getting the Replica Node hostname
    $strHostnameReplica = $objRawData.vrops.mainNodes.replicaNode.hostname
    if ($strHostnameReplica) {
        $arrAllVMs += New-Object -TypeName PSObject -Property @{hostname = $strHostnameReplica; vCenter = $strHostnameVCMain; role = "replica"}
    } # end if
    # Getting any Main Data Nodes
    $arrDataNodesMain = $objRawData.vrops.mainNodes.dataNodes.dNode.hostname | Where Length -ne 0
    $arrAllDNodes = $arrDataNodesMain | ForEach-Object {
        New-Object -TypeName PSObject -Property @{hostname = $_ ; vCenter = $strHostnameVCMain; role = "dNodeMain"}
    } # end ForEach-Object
    # Adding the Main Data Nodes to the array of VM's
    $arrAllVMs += $arrAllDNodes
    # Getting the Main vCenter username
    $strUsernameVCMain = $objRawData.vrops.vcenterMain.username
    if (!$strUsernameVCMain) { $msg = "ERROR - XML - No username set for vCenterMain"; fnLogData $msg $logfile; throw $msg }
    # Checking for vcenterMain passwword
    $strPasswordVCMain = $objRawData.vrops.vcenterMain.password
    if (!$strPasswordVCMain){
        # Getting a password for the Main vCenter
        $strVCPInput = fnGetAndStorePassword $strUsernameVCMain $strHostnameVCMain $byteArrayKey $objRawData "vrops.vcenterMain.password" $strDataFile
    } else {
        # Password exists in the XML so we'll try to use it here
        $strVCPInput = $strPasswordVCMain | ConvertTo-SecureString -Key $byteArrayKey
    } # end if
    # Creating a credential object to connect to the main vCenter
    $objCredsVCMain = New-Object System.Management.Automation.PSCredential($strUsernameVCMain, $strVCPInput)
    # Connecting to the main vCenter
    $objvCenterMain = fnConnectvCenter $strHostnameVCMain $objCredsVCMain
    if ($objvCenterMain -and (!($objvCenterMain.GetType().Name -eq "VIServerImpl"))) { $msg = "ERROR - Unable to connect to vcenterMain $strHostnameVCMain"; fnLogData $msg $logfile; throw $msg }
    # We'll only verify the RG Groups if the requested Cluster Operation is for All Nodes
    if ($strRequestedClusterOp -match "All_Nodes"){
        # Getting any Data Nodes for Remote Group 01
        $arrDataNodesRG01 = $objRawData.vrops.remoteNodesGroup01.rNode.hostname | Where Length -ne 0
        # Getting the Remote Group 01 vCenter details if any Data Nodes were specified in Remote Group 01
        if ($arrDataNodesRG01.Count -gt 0){
            # Getting the vCenter hostname for RG01
            $strHostnameVCRG01 = $objRawData.vrops.remoteNodesGroup01vcenter.hostname
            if (!$strHostnameVCRG01) { $msg = "ERROR - XML - Remote Group 01 Data Nodes specified with no vCenter hostname"; fnLogData $msg $logfile; throw $msg }
            # Getting the vCenter username for RG01
            $strUsernameVCRG01 = $objRawData.vrops.remoteNodesGroup01vcenter.username
            if (!$strUsernameVCRG01) { $msg = "ERROR - XML - Remote Group 01 Data Nodes specified with no vCenter username"; fnLogData $msg $logfile; throw $msg }
            # Checking for the vCenter password for RG01
            $strVCRG01Password = $objRawData.vrops.remoteNodesGroup01vcenter.password
            # If there's no password we'll set and save it here using the encryption key we already set in $byteArrayKey
            if (!$strVCRG01Password){
                $strVCRG01Input = fnGetAndStorePassword $strUsernameVCRG01 $strHostnameVCRG01 $byteArrayKey $objRawData "vrops.remoteNodesGroup01vcenter.password" $strDataFile
            } else {
                # Password exists in the XML so we'll try to use it here
                $strVCRG01Input = $strVCRG01Password | ConvertTo-SecureString -Key $byteArrayKey
            } # end if
            # Creating a credential object to connect to RG01 vCenter
            $objCredsVCRG01 = New-Object System.Management.Automation.PSCredential($strUsernameVCRG01, $strVCRG01Input)
            # Connecting to RG01 vCenter
            $objvCenterRG01 = fnConnectvCenter $strHostnameVCRG01 $objCredsVCRG01
            # Adding the RG01 VM's to the array
            $arrAllRG01Nodes = $arrDataNodesRG01 | ForEach-Object {
                New-Object -TypeName PSObject -Property @{hostname = $_ ; vCenter = $strHostnameVCRG01; role = "dNodeRG01"}
            } # end ForEach-Object
            $arrAllVMs += $arrAllRG01Nodes
        } # end if
        # Getting any Data Nodes for Remote Group 02
        $arrDataNodesRG02 = $objRawData.vrops.remoteNodesGroup02.rNode.hostname | Where Length -ne 0
        # Getting the Remote Group 02 vCenter details if any Data Nodes were specified in Remote Group 02
        if ($arrDataNodesRG02.Count -gt 1){
            # Getting the vCenter hostname for RG02
            $strHostnameVCRG02 = $objRawData.vrops.remoteNodesGroup02vcenter.hostname
            if (!$strHostnameVCRG02) { $msg = "ERROR - XML - Remote Group 02 Data Nodes specified with no vCenter hostname"; fnLogData $msg $logfile; throw $msg }
            # Getting the vCenter username for RG02
            $strUsernameVCRG02 = $objRawData.vrops.remoteNodesGroup02vcenter.username
            if (!$strUsernameVCRG02) { $msg = "ERROR - XML - Remote Group 02 Data Nodes specified with no vCenter username"; fnLogData $msg $logfile; throw $msg }
            $strVCRG02Password = $objRawData.vrops.remoteNodesGroup02vcenter.password
            # If there's no password we'll set and save it here using the encryption key we already set in $byteArrayKey
            if (!$strVCRG02Password){
                $strVCRG02Input = fnGetAndStorePassword $strUsernameVCRG02 $strHostnameVCRG02 $byteArrayKey $objRawData "vrops.remoteNodesGroup02vcenter.password" $strDataFile
            } else {
                # Password exists in XML so we'll try to use it here
                $strVCRG02Input = $strVCRG02Password | ConvertTo-SecureString -Key $byteArrayKey
            } # end if
            # Creating a credential object to connect to RG01 vCenter
            $objCredsVCRG02 = New-Object System.Management.Automation.PSCredential($strUsernameVCRG02, $strVCRG02Input)
            # Connecting to RG02 vCenter
            $objvCenterRG02 = fnConnectvCenter $strHostnameVCRG02 $objCredsVCRG02
            # Adding the RG02 VM's to the array
            $arrAllRG02Nodes = $arrDataNodesRG02 | ForEach-Object {
                New-Object -TypeName PSObject -Property @{hostname = $_ ; vCenter = $strHostnameVCRG02; role = "dNodeRG02"}
            } # end ForEach-Object
            $arrAllVMs += $arrAllRG02Nodes
        } # end if
    } # end if ($strRequestedClusterOp -match "All_")

    ###################################################################
    # Verifying VM's in Xml exist in their respective vCenter Servers #
    ###################################################################

    # First we'll make sure we can find the VM's on the specified vCenter
    foreach ($itemVM in $arrAllVMs){
        try {
            # We'll try to find the VM by dns name and the vSphere name
            fnLogData "INFO - Locating: $($itemVM.hostname)" $logfile
            $objVM = Get-VM -Name $itemVM.hostname -Server $itemVM.vCenter
            if (!$objVM){
                $objVM = Get-View -ViewType VirtualMachine -Filter @{"Guest.Hostname" = $itemVM.hostname}
            } # end if
            $itemVM | Add-Member -MemberType NoteProperty -Name vCenterVm -Value $objVM
            if ($objVM){
                fnLogData "INFO - Successfully located: $($itemVM.hostname) on vCenter: $($itemVM.vCenter)" $logfile
            } else {
                $msg = "ERROR - $($itemVM.hostname) does not exist on vCenter: $($itemVM.vCenter). Please check the XML file."
                fnLogData $msg $logfile
                throw $msg
            } # end if
        } catch {
            $msg = "ERROR - $($itemVM.hostname) does not exist on vCenter: $($itemVM.vCenter). Please check the XML file."
            fnLogData $msg $logfile
            throw $msg
        } # end try/catch
    } # end foreach

    #######################
    # Shutdown Operations #
    #######################

    # Taking down Data Nodes first
    $arrDNodes = $arrAllVMs | Where role -match "dNode"
    if ($arrDNodes){
        foreach ($objdNode in $arrDNodes){
            # Shutting down each Data Node
            $strShutdownResult = fnShutdownVM $objdNode.vCenterVm $objvCenterMain 1
            fnLogData $strShutdownResult $logfile
        } # end foreach
    } # end if

    # Taking down Replica Node
    $objReplicaNode = $arrAllVMs | Where role -eq "replica" | Select -First 1
    if ($objReplicaNode){
        $strShutdownResult = fnShutdownVM $objReplicaNode.vCenterVm $objvCenterMain 1
    } else {
        fnLogData "INFO - No Replica Node specified" $logfile
    } # end if

    # Taking down Master Node
    $objMasterNode = $arrAllVMs | Where role -eq "master" | Select -First 1 
    $strShutdownResult = fnShutdownVM $objMasterNode.vCenterVm $objvCenterMain 1

    # If this is a Shutdown Operation we'll end the script here
    if ($strRequestedClusterOp -match "Shutdown_"){
        fnLogData "INFO - Script ending. Requested Operation: $strRequestedClusterOp" $logfile
        fnLogData "END - Cluster taken Offline and all Nodes shutdown" $logfile
        return
    } # end if

    #########################
    # VM Startup Operations #
    #########################
    
    $blStartupError = $False
    # Bring back the Master Node first
    $objMasterNode.vCenterVm = Get-VM -Name $objMasterNode.hostname
    $blMasterStartup = fnStartupvROpsVM $objMasterNode.vCenterVm $objvCenterMain $objvROPsCreds $strvROpsMasterName 1
    if ($blMasterStartup){
        fnLogData "INFO - Master Node: $($objMasterNode.hostname) brought up successfully to vROps OFFLINE cluster state" $logfile
    } else {
        fnLogData "ERROR - There was a problem bringing the Master Node: $($objMasterNode.hostname) online" $logfile
        $blStartupError = $True
    } # end if

    # Bring back the Replica Node
    if ($objReplicaNode){
        $objReplicaNode.vCenterVm = Get-VM -Name $objReplicaNode.hostname
        $blReplicaStartup = fnStartupvROpsVM $objReplicaNode.vCenterVm $objvCenterMain $objvROPsCreds $strvROpsMasterName 1
    } # end if
    if ($blReplicaStartup){
        fnLogData "INFO - Replica Node: $($objReplicaNode.hostname) brought up successfully to vROps OFFLINE cluster state" $logfile
    } else {
        fnLogData "ERROR - There was a problem bringing the Replica Node: $($objReplicaNode.hostname) online" $logfile
        $blStartupError = $True
    } # end if

    # Bring back the Data Nodes
    if ($arrDNodes){
        foreach ($objdNode in $arrDNodes){
            $objDNode.vCenterVm = Get-VM -Name $objdNode.hostname
            $blDataNodeStartup = fnStartupvROpsVM $objdNode.vCenterVm $objvCenterMain $objvROPsCreds $strvROpsMasterName 1
            if ($blDataNodeStartup){
                fnLogData "INFO - Data Node: $($objdNode.hostname) brought up successfully to vROps OFFLINE cluster state" $logfile
            } else {
                fnLogData "ERROR - There was a problem bringing the Data Node: $($objdNode.hostname) online" $logfile
                $blStartupError = $True
            } # end if
        } # end foreach
    } # end if

    ##############################
    # Cluster Startup Operations #
    ##############################

    # If the requested operation leaves the Cluster Offline we'll end the script here
    if ($strRequestedClusterOp -eq "Reboot_Main_Nodes_Leave_Cluster_Offline"){
        fnLogData "INFO - Script ending. Requested Operation: $strRequestedClusterOp" $logfile
        fnLogData "INFO - vROPs Cluster taken Offline. Main Nodes restarted and vROPs Cluster left Offline" $logfile
        fnLogData "END - Script finished successfully at $(Get-Date)" $logfile
        return
    } elseif ($strRequestedClusterOp -eq "Reboot_All_Nodes_Leave_Cluster_Offline") {
        fnLogData "INFO - Script ending. Requested Operation: $strRequestedClusterOp" $logfile
        fnLogData "INFO - vROPs Cluster Taken Offline. All Nodes restarted and vROPs Cluster left Offline" $logfile
        fnLogData "END - Script finished successfully at $(Get-Date)" $logfile
        return
    } # end if

    # We can close our vSphere connection now as cluster operations are via REST calls only
    fnDisconnectvCenter
    
    # If we reach this section we'll bring the Cluster back Online and end the script
    if (!$blStartupError){
        # We'll wait 30s first for the dust to settle before we try to bring the Cluster online again
        fnLogData "INFO - Waiting 30 seconds before attempting Cluster Online operation" $logfile
        Start-Sleep -Seconds 30
        $strFinalClusterState = $Null
        $strFinalClusterState = fnClusterOps $strHostnameMaster "ONLINE" $objvROPsCreds $Null
        fnLogData "INFO - Script ending. Request Operation: $strRequestedClusterOp" $logfile
        if ($strRequestedClusterOp -eq "Reboot_Main_Nodes_Bring_Cluster_Online"){
            fnLogData "INFO - vROPs Cluster Taken Offline. All Main Nodes restarted and vROPs Cluster brought Online" $logfile
        } elseif ($strRequestedClusterOp -eq "Reboot_All_Nodes_Bring_Cluster_Online"){
            fnLogData "INFO - vROPs Cluster Taken Offline. All Nodes restarted and vROPs Cluster brought Online" $logfile
        } # end if
        fnLogData "INFO - vROPs Cluster is in State: $($strFinalClusterState.cluster_online_state_snapshot)" $logfile
        fnLogData "END - Script finished successfully at $(Get-Date)" $logfile
    } else {
        fnLogData "ERROR - vROps cluster left in offline state due to problems bringing nodes online" $logfile
        fnLogData "END - Script failed at $(Get-Date)" $logfile
    } # end if