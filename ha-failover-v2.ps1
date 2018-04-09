Write-Output -InputObject "PowerShell Timer trigger function executed at:$(Get-Date)"

<#     
    Palo Alto Networks Traps PA-Azure Failover Example
    This script is an example for monitoring PA firewall status and performing
    fail-over and/or fail-back.
    This script is used as part of an Azure Function App called by a Timer Trigger event.  
    
    To setup, the following items must be configured:
    - Pre-create Azure ResourceGroups, virtual firewalls, Virtual Networks and Subnets
    - Create Azure Timer Function 
    - Set Function App Settings with credentials
      SP_PASSWORD, SP_USERNAME, TENANTID, SUBSCRIPTIONID, AZURECLOUD must be added
      AZURECLOUD = "AzureCloud" or "AzureUSGovernment"
    - Set Firewall VM names and Resource Group in Function App Settings
      FW1NAME, FW2NAME, FWMONITOR, FW1FQDN, FW1PORT, FW2FQDN, FW2PORT, FWRGNAME, FWTRIES, FWDELAY, FWUDRTAG must be added
      FWMONITOR = "VMStatus" or "TCPPort" - If using "TCPPort", then also set FW1FQDN, FW2FQDN, FW1PORT and FW2PORT values
    - Set Timer Schedule where positions represent: Seconds - Minutes - Hours - Day - Month - DayofWeek
      Example:  "*/30 * * * * *" to run on multiples of 30 seconds
      Example:  "0 */5 * * * *" to run on multiples of 5 minutes on the 0-second mark
#>

#**************************************************************
#          Set firewall monitoring variables here
#**************************************************************

$vmFW1Name = $env:FW1NAME              # Set the Name of the primary firewall
$vmFW2Name = $env:FW2NAME              # Set the Name of the secondaryfirewall
$Fw1RGName = $env:FWRGNAME             # Set the ResourceGroup that contains Fw1
$Fw2RGName = $env:FWRGNAME             # Set the ResourceGroup that contains Fw2

<#
    Set the parameter $monitor to  "VMStatus" if the current state 
    of the firewall is monitored.  The firewall will be marked as 
    down if we do not receive a "running response to the api call"
    Set the parameter $monitor to "TCPPort"  if the forwarding state
    of the firewall is to be tested by connecting through the firewall 
    to remote sites
#>

$monitor = $env:FWMONITOR              # "VMStatus" or "TCPPort" are valid values

#**************************************************************
#    The parameters below are required if using "TCPPort" mode
#**************************************************************

$tcpFW1Server = $env:FW1FQDN   # Hostname of the site to be monitored if using "TCPPort"
$tcpFW1Port = $env:FW1PORT
$tcpFW2Server = $env:FW2FQDN
$tcpFW2Port = $env:FW2PORT

#**************************************************************
#    Set the failover and failback behaviour for the firewalls
#**************************************************************

$FailOver = $True          # Trigger to enable fail-over to FW2 if FW1 drops when active
$FailBack = $True          # Trigger to enable fail-back to FW1 if FW2 drops when active

# FW is deemed down if ALL intTries fail with intSeconds between tries

$intTries = $env:FWTRIES          # Number of Firewall tests to try 
$intSleep = $env:FWDELAY          # Delay in seconds between tries





<# Set the subscription that contains the ResourceGroups for the firewall
Optional - Set the default SubscriptionID that contains the resource groups defined above.
If a value is set then the script will also search for other subscriptionIDs associcated with 
the account that the function runs with.   If no value is set then the script will assume only 
one subscription is linked to the account. 

$defaultsubscriptionID = ''

#>

$defaultsubscriptionID = '' 



<#
    Set the failover method.  Secondary-int will move the secondary ip 
    from the primary firewall to the secondary which does not require any 
    modification to routing tables so will result in faster failover times 
    when multiple route tables are required. 
    
    Options for $failoverMode are 'secondary-int' and 'route-table'
    
   
    $Script:IpconfigName is the IPconfiguration Name for the secondary IP address
#>
$failoverMode =  $env:FAILMODE # Use secondary-int if moving a secondary IP address"
#$failoverMode = 'route-table'
$Script:IpconfigName = $env:IPCONFIGNAME

<#
    TCPPort monitoring is most applicable when the azure function is deployed within
    the VNET (App Service Plan) as the azure source IP resides inside the VNET.  If deploying
    using a consumption model use VMStatus instead
#>

$tcpFW1Server = 'www.microsoft.com'   # Hostname of the site to be monitored if using "TCPPort"
$tcpFW1Port = 80
$tcpFW2Server = 'www.novell.com'
$tcpFW2Port = 443

#**************************************************************
#    Set the failover and failback behaviour for the firewalls
#**************************************************************
$FailOver = $True          # Trigger to enable fail-over to FW2 if FW1 drops when active
$FailBack = $True          # Trigger to enable fail-back to FW1 if FW2 drops when active
# FW is deemed down if ALL intTries fail with intSeconds between tries
$intTries = 1          # Number of Firewall tests to try 
$intSleep = 0          # Delay in seconds between tries

#**************************************************************
#                Functions Code Block
#**************************************************************

<#
    Test-VM-Status will return $null if the firewall status is 
    determined to be "Running".  For any other state received the 
    script will return $true and the firwall will be determined to 
    be "Down"
#>

Function Test-VM-Status ($VM, $FwResourceGroup) 
{
  $VMDetail = Get-AzureRmVM -ResourceGroupName $FwResourceGroup -Name $VM -Status
  foreach ($VMStatus in $VMDetail.Statuses)
  { 
    $Status = $VMStatus.code
      
    if($Status.CompareTo('PowerState/running') -eq 0)
    {
      Return $False
    }
  }
  Return $True  
}

# Test TCP Port responds
Function Test-TCP-Port ($server, $port)
{
  $tcpclient = New-Object -TypeName system.Net.Sockets.TcpClient
  $iar = $tcpclient.BeginConnect($server, $port, $null, $null)
  $wait = $iar.AsyncWaitHandle.WaitOne(1000, $False)
  return $wait
}

<#
    The firewall will find all route tables within the resource group.
    The route tables are stored in an array.
    Iterate of the routing tables looking to entries that match any of the 
    primary firewalls interfaces ($Script:PrimaryInts).  If a match is found
    Substitute the current IP for the secondary firewall IP ($Script:SecondaryInts)
#>

function Failover {
if ($failoverMode -eq 'route-table')
  {
  

  foreach ($subscriptionID in $Script:listofsubscriptionIDs){
  Set-AzureRmContext -SubscriptionId $subscriptionID
  $tagValue = $env:FWUDRTAG
  $res = Find-AzureRmResource -TagName pan_ha_udr -TagValue $tagValue

  foreach ($rtable in $res)
    {
    $table = Get-AzureRmRouteTable -ResourceGroupName $rtable.ResourceGroupName -Name $rtable.name
    foreach ($routeName in $table.Routes){
      Write-Output -InputObject "Updating route table  "
      Write-Output -InputObject $rtable.name

      for ($i = 0; $i -lt $PrimaryInts.count; $i++)
      {
        if($routeName.NextHopIpAddress -eq $SecondaryInts[$i])
        {
          Write-Output -InputObject 'Already on Secondary FW' 
          
        }
        elseif($routeName.NextHopIpAddress -eq $PrimaryInts[$i])
        {
          Set-AzureRmRouteConfig -Name $routeName.Name  -NextHopType VirtualAppliance -RouteTable $table -AddressPrefix $routeName.AddressPrefix -NextHopIpAddress $SecondaryInts[$i] 
        }
      }
    }
  

    $UpdateTable = [scriptblock]{param($table) Set-AzureRmRouteTable -RouteTable $table}

    &$UpdateTable $table 

  }
}
}
elseif ($failoverMode -eq 'secondary-int'){
  moveToFW2
  }
else {
  Write-Output -InputObject "No failovermode specified in parameter failoverMode" 
  }
}


<#
    The firewall will find all route tables within the resource group.
    The route tables are stored in an array.
    Iterate of the routing tables looking to entries that match any of the 
    secondary firewall interfaces ($Script:SecondaryInts).  If a match is found
    Substitute the current IP for the secondary firewall IP ($Script:PrimaryInts)
#>
function Failback {
if ($failoverMode -eq 'route-table')
{
  foreach ($subscriptionID in $Script:listofsubscriptionIDs){
  Set-AzureRmContext -SubscriptionId $subscriptionID
  $tagValue = $env:FWUDRTAG
  $res = Find-AzureRmResource -TagName pan_ha_udr -TagValue $tagValue

  foreach ($rtable in $res)
  {
    $table = Get-AzureRmRouteTable -ResourceGroupName $rtable.ResourceGroupName -Name $rtable.name


    foreach ($routeName in $table.Routes)
    {
      Write-Output -InputObject "Updating route table  "
      Write-Output -InputObject $rtable.name
      for ($i = 0; $i -lt $PrimaryInts.count; $i++)
      {
        if($routeName.NextHopIpAddress -eq $PrimaryInts[$i])
        {
          Write-Output -InputObject 'Already on Primary FW' 
        
        }
        elseif($routeName.NextHopIpAddress -eq $SecondaryInts[$i])
        {
          Set-AzureRmRouteConfig -Name $routeName.Name  -NextHopType VirtualAppliance -RouteTable $table -AddressPrefix $routeName.AddressPrefix -NextHopIpAddress $PrimaryInts[$i]
        }  
      }  
    }  

    $UpdateTable = [scriptblock]{param($table) Set-AzureRmRouteTable -RouteTable $table}

    &$UpdateTable $table  
  }
}
}
elseif ($failoverMode -eq 'secondary-int'){
  moveToFW1
  }
else {
  Write-Output -InputObject "No failovermode specified in parameter failoverMode" 
  }
}
<#
     FW1secondaryIpconfig and FW1Nics both are arrays that we index through when moving the secondary IP address
#>
function moveToFW2 {
    for ($i = 0; $i -lt $Fw1Nics.count; $i++)
        {
        if ($Script:FW1secondaryIpconfig[$i] -ne $Null)
            {
            Remove-AzureRmNetworkInterfaceIpConfig -Name $Script:IpconfigName -NetworkInterface $Script:Fw1Nics[$i]
            Set-AzureRmNetworkInterface  -NetworkInterface $Script:Fw1Nics[$i]

            Add-AzureRmNetworkInterfaceIpConfig -Name $Script:ipconfigname -NetworkInterface $Script:Fw2Nics[$i] -PrivateIpAddress $Script:FW1secondaryIpconfig[$i] -SubnetId $Script:Fw2Nics[$i].IpConfigurations[0].Subnet.Id
            Set-AzureRmNetworkInterface  -NetworkInterface $Script:Fw2Nics[$i]
            }
        }
}
<#
     FW1secondaryIpconfig and FW1Nics both are arrays that we index through when moving the secondary IP address
#>
function moveToFW1 {
    for ($i = 0; $i -lt $Fw2Nics.count; $i++)
        {
        if ($Script:FW2secondaryIpconfig[$i] -ne $Null)
            {
            Remove-AzureRmNetworkInterfaceIpConfig -Name $Script:IpconfigName -NetworkInterface $Script:Fw2Nics[$i]
            Set-AzureRmNetworkInterface  -NetworkInterface $Script:Fw2Nics[$i]

            Add-AzureRmNetworkInterfaceIpConfig -Name $Script:ipconfigname -NetworkInterface $Script:Fw1Nics[$i] -PrivateIpAddress $Script:FW2secondaryIpconfig[$i] -SubnetId $Script:Fw1Nics[$i].IpConfigurations[0].Subnet.Id
            Set-AzureRmNetworkInterface  -NetworkInterface $Script:Fw1Nics[$i]
            }
        }
}
<#
    Find all the secondary ip addresses associated with a firewall instance and store them in an array
#>
Function getsecondaryipconfig {
  $nics = Get-AzureRmNetworkInterface | Where-Object -Property VirtualMachine -NE -Value $null  #skip Nics with no VM
  $vms1 = Get-AzureRmVM -Name $vmFW1Name -ResourceGroupName $Fw1RGName
  $vms2 = Get-AzureRmVM -Name $vmFW2Name -ResourceGroupName $Fw2RGName
  $i=0
  foreach($nic in $nics)
  {
    <#
        For each Nic look for the NIC ID if the firewall has the NIC bound to it then store the IP 
        address in an array for later use.
    #>
    
    if (($nic.VirtualMachine.Id -EQ $vms1.id) -Or ($nic.VirtualMachine.id -EQ $vms2.id)) 
    {
      $VM = $vms | Where-Object -Property Id -EQ -Value $nic.VirtualMachine.id
      if ($VM.Name -eq $vmFW1Name)
        {
            $Script:Fw1Nics += $nic
            if ($nic.IpConfigurations.count -eq 2)
                {
                $Script:Fw1IsPrimary
                $Script:ipconfigname =$nic.IpConfigurations[1].Name
                $prv = $nic.IpConfigurations[1] | Select-Object -ExpandProperty PrivateIpAddress  
                $Script:FW1secondaryIpconfig += $prv
                }
            else {$Script:FW1secondaryIpconfig += $Null}
        
        }
      elseif ($VM.Name -eq $vmFW2Name) 
        {
            $Script:Fw2Nics += $nic
            if ($nic.IpConfigurations.count -eq 2)
                {
                $Script:Fw2IsPrimary
                $Script:ipconfigname =$nic.IpConfigurations[1].Name
                $prv = $nic.IpConfigurations[1] | Select-Object -ExpandProperty PrivateIpAddress  
                $Script:FW2secondaryIpconfig += $prv
                }
            else {$Script:FW2secondaryIpconfig += $Null}
        
        }
    }
    }
  
}
<#
    Find all the interfaces associated with a firewall instance and store them in an arry
#>
Function getfwinterfaces {
  $nics = Get-AzureRmNetworkInterface | Where-Object -Property VirtualMachine -NE -Value $null  #skip Nics with no VM
  $vms1 = Get-AzureRmVM -Name $vmFW1Name -ResourceGroupName $Fw1RGName
  $vms2 = Get-AzureRmVM -Name $vmFW2Name -ResourceGroupName $Fw2RGName
  foreach($nic in $nics)
  {
    <#
        For each Nic look for the NIC ID if the firewall has the NIC bound to it then store the IP 
        address in an array for later use.
    #>
    if (($nic.VirtualMachine.Id -EQ $vms1.id) -Or ($nic.VirtualMachine.id -EQ $vms2.id)) 
    {
      $VM = $vms | Where-Object -Property Id -EQ -Value $nic.VirtualMachine.id
      $prv = $nic.IpConfigurations[0] | Select-Object -ExpandProperty PrivateIpAddress  
      if ($VM.Name -eq $vmFW1Name)
      {
        $Script:PrimaryInts += $prv
        
      }
      elseif($VM.Name -eq $vmFW2Name)
      {
        $Script:SecondaryInts += $prv
       
      }
    }
  }
}
 
Function getallsubscriptions {
  Write-Output -InputObject "Enumerating all subscriptins ..."
  $Script:listofsubscriptionIDs = (Get-AzureRmSubscription).SubscriptionId
  Write-Output -InputObject $Script:listofsubscriptionIDs

}


    #**************************************************************
    #                      Main Code Block                            
    #**************************************************************

    # Set Service Principal Credentials and establish your Azure RM Context
    # SP_PASSWORD, SP_USERNAME, TENANTID, SUBSCRIPTIONID and AZURECLOUD are app settings
#>


$password = ConvertTo-SecureString $env:SP_PASSWORD -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential ($env:SP_USERNAME, $password)
$azureEnv = Get-AzureRmEnvironment -Name $env:AZURECLOUD
Add-AzureRmAccount -ServicePrincipal -Tenant $env:TENANTID -Credential $credential -SubscriptionId $env:SUBSCRIPTIONID -Environment $azureEnv

$context = Get-AzureRmContext
Set-AzureRmContext -Context $context

<#
Use Login-AzureRmAccount if testing from a local machine
Use $env:SP_PASSWORD and $env:SP_USERNAME if used in an Azure Function
Login-AzureRmAccount
#>

$Script:PrimaryInts = @()
$Script:SecondaryInts = @()
$Script:FW1secondaryIpconfig =@()
$Script:FW2secondaryIpconfig =@()
$Script:listofsubscriptionIDs = @()
$Script:Fw1Nics = @()
$Script:Fw2Nics = @()
$Script:ipconfigname



# Check firewall status $intTries with $intSleep between tries
$ctrFW1 = 0
$ctrFW2 = 0
$FW2Down = $True
$FW1Down = $True
$vms = Get-AzureRmVM
getallsubscriptions
if ($failoverMode -eq 'route-table')
  {
  getfwinterfaces
  }
elseif ($failoverMode -eq 'secondary-int'){
  getsecondaryipconfig
  }
else {
  Write-Output -InputObject "No failovermode specified in parameter failoverMode" 
  }
For ($ctr = 1; $ctr -le $intTries; $ctr++)
{
  # Test FW States based on VM PowerState (if specified)
  if ($monitor -eq 'VMStatus')
  {
    $FW1Down = Test-VM-Status -VM $vmFW1Name -FwResourceGroup $Fw1RGName
    $FW2Down = Test-VM-Status -VM $vmFW2Name -FwResourceGroup $Fw2RGName
  }
  # Test FW States based on TCP Port checks (if specified)
  if ($monitor -eq 'TCPPort')
  {
    $FW1Down = -not (Test-TCP-Port -server $tcpFW1Server -port $tcpFW1Port)
    $FW2Down = -not (Test-TCP-Port -server $tcpFW2Server -port $tcpFW2Port)
  }
  Write-Output -InputObject "Pass $ctr of $intTries - FW1Down is $FW1Down, FW2Down is $FW2Down"
  if ($FW1Down) 
  {
    $ctrFW1++
  }
  if ($FW2Down) 
  {
    $ctrFW2++
  }
  Write-Output -InputObject "Sleeping $intSleep seconds"
  Start-Sleep $intSleep
}

if ($ctrFW1 -eq $intTries) 
{
  $FW1Down = $True
}
if ($ctrFW2 -eq $intTries) 
{
  $FW2Down = $True
}
# Fail-over logic tree

if (($FW1Down) -and -not ($FW2Down))
{
  if ($FailOver )
  {
    Write-Output -InputObject 'FW1 Down - Failing over to FW2'
    Failover 
  }
}
elseif (-not ($FW1Down) -and ($FW2Down))
{
  if ($FailBack)
  {
    Write-Output -InputObject 'FW2 Down - Failing back to FW1'
    Failback
  }
  else 
  {
    Write-Output -InputObject 'FW2 Down - Failing back disabled'
  }
}
elseif (($FW1Down) -and ($FW2Down))
{
  #notify both FW are down
  Write-Output -InputObject 'Both FW1 and FW2 Down - Manual recovery action required'
}
else
{
  #log both FW are up
  Write-Output -InputObject 'Both FW1 and FW2 Up - No action required'
}
