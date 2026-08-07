<?xml version="1.0" encoding="utf-8"?>
<AgileDotNet Version="6.6.0.42">
  <AssemblyList>
    <Assembly Path="bin\Release\net48\FaultCases.dll" Secure="false" Obfuscation="false" FlowObfuscation="false" MethodCallObfuscation="false" ILMerge="none" />
  </AssemblyList>
  <CodeVirtualizationRules>
    <MemberSelector Name="FaultPatterns.FaultFlow" Selector="Int32 FaultFlow(Int32)" Owner="FaultCases.FaultPatterns" Type="Method" />
  </CodeVirtualizationRules>
  <Settings>
    <General OutputDirectory="bin\Release\net48\Secured-fault" SignatureFile="" PfxPassword="" FilePathMode="relativepath" GenerateDebugInfo="True" SdkPath="" />
    <Obfuscation ObfuscationMapFile="ObfuscationMap" RenamingScheme="printablechars" CrossAssemblyObfuscation="false" ExcludeXamlTypes="false" ControlFlowObfuscation="basic" PredefindSymbolNamesFilePath="" RenameMethodParameters="False">
      <RenamingExclusions />
      <AssemblyLoadPaths />
    </Obfuscation>
    <Secure SecureUserStrings="false" EncryptManagedResources="false" RedistName="AgileDotNetRT" RedistName64="AgileDotNetRT64" DisableRuntimeEmbedding="False" AntiDebuggerDetection="False" SkipSmallMethods="False" />
    <Tracking ConfigureErrorReporting="false" ProductName="AgileDotNet" ProductVersion="6.6.0.42" CompanyName="SecureTeam Software Ltd." />
    <CodeVirtualization PerformCodeVirtualization="true" RedistName="AgileDotNet.VMRuntime" />
    <LicenseFeatures />
  </Settings>
  <Licensing>
    <Licenses />
  </Licensing>
</AgileDotNet>
