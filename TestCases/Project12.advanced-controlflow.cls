<?xml version="1.0" encoding="utf-8"?>
<AgileDotNet Version="6.6.0.42">
  <AssemblyList>
    <Assembly Path="bin\Release\net48\TestCases.exe" Secure="false" Obfuscation="false" FlowObfuscation="false" MethodCallObfuscation="false" ILMerge="none" />
  </AssemblyList>
  <CodeVirtualizationRules>
    <MemberSelector Name="TestPatterns.BuildDictionary" Selector="Dictionary&lt;String, String&gt; BuildDictionary(String, String, String, String)" Owner="TestCases.TestPatterns" Type="Method" />
    <MemberSelector Name="TestPatterns.CheckArrayLengthIndex" Selector="Boolean CheckArrayLengthIndex(String)" Owner="TestCases.TestPatterns" Type="Method" />
    <MemberSelector Name="TestPatterns.GuidRoundTrip" Selector="Boolean GuidRoundTrip()" Owner="TestCases.TestPatterns" Type="Method" />
    <MemberSelector Name="TestPatterns.CompareNumericPaths" Selector="Boolean CompareNumericPaths(Int32, Int32, Double, Double, Byte)" Owner="TestCases.TestPatterns" Type="Method" />
    <MemberSelector Name="TestPatterns.CheckReferenceNulls" Selector="Boolean CheckReferenceNulls(String, Object)" Owner="TestCases.TestPatterns" Type="Method" />
    <MemberSelector Name="TestPatterns.ComputeI4Arithmetic" Selector="Int32 ComputeI4Arithmetic(Byte, Int32)" Owner="TestCases.TestPatterns" Type="Method" />
    <MemberSelector Name="TestPatterns.SwitchWithFinally" Selector="Int32 SwitchWithFinally(Int32)" Owner="TestCases.TestPatterns" Type="Method" />
    <MemberSelector Name="TestPatterns.SwitchWithCatchFinally" Selector="Int32 SwitchWithCatchFinally(Int32)" Owner="TestCases.TestPatterns" Type="Method" />
    <MemberSelector Name="TestPatterns.LoopContinueBreakFinally" Selector="Int32 LoopContinueBreakFinally(Int32)" Owner="TestCases.TestPatterns" Type="Method" />
    <MemberSelector Name="TestPatterns.MergeBackedgeStates" Selector="Int32 MergeBackedgeStates(Int32, Boolean)" Owner="TestCases.TestPatterns" Type="Method" />
    <MemberSelector Name="TestPatterns.RethrowWithoutFilter" Selector="Int32 RethrowWithoutFilter(Int32)" Owner="TestCases.TestPatterns" Type="Method" />
  </CodeVirtualizationRules>
  <Settings>
    <General OutputDirectory="bin\Release\net48\Secured-advanced-controlflow" SignatureFile="" PfxPassword="" FilePathMode="relativepath" GenerateDebugInfo="True" SdkPath="" />
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
