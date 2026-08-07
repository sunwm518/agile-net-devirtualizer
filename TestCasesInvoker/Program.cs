using System;
using System.Globalization;
using System.IO;
using System.Reflection;

namespace TestCasesInvoker
{
    internal static class Program
    {
        private static string targetDirectory = string.Empty;

        public static int Main(string[] args)
        {
            if (args.Length < 1 || args.Length > 4)
            {
                Console.Error.WriteLine(
                    "Usage: TestCasesInvoker.exe <TestCases.exe> [--agile66-profile] "
                    + "[--controlflow] [--advanced-controlflow]");
                return 2;
            }

            bool agile66Profile = false;
            bool includeControlFlow = false;
            bool includeAdvancedControlFlow = false;
            for (int i = 1; i < args.Length; i++)
            {
                if (string.Equals(args[i], "--agile66-profile", StringComparison.Ordinal))
                    agile66Profile = true;
                else if (string.Equals(args[i], "--controlflow", StringComparison.Ordinal))
                    includeControlFlow = true;
                else if (string.Equals(args[i], "--advanced-controlflow", StringComparison.Ordinal))
                {
                    includeControlFlow = true;
                    includeAdvancedControlFlow = true;
                }
                else
                {
                    Console.Error.WriteLine("Unknown option: " + args[i]);
                    return 2;
                }
            }

            string targetPath = Path.GetFullPath(args[0]);
            if (!File.Exists(targetPath))
            {
                Console.Error.WriteLine("Target assembly does not exist: " + targetPath);
                return 2;
            }

            targetDirectory = Path.GetDirectoryName(targetPath);
            AppDomain.CurrentDomain.AssemblyResolve += ResolveTargetDependency;

            try
            {
                Assembly assembly = Assembly.LoadFrom(targetPath);
                Type patterns = assembly.GetType("TestCases.TestPatterns", true);
                int failures = 0;

                failures += Check(patterns, "Compare.True", "CompareNumericPaths", true,
                    3, 8, 2.5, 4.0, (byte)1);
                failures += Check(patterns, "Compare.IntegerEqual", "CompareNumericPaths", false,
                    8, 8, 2.5, 4.0, (byte)1);
                failures += Check(patterns, "Compare.IntegerReversed", "CompareNumericPaths", false,
                    9, 3, 2.5, 4.0, (byte)1);
                failures += Check(patterns, "Compare.FloatEqual", "CompareNumericPaths", false,
                    3, 8, 4.0, 4.0, (byte)1);
                failures += Check(patterns, "Compare.FloatReversed", "CompareNumericPaths", false,
                    3, 8, 5.0, 4.0, (byte)1);
                failures += Check(patterns, "Compare.MarkerZero", "CompareNumericPaths", false,
                    3, 8, 2.5, 4.0, (byte)0);
                failures += Check(patterns, "Compare.Negative", "CompareNumericPaths", true,
                    -8, -3, -4.5, -1.0, byte.MaxValue);
                // Agile.NET 6.6 orders NaN through its comparison helper and returns true here,
                // unlike the original CLR unordered comparison. Keep that protection drift explicit;
                // the devirtualized result is still required to recover the source/CLR result.
                failures += Check(patterns, "Compare.NaN", "CompareNumericPaths", agile66Profile,
                    3, 8, double.NaN, 4.0, (byte)1);
                failures += Check(patterns, "Compare.Infinity", "CompareNumericPaths", true,
                    3, 8, 1.0, double.PositiveInfinity, (byte)1);

                failures += Check(patterns, "Null.Valid", "CheckReferenceNulls", true,
                    "ready", null);
                failures += Check(patterns, "Null.TextNull", "CheckReferenceNulls", false,
                    null, null);
                failures += Check(patterns, "Null.OptionalSet", "CheckReferenceNulls", false,
                    "ready", new object());
                failures += Check(patterns, "Null.EmptyText", "CheckReferenceNulls", true,
                    string.Empty, null);

                failures += Check(patterns, "Arithmetic.Standard", "ComputeI4Arithmetic", 58,
                    (byte)23, 7);
                failures += Check(patterns, "Arithmetic.ExactDivision", "ComputeI4Arithmetic", 42,
                    (byte)14, 7);
                failures += Check(patterns, "Arithmetic.ZeroValue", "ComputeI4Arithmetic", 14,
                    (byte)0, 7);
                failures += Check(patterns, "Arithmetic.ByteMax", "ComputeI4Arithmetic", 527,
                    byte.MaxValue, 16);
                failures += Check(patterns, "Arithmetic.ZeroDivisor", "ComputeI4Arithmetic", -1,
                    (byte)23, 0);
                failures += Check(patterns, "Arithmetic.NegativeDivisor", "ComputeI4Arithmetic", 30,
                    (byte)23, -7);
                failures += Check(patterns, "Arithmetic.Overflow", "ComputeI4Arithmetic", 253,
                    byte.MaxValue, int.MaxValue);

                if (includeControlFlow)
                {
                    failures += CheckWithState(patterns, "ControlFlow.Finally.Case0",
                        "SwitchWithFinally", "LastSwitchFinallyState", 11, 110, 0);
                    failures += CheckWithState(patterns, "ControlFlow.Finally.Case1",
                        "SwitchWithFinally", "LastSwitchFinallyState", 21, 120, 1);
                    failures += CheckWithState(patterns, "ControlFlow.Finally.EarlyReturn",
                        "SwitchWithFinally", "LastSwitchFinallyState", 30, 130, 2);
                    failures += CheckWithState(patterns, "ControlFlow.Finally.GotoCase",
                        "SwitchWithFinally", "LastSwitchFinallyState", 11, 110, 3);
                    failures += CheckWithState(patterns, "ControlFlow.Finally.Default",
                        "SwitchWithFinally", "LastSwitchFinallyState", -4, 95, 99);

                    failures += CheckWithState(patterns, "ControlFlow.CatchFinally.Normal",
                        "SwitchWithCatchFinally", "LastCatchFinallyState", 6, 11, 0);
                    failures += CheckWithState(patterns, "ControlFlow.CatchFinally.Caught",
                        "SwitchWithCatchFinally", "LastCatchFinallyState", 51, 101, 1);
                    failures += CheckWithState(patterns, "ControlFlow.CatchFinally.EarlyReturn",
                        "SwitchWithCatchFinally", "LastCatchFinallyState", 25, 51, 2);
                    failures += CheckWithState(patterns, "ControlFlow.CatchFinally.Default",
                        "SwitchWithCatchFinally", "LastCatchFinallyState", -4, -9, 99);
                }

                if (includeAdvancedControlFlow)
                {
                    failures += CheckWithState(patterns, "Advanced.Loop.Zero",
                        "LoopContinueBreakFinally", "LastLoopFinallyState", 0, 0, 0);
                    failures += CheckWithState(patterns, "Advanced.Loop.One",
                        "LoopContinueBreakFinally", "LastLoopFinallyState", 1000, 0, 1);
                    failures += CheckWithState(patterns, "Advanced.Loop.Continue",
                        "LoopContinueBreakFinally", "LastLoopFinallyState", 2010, 12, 2);
                    failures += CheckWithState(patterns, "Advanced.Loop.Break",
                        "LoopContinueBreakFinally", "LastLoopFinallyState", 3112, 12081, 4);
                    failures += CheckWithState(patterns, "Advanced.Loop.Negative",
                        "LoopContinueBreakFinally", "LastLoopFinallyState", 0, 0, -2);

                    failures += CheckWithState(patterns, "Advanced.Merge.ZeroNormal",
                        "MergeBackedgeStates", "LastMergeTrace", -16, 12222, 0, false);
                    failures += CheckWithState(patterns, "Advanced.Merge.ZeroAlternate",
                        "MergeBackedgeStates", "LastMergeTrace", -12, 22222, 0, true);
                    failures += CheckWithState(patterns, "Advanced.Merge.FiveNormal",
                        "MergeBackedgeStates", "LastMergeTrace", -12, 22222, 5, false);
                    failures += CheckWithState(patterns, "Advanced.Merge.FiveAlternate",
                        "MergeBackedgeStates", "LastMergeTrace", 4, 12222, 5, true);

                    failures += CheckWithDetailedState(patterns, "Advanced.Filter.Caught",
                        50, 1236, string.Empty, 0);
                    failures += CheckWithDetailedState(patterns, "Advanced.Filter.Rethrow",
                        107, 123456, "System.ArgumentException:rethrow", 1);
                    failures += CheckWithDetailedState(patterns, "Advanced.Filter.Bypass",
                        106, 1256, "System.ArgumentException:bypass", 2);
                    failures += CheckWithDetailedState(patterns, "Advanced.Filter.Normal",
                        13, 16, string.Empty, 3);
                    failures += CheckThrowsWithState(patterns, "Advanced.Filter.Escape",
                        typeof(InvalidOperationException), "escape", 126, 4);

                    failures += CheckRethrowWithState(patterns, "Advanced.Rethrow.Normal",
                        10, 14, string.Empty, 0);
                    failures += CheckRethrowWithState(patterns, "Advanced.Rethrow.Caught",
                        105, 1234, "System.ArgumentException:inner", 1);
                    failures += CheckRethrowThrowsWithState(patterns, "Advanced.Rethrow.Escape",
                        typeof(InvalidOperationException), "escape", 14, 2);
                }

                return failures == 0 ? 0 : 1;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.ToString());
                return 2;
            }
        }

        private static int Check(Type patterns, string caseName, string methodName,
            object expected, params object[] arguments)
        {
            MethodInfo method = patterns.GetMethod(methodName, BindingFlags.Public | BindingFlags.Static);
            if (method == null)
                throw new MissingMethodException(patterns.FullName, methodName);

            object actual;
            try
            {
                actual = method.Invoke(null, arguments);
            }
            catch (TargetInvocationException ex)
            {
                throw ex.InnerException ?? ex;
            }

            string actualText = Convert.ToString(actual, CultureInfo.InvariantCulture);
            Console.WriteLine(caseName + "=" + actualText);
            if (object.Equals(actual, expected))
                return 0;

            Console.Error.WriteLine(caseName + " expected "
                + Convert.ToString(expected, CultureInfo.InvariantCulture) + " but got " + actualText);
            return 1;
        }

        private static int CheckWithState(Type patterns, string caseName, string methodName,
            string stateFieldName, int expectedResult, int expectedState, params object[] arguments)
        {
            MethodInfo method = patterns.GetMethod(methodName, BindingFlags.Public | BindingFlags.Static);
            if (method == null)
                throw new MissingMethodException(patterns.FullName, methodName);
            FieldInfo stateField = patterns.GetField(stateFieldName,
                BindingFlags.Public | BindingFlags.Static);
            if (stateField == null)
                throw new MissingFieldException(patterns.FullName, stateFieldName);

            object actualResult;
            try
            {
                actualResult = method.Invoke(null, arguments);
            }
            catch (TargetInvocationException ex)
            {
                throw ex.InnerException ?? ex;
            }

            object actualState = stateField.GetValue(null);
            string actualText = Convert.ToString(actualResult, CultureInfo.InvariantCulture)
                + "|" + Convert.ToString(actualState, CultureInfo.InvariantCulture);
            Console.WriteLine(caseName + "=" + actualText);
            if (object.Equals(actualResult, expectedResult) && object.Equals(actualState, expectedState))
                return 0;

            Console.Error.WriteLine(caseName + " expected " + expectedResult + "|" + expectedState
                + " but got " + actualText);
            return 1;
        }

        private static int CheckWithDetailedState(Type patterns, string caseName, int expectedResult,
            int expectedTrace, string expectedException, int mode)
        {
            MethodInfo method = patterns.GetMethod("FilterAndRethrow",
                BindingFlags.Public | BindingFlags.Static);
            FieldInfo traceField = patterns.GetField("LastFilterTrace",
                BindingFlags.Public | BindingFlags.Static);
            FieldInfo exceptionField = patterns.GetField("LastFilterException",
                BindingFlags.Public | BindingFlags.Static);
            if (method == null || traceField == null || exceptionField == null)
                throw new MissingMemberException(patterns.FullName, "FilterAndRethrow state");

            object actualResult = method.Invoke(null, new object[] { mode });
            object actualTrace = traceField.GetValue(null);
            object actualException = exceptionField.GetValue(null);
            string actualText = actualResult + "|" + actualTrace + "|" + actualException;
            Console.WriteLine(caseName + "=" + actualText);
            if (object.Equals(actualResult, expectedResult)
                && object.Equals(actualTrace, expectedTrace)
                && object.Equals(actualException, expectedException))
                return 0;

            Console.Error.WriteLine(caseName + " expected " + expectedResult + "|" + expectedTrace
                + "|" + expectedException + " but got " + actualText);
            return 1;
        }

        private static int CheckThrowsWithState(Type patterns, string caseName, Type exceptionType,
            string exceptionMessage, int expectedTrace, int mode)
        {
            MethodInfo method = patterns.GetMethod("FilterAndRethrow",
                BindingFlags.Public | BindingFlags.Static);
            FieldInfo traceField = patterns.GetField("LastFilterTrace",
                BindingFlags.Public | BindingFlags.Static);
            if (method == null || traceField == null)
                throw new MissingMemberException(patterns.FullName, "FilterAndRethrow state");

            Exception actualException = null;
            try
            {
                method.Invoke(null, new object[] { mode });
            }
            catch (TargetInvocationException ex)
            {
                actualException = ex.InnerException;
            }

            object actualTrace = traceField.GetValue(null);
            string actualText = (actualException == null ? "<none>" : actualException.GetType().FullName
                + ":" + actualException.Message) + "|" + actualTrace;
            Console.WriteLine(caseName + "=" + actualText);
            if (actualException != null && actualException.GetType() == exceptionType
                && actualException.Message == exceptionMessage && object.Equals(actualTrace, expectedTrace))
                return 0;

            Console.Error.WriteLine(caseName + " expected " + exceptionType.FullName + ":"
                + exceptionMessage + "|" + expectedTrace + " but got " + actualText);
            return 1;
        }

        private static int CheckRethrowWithState(Type patterns, string caseName, int expectedResult,
            int expectedTrace, string expectedException, int mode)
        {
            MethodInfo method = patterns.GetMethod("RethrowWithoutFilter",
                BindingFlags.Public | BindingFlags.Static);
            FieldInfo traceField = patterns.GetField("LastRethrowTrace",
                BindingFlags.Public | BindingFlags.Static);
            FieldInfo exceptionField = patterns.GetField("LastRethrowException",
                BindingFlags.Public | BindingFlags.Static);
            if (method == null || traceField == null || exceptionField == null)
                throw new MissingMemberException(patterns.FullName, "RethrowWithoutFilter state");

            object actualResult = method.Invoke(null, new object[] { mode });
            object actualTrace = traceField.GetValue(null);
            object actualException = exceptionField.GetValue(null);
            string actualText = actualResult + "|" + actualTrace + "|" + actualException;
            Console.WriteLine(caseName + "=" + actualText);
            if (object.Equals(actualResult, expectedResult)
                && object.Equals(actualTrace, expectedTrace)
                && object.Equals(actualException, expectedException))
                return 0;

            Console.Error.WriteLine(caseName + " expected " + expectedResult + "|" + expectedTrace
                + "|" + expectedException + " but got " + actualText);
            return 1;
        }

        private static int CheckRethrowThrowsWithState(Type patterns, string caseName,
            Type exceptionType, string exceptionMessage, int expectedTrace, int mode)
        {
            MethodInfo method = patterns.GetMethod("RethrowWithoutFilter",
                BindingFlags.Public | BindingFlags.Static);
            FieldInfo traceField = patterns.GetField("LastRethrowTrace",
                BindingFlags.Public | BindingFlags.Static);
            if (method == null || traceField == null)
                throw new MissingMemberException(patterns.FullName, "RethrowWithoutFilter state");

            Exception actualException = null;
            try
            {
                method.Invoke(null, new object[] { mode });
            }
            catch (TargetInvocationException ex)
            {
                actualException = ex.InnerException;
            }

            object actualTrace = traceField.GetValue(null);
            string actualText = (actualException == null ? "<none>" : actualException.GetType().FullName
                + ":" + actualException.Message) + "|" + actualTrace;
            Console.WriteLine(caseName + "=" + actualText);
            if (actualException != null && actualException.GetType() == exceptionType
                && actualException.Message == exceptionMessage && object.Equals(actualTrace, expectedTrace))
                return 0;

            Console.Error.WriteLine(caseName + " expected " + exceptionType.FullName + ":"
                + exceptionMessage + "|" + expectedTrace + " but got " + actualText);
            return 1;
        }

        private static Assembly ResolveTargetDependency(object sender, ResolveEventArgs args)
        {
            string simpleName = new AssemblyName(args.Name).Name + ".dll";
            string candidate = Path.Combine(targetDirectory, simpleName);
            return File.Exists(candidate) ? Assembly.LoadFrom(candidate) : null;
        }
    }
}
