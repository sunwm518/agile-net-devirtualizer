using System;
using System.Collections.Generic;

namespace TestCases
{
    // Small, targeted repros with known source behavior for devirtualization gaps.
    // Build this, run AgileDotNet.exe over the built exe (virtualize the whole assembly,
    // or just the TestPatterns class/methods if the tool lets you pick), and send back
    // BOTH the original (pre-virtualization) exe and the virtualized exe + VMRuntime.dll.
    public static class TestPatterns
    {
        // --- Repro 1: computed-index array access (sample2's blocker) ---
        // The classic `arr[arr.Length - 1]` shape: the compiler reads `chars` once for
        // the length computation and a SECOND time for the actual element access, with
        // arithmetic in between. This is exactly the pattern our lifter loses track of.
        public static bool CheckArrayLengthIndex(string input)
        {
            char[] chars = input.ToCharArray();
            if (chars.Length == 0)
            {
                return false;
            }
            if (chars[0] != 'A')
            {
                return false;
            }
            if (chars[chars.Length - 1] != 'Z')
            {
                return false;
            }
            return true;
        }

        // --- Repro 2: Dictionary built via repeated Add() calls, then reused (0x06000064) ---
        // Several void Add() calls interspersed with string concatenation, then the SAME
        // dictionary reference is read/passed on afterward — the shape where our interpreter
        // has previously mis-tracked the dictionary's identity as a leftover string value.
        public static Dictionary<string, string> BuildDictionary(string keyA, string valA, string keyB, string valB)
        {
            var map = new Dictionary<string, string>();
            string combined = valA + valB;
            map.Add(keyA, combined);
            map.Add(keyB, valB);
            Console.WriteLine("dict count: " + map.Count);
            return map;
        }

        // --- Repro 3: value-type (struct) virtual call + reconstruction (0x0600001E) ---
        // Guid.ToString() is a virtual call on a struct receiver — needs either `box` or a
        // `constrained.` prefix to be valid IL. This is the shape behind the "found address
        // of value Guid, expected ref Object" / "call to base type of valuetype" errors.
        public static bool GuidRoundTrip()
        {
            Guid g = Guid.NewGuid();
            string s = g.ToString();
            Guid parsed = new Guid(s);
            return parsed.ToString() == s;
        }

        // --- Repro 4: native numeric comparison reconstruction ---
        // Parameters keep the compiler from folding the expressions. Together these checks
        // exercise signed integer, floating-point and byte/I4 comparison paths.
        public static bool CompareNumericPaths(int low, int high, double small, double large, byte marker)
        {
            bool integers = low < high
                && high > low
                && low != high
                && low <= high
                && high >= low;
            bool floatingPoint = small < large
                && large > small
                && small != large;
            bool byteValue = marker != 0;
            return integers && floatingPoint && byteValue;
        }

        // --- Repro 5: reference equality and null/falsy reconstruction ---
        // This deliberately uses both branch-style null tests and a direct reference equality.
        public static bool CheckReferenceNulls(string text, object optional)
        {
            if (text == null)
            {
                return false;
            }
            if (optional != null)
            {
                return false;
            }

            object alias = text;
            return alias != null && alias == (object)text;
        }

        // --- Repro 6: CLR I4-stack arithmetic with a byte operand ---
        // Byte is represented as I4 on the evaluation stack. The expression covers the
        // add/multiply/subtract/remainder family that previously leaked VM helper calls.
        public static int ComputeI4Arithmetic(byte value, int divisor)
        {
            if (divisor == 0)
            {
                return -1;
            }

            int remainder = value % divisor;
            int mixed = (value + divisor) * 2;
            return mixed - remainder;
        }

        // --- Repro 7: dense switch with return/leave through a finally region ---
        // The public state makes finally execution observable even when a case returns early.
        public static int LastSwitchFinallyState;

        public static int SwitchWithFinally(int selector)
        {
            int result = 0;
            LastSwitchFinallyState = -999;
            try
            {
                switch (selector)
                {
                    case 0:
                        result = 10;
                        break;
                    case 1:
                        result = 20;
                        break;
                    case 2:
                        result = 30;
                        return result;
                    case 3:
                        result = 40;
                        goto case 0;
                    default:
                        result = -5;
                        break;
                }

                return result + 1;
            }
            finally
            {
                LastSwitchFinallyState = result + 100;
            }
        }

        // --- Repro 8: switch + catch nested inside a finally-protected region ---
        // Case 1 exercises the catch path; case 2 leaves both protected regions through a return.
        public static int LastCatchFinallyState;

        public static int SwitchWithCatchFinally(int selector)
        {
            int result = 0;
            LastCatchFinallyState = -999;
            try
            {
                try
                {
                    switch (selector)
                    {
                        case 0:
                            result = 5;
                            break;
                        case 1:
                            throw new InvalidOperationException("control-flow fixture");
                        case 2:
                            result = 25;
                            return result;
                        default:
                            result = -5;
                            break;
                    }
                }
                catch (InvalidOperationException)
                {
                    result = 50;
                }

                return result + 1;
            }
            finally
            {
                LastCatchFinallyState = result * 2 + 1;
            }
        }

        // --- Repro 9: loop backedge with continue/break leaving through finally ---
        public static int LastLoopFinallyState;

        public static int LoopContinueBreakFinally(int limit)
        {
            int sum = 0;
            int index = 0;
            LastLoopFinallyState = 0;
            while (index < limit)
            {
                try
                {
                    if (index == 1)
                    {
                        sum += 10;
                        index++;
                        continue;
                    }
                    if (index == 3)
                    {
                        sum += 100;
                        break;
                    }

                    sum += index;
                }
                finally
                {
                    LastLoopFinallyState = unchecked(LastLoopFinallyState * 31 + index + sum);
                }

                index++;
            }

            return sum + index * 1000;
        }

        // --- Repro 10: differing values merge at a loop header and after every branch ---
        public static int LastMergeTrace;

        public static int MergeBackedgeStates(int seed, bool alternate)
        {
            int value = alternate ? seed + 3 : seed - 2;
            int trace = 0;
            for (int index = 0; index < 5; index++)
            {
                if (((value + index) & 1) == 0)
                {
                    value = value * 2 + index;
                    trace = trace * 10 + 1;
                }
                else
                {
                    value -= 3;
                    trace = trace * 10 + 2;
                }
            }

            LastMergeTrace = trace;
            return value;
        }

        // --- Repro 11: filter evaluation, false filter, rethrow and escaping exception ---
        public static int LastFilterTrace;
        public static string LastFilterException;

        public static int FilterAndRethrow(int mode)
        {
            LastFilterTrace = 0;
            LastFilterException = string.Empty;
            try
            {
                try
                {
                    LastFilterTrace = LastFilterTrace * 10 + 1;
                    if (mode == 0)
                        throw new InvalidOperationException("caught");
                    if (mode == 1)
                        throw new ArgumentException("rethrow");
                    if (mode == 2)
                        throw new ArgumentException("bypass");
                    if (mode == 4)
                        throw new InvalidOperationException("escape");
                    return 10 + mode;
                }
                catch (Exception ex) when (RecordFilter(ex, mode))
                {
                    LastFilterTrace = LastFilterTrace * 10 + 3;
                    if (mode == 1)
                    {
                        LastFilterTrace = LastFilterTrace * 10 + 4;
                        throw;
                    }
                    return 50;
                }
            }
            catch (ArgumentException ex)
            {
                LastFilterTrace = LastFilterTrace * 10 + 5;
                LastFilterException = ex.GetType().FullName + ":" + ex.Message;
                return 100 + ex.Message.Length;
            }
            finally
            {
                LastFilterTrace = LastFilterTrace * 10 + 6;
            }
        }

        public static bool RecordFilter(Exception ex, int mode)
        {
            LastFilterTrace = LastFilterTrace * 10 + 2;
            return ex.Message.Length >= 6 && mode != 2 && mode != 4;
        }

        // --- Repro 12: rethrow and finally without a filter ---
        // Agile.NET 6.6 rejects endfilter during protection, so the filter case above remains a
        // source-only CLR oracle while this method isolates the rethrow behavior it can virtualize.
        public static int LastRethrowTrace;
        public static string LastRethrowException;

        public static int RethrowWithoutFilter(int mode)
        {
            LastRethrowTrace = 0;
            LastRethrowException = string.Empty;
            try
            {
                try
                {
                    LastRethrowTrace = LastRethrowTrace * 10 + 1;
                    if (mode == 0)
                        return 10;
                    if (mode == 1)
                        throw new ArgumentException("inner");
                    throw new InvalidOperationException("escape");
                }
                catch (ArgumentException)
                {
                    LastRethrowTrace = LastRethrowTrace * 10 + 2;
                    throw;
                }
            }
            catch (ArgumentException ex)
            {
                LastRethrowTrace = LastRethrowTrace * 10 + 3;
                LastRethrowException = ex.GetType().FullName + ":" + ex.Message;
                return 100 + ex.Message.Length;
            }
            finally
            {
                LastRethrowTrace = LastRethrowTrace * 10 + 4;
            }
        }

        public static void Main(string[] args)
        {
            Console.WriteLine("Test1 (array length index): " + CheckArrayLengthIndex("AxyZ"));

            var dict = BuildDictionary("first", "hello", "second", "world");
            foreach (var kv in dict)
            {
                Console.WriteLine("  " + kv.Key + " = " + kv.Value);
            }

            Console.WriteLine("Test3 (guid roundtrip): " + GuidRoundTrip());
            if (args.Length > 0 && args[0] == "--extended")
            {
                Console.WriteLine("Test4 (numeric comparisons): " + CompareNumericPaths(3, 8, 2.5, 4.0, 1));
                Console.WriteLine("Test5 (reference nulls): " + CheckReferenceNulls("ready", null));
                Console.WriteLine("Test6 (i4 arithmetic): " + ComputeI4Arithmetic(23, 7));
            }

            Console.WriteLine("Done. Press Enter to exit.");
            Console.ReadLine();
        }
    }
}
