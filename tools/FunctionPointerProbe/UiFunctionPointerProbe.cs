using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Windows.Forms;

internal sealed record UiProbeResult(
    bool Valid,
    object InitializedInstance,
    int FunctionPointers,
    int GotFocusSubscriptions,
    int BackgroundThreads)
{
    public override string ToString() =>
        $"UI_VALID={Valid} LD_FTN={FunctionPointers} GOT_FOCUS={GotFocusSubscriptions} "
        + $"BACKGROUND_THREADS={BackgroundThreads}";
}

internal static class UiFunctionPointerProbe
{
    public static UiProbeResult Run(Assembly assembly, int? token)
    {
        var method = ResolveMethod(assembly, token);
        if (method.IsStatic || method.GetParameters().Length != 2
            || method.GetParameters()[1].ParameterType != typeof(EventArgs))
            throw new InvalidOperationException("UI probe requires an instance (object, EventArgs) method");
        object instance = Activator.CreateInstance(method.DeclaringType!, nonPublic: true)
            ?? throw new InvalidOperationException("could not construct UI declaring type");

        var pointers = IlTokenReader.FunctionPointers(method);
        var eventTargets = pointers.Where(pointer =>
            pointer.GetParameters().Length == 2
            && pointer.GetParameters()[1].ParameterType == typeof(EventArgs)).ToArray();
        var threadTargets = pointers.Where(pointer =>
            pointer.GetParameters().Length == 0).ToArray();
        if (instance is Form form)
        {
            form.CreateControl();
            _ = form.Handle;
            method.Invoke(instance, new[] { instance, EventArgs.Empty });
        }
        else
        {
            method.Invoke(instance, new[] { instance, EventArgs.Empty });
        }

        int subscriptions = CountGotFocusSubscriptions(instance, eventTargets);
        var threads = BackgroundThreads(instance);
        int backgroundThreads = threads.Count;
        foreach (var thread in threads.Where(thread => thread.IsAlive))
        {
            thread.Abort();
            thread.Join(TimeSpan.FromSeconds(2));
        }
        bool valid = pointers.Count == 3 && eventTargets.Length == 2
            && threadTargets.Length == 1 && subscriptions >= 2 && backgroundThreads >= 1;
        return new UiProbeResult(valid, instance, pointers.Count,
            subscriptions, backgroundThreads);
    }

    private static MethodInfo ResolveMethod(Assembly assembly, int? token)
    {
        if (token is int metadataToken)
            return assembly.ManifestModule.ResolveMethod(metadataToken) as MethodInfo
                ?? throw new InvalidOperationException($"0x{metadataToken:X8} is not a method");

        var matches = assembly.GetTypes()
            .Where(type => typeof(Form).IsAssignableFrom(type))
            .SelectMany(type => type.GetMethods(BindingFlags.Instance | BindingFlags.Public
                | BindingFlags.NonPublic | BindingFlags.DeclaredOnly))
            .Where(IsCandidate)
            .ToArray();
        return matches.Length == 1 ? matches[0] : throw new InvalidOperationException(
            $"automatic UI function-pointer discovery found {matches.Length} candidates");
    }

    private static bool IsCandidate(MethodInfo method)
    {
        var parameters = method.GetParameters();
        if (method.IsAbstract || method.ReturnType != typeof(void) || parameters.Length != 2
            || parameters[0].ParameterType != typeof(object)
            || parameters[1].ParameterType != typeof(EventArgs))
            return false;
        try
        {
            var pointers = IlTokenReader.FunctionPointers(method);
            return pointers.Count == 3
                && pointers.Count(pointer => pointer.GetParameters().Length == 2
                    && pointer.GetParameters()[1].ParameterType == typeof(EventArgs)) == 2
                && pointers.Count(pointer => pointer.GetParameters().Length == 0) == 1;
        }
        catch (Exception exception) when (exception is InvalidOperationException
            or ArgumentException or BadImageFormatException)
        {
            return false;
        }
    }

    private static IReadOnlyList<Thread> BackgroundThreads(object instance) =>
        InstanceFields(instance).Select(field => field.GetValue(instance))
            .OfType<Thread>().Where(thread => thread.IsBackground).ToArray();

    private static int CountGotFocusSubscriptions(
        object instance,
        IReadOnlyCollection<MethodInfo> targets)
    {
        var eventsProperty = typeof(Component).GetProperty("Events",
            BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new MissingMemberException("Component.Events");
        var keyField = typeof(Control).GetField("EventGotFocus",
            BindingFlags.Static | BindingFlags.NonPublic)
            ?? typeof(Control).GetFields(BindingFlags.Static | BindingFlags.NonPublic)
                .SingleOrDefault(field => field.Name.IndexOf("GotFocus",
                    StringComparison.OrdinalIgnoreCase) >= 0)
            ?? throw new MissingMemberException("Control.EventGotFocus");
        object key = keyField.GetValue(null)
            ?? throw new InvalidOperationException("GotFocus event key is null");
        int matches = 0;
        foreach (var control in InstanceFields(instance).Select(field => field.GetValue(instance))
            .OfType<Control>().Distinct())
        {
            var list = (EventHandlerList)eventsProperty.GetValue(control);
            if (list[key] is not Delegate handlers)
                continue;
            foreach (var handler in handlers.GetInvocationList())
                if (targets.Any(target => target.MetadataToken == handler.Method.MetadataToken))
                    matches++;
        }
        return matches;
    }

    private static IEnumerable<FieldInfo> InstanceFields(object instance)
    {
        for (Type? type = instance.GetType(); type is not null; type = type.BaseType)
        foreach (var field in type.GetFields(BindingFlags.Instance
            | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly))
            yield return field;
    }
}
