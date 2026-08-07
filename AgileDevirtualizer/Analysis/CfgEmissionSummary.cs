namespace AgileDevirtualizer.Analysis;

internal sealed class CfgEmissionSummary
{
    private readonly Dictionary<CfgControlFlowFeatures, int> _featureCounts = [];
    private readonly List<string> _decisions = [];
    private readonly List<CfgMethodEmissionDecision> _methodDecisions = [];

    public CfgEmissionSummary(bool enabled) => Enabled = enabled;

    public bool Enabled { get; }
    public int Candidates { get; private set; }
    public int Activated { get; private set; }
    public int Optimized { get; private set; }
    public int SemanticFailures { get; private set; }
    public int NotSelected { get; private set; }
    public IReadOnlyDictionary<CfgControlFlowFeatures, int> FeatureCounts => _featureCounts;
    public IReadOnlyList<string> Decisions => _decisions;
    public IReadOnlyList<CfgMethodEmissionDecision> MethodDecisions => _methodDecisions;

    public void Record(uint token, string identity, CfgEmissionDecision decision)
    {
        if (decision.Outcome == CfgEmissionOutcome.NotSelected)
            NotSelected++;
        else
            Candidates++;
        if (decision.Outcome == CfgEmissionOutcome.Activated)
        {
            Activated++;
            if (decision.Optimized)
                Optimized++;
        }
        if (decision.Outcome == CfgEmissionOutcome.SemanticFailure)
            SemanticFailures++;

        foreach (var feature in Enum.GetValues<CfgControlFlowFeatures>())
        {
            if (feature == CfgControlFlowFeatures.None || !decision.Features.HasFlag(feature))
                continue;
            _featureCounts[feature] = _featureCounts.GetValueOrDefault(feature) + 1;
        }
        _decisions.Add($"{identity}: {decision.Outcome}; features={decision.Features}; {decision.Reason}");
        _methodDecisions.Add(new CfgMethodEmissionDecision(token, identity, decision));
    }
}

internal sealed record CfgMethodEmissionDecision(
    uint Token,
    string Identity,
    CfgEmissionDecision Decision);
