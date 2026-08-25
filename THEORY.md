# Theory

## Observation

Final correctness, latency, token, and cost scores hide how much discarded or repeated work an agent performed.

## Hypothesis

Correctness-gated trajectory metrics can reveal material efficiency differences that final-result metrics miss.

## Proposed mechanism

Reconstruct net and gross mutation, editing payload, and semantic-region revisits from observable execution artifacts; classify why revisits occurred.

## Falsifiable requirements

1. Efficiency comparisons are invalid until every compared result passes the same correctness gate.
2. Zero and near-zero net mutation are reported as typed states, not misleading infinite scores.
3. Revisit causes remain explicit: KNOWN_AHEAD, DISCOVERY, TEST_RUNTIME_EVIDENCE, SELF_CORRECTION, FORMATTER, CONFLICT, OTHER_UNKNOWN.

## Disconfirming results

The hypothesis should be weakened or rejected if a comparable baseline passes the same correctness gate and this mechanism provides no repeatable benefit, or if the mechanism introduces safety/correctness failures that bounded revisions do not resolve. Negative results remain in `experiments/`.

## Uncertainty

Cross-model replication, semantic-region ground truth, near-zero net-mutation conventions, and correlation with independent quality judgments.
