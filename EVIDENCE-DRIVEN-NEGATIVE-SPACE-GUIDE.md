# Evidence-Driven Investigation and Negative-Space Audit

A project-agnostic guide for an AI model investigating an unclear bug, unexplained behavior, system boundary, or proposed opportunity. Use it as a working protocol, not as a reason to generate a large speculative report.

The central question is: **What can the system demonstrably do, what does it reject or hide, and which observation would distinguish the remaining explanations?**

## Working stance

1. Treat a small or ordinary-looking anomaly as a clue, not as proof of a large outcome or as a reason to dismiss it.
2. Preserve a known observation as ground truth. Make each proposed explanation account for it.
3. Separate what was observed from what was inferred, and state what remains unknown.
4. Reduce the problem until its necessary conditions are visible. Expand only when the simpler model is understood.
5. Use failures to update the model. An approach that fails identifies a missing prerequisite, a wrong assumption, or a measurement problem.
6. Follow behavior past the exciting intermediate result. The full workflow can still fail later.

## Terms and evidence labels

- **Positive space:** inputs, states, and transitions known to work.
- **Negative space:** tested inputs or states that are rejected, transformed, ignored, or produce a different outcome. It also includes states a producer cannot generate under the tested conditions.
- **Masked:** behavior behind an earlier gate that the current experiment cannot reach. Masked does not mean absent.
- **Producer:** any client, user, process, tool, service, or environmental condition that creates an input or state.
- **Gate:** a validation, permission, timing, resource, or state condition that must be passed to reach the next behavior.
- **Oracle:** an observable result that distinguishes at least two hypotheses.
- **PROVEN:** directly observed under recorded conditions, with a reproducible artifact.
- **INFERRED:** supported by an explicit evidence chain but not directly observed.
- **UNKNOWN:** not yet tested or distinguishable.
- **MASKED:** cannot currently be observed because an earlier gate blocks it.

Avoid universal claims of absence. Say "not observed under these conditions" unless the complete relevant space is actually known.

## Investigation loop

### 1. Fix the objective and scope

Write down the user's actual question, the observed symptom, and a concrete success criterion. Record environment, version, configuration, privileges, input, timing, and other conditions that may change the result. For live or third-party systems, establish authorization and avoid state-changing experiments outside that scope.

Keep an objective ledger visible throughout the investigation:

| Field | Current answer |
| --- | --- |
| Objective | What must be explained or achieved? |
| Ground truth | What exact observation can be reproduced? |
| Current model | What mechanism best explains it? |
| Key unknown | Which missing fact most affects the next decision? |
| Next test | What cheap observation would distinguish the leading hypotheses? |

### 2. Establish a baseline and a reachable path

Find one valid path through the system and capture its inputs and outputs. Inspect actual producers and contracts: source code, schemas, official clients, documentation, traces, or the running system, as available. Map the sequence from producer through each gate to the final effect. Note which layers are directly observable and which are only inferred.

If no successful baseline is available, record the earliest reachable gate. Do not describe behavior behind that gate as if it has been tested.

### 3. Minimize the phenomenon

Reduce the reproducer or scenario while checking that the defining behavior still occurs. Remove one input, step, dependency, configuration option, or concurrent actor at a time. Record what makes the behavior disappear. For intermittent results, track frequency and timing instead of treating one missed run as disproof.

Compare an original artifact with every simplified or AI-generated replacement. For structured protocols, compare decoded fields and raw bytes when necessary; for other systems, compare traces, state transitions, outputs, and side effects. A plausible reconstruction is not equivalent until it reproduces the same observation.

### 4. Map the negative space

List the dimensions that could change the result, then test only those relevant to the objective:

- **Value:** missing, extra, null, wrong type, boundary, malformed, or normalized input.
- **Structure:** order, nesting, interface, format, route, protocol, or dependency shape.
- **State:** prior calls, replay, expiry, lifecycle, concurrency, cache, or connection reuse.
- **Environment:** version, configuration, permissions, deployment, hardware, or enabled features.
- **Resource:** limits, quotas, scheduling, allocation, latency, or cost.
- **Observation:** error body, return value, logs, timing, state change, and later behavior.

Use a **valid envelope plus one changed dimension**: keep every known prerequisite satisfied while varying one feature. Otherwise, an earlier gate may explain the response and conceal the behavior of interest. Record the rejecting or transforming layer where evidence permits. A generic error, timeout, or unchanged output alone rarely identifies the layer.

### 5. Run discriminating experiments

Before each experiment, state:

> Hypothesis: __. If true, I expect __. If false, I expect __. I will observe __ while holding __ constant.

Choose the cheapest test that could change the decision. Instrument the exact transition where competing explanations diverge. Keep diagnostic changes separate from the final result: tracing, synthetic delays, disabled checks, or simplified environments can reveal a mechanism while changing the behavior being studied.

For each test, retain the input, conditions, raw observation, interpretation, and confidence label. When an experiment fails, name the failed prerequisite. Do not merely repeat it with more volume unless repetition itself tests a timing or reliability hypothesis.

### 6. Revise the model at the point of contradiction

When the result disagrees with the model, identify the first step where prediction and observation differ. Check whether the input reached the intended gate, whether the measurement is valid, and whether a copied technique or source description has an unstated assumption.

Ask: **What must be true for the next transition to occur, and what existing behavior could make it true?** A blocked path may reveal a useful scheduling point, state boundary, normalization rule, or alternate producer. Prefer a system mechanism you can observe over an invented explanation. Keep abandoned approaches in a short log with the evidence that ruled them out.

### 7. Validate the complete outcome

Return to realistic conditions after diagnostic work. Follow the whole chain, including cleanup and subsequent operations. Repeat enough to assess reliability. Test the conditions that matter to the claim, such as different versions or configurations, without silently generalizing beyond them. Distinguish an intermediate capability from the user's actual success criterion.

## Drift controls for an AI model

- Do not turn a source-code possibility into a claim of reachable behavior without showing a producer and path through the gates.
- Do not treat a hidden state as absent; label it MASKED and name the gate.
- Do not treat repeated failures as independent evidence if they all hit the same earlier gate.
- Do not defend a generated explanation that conflicts with bytes, traces, or observed behavior. Correct the explanation.
- Do not adopt a familiar technique merely because it worked elsewhere. Check its prerequisites here.
- Do not expand into every imaginable edge case. Prioritize tests by their ability to distinguish hypotheses or change the outcome.
- Do not report success at an intermediate step if later execution fails.
- Every few experiments, restate the objective, strongest evidence, current unknown, and next test. If a tangent answers none of these, stop it.

## Response format

Report the result in this order:

1. **Answer:** the strongest conclusion justified by the evidence, scoped to tested conditions.
2. **Evidence:** minimal reproducer, key observations, and links or paths to artifacts.
3. **Mechanism:** the sequence of gates and state changes, marking inference explicitly.
4. **Negative space:** what was rejected, transformed, unreachable, or masked, and by which layer if known.
5. **Remaining uncertainty:** the smallest unresolved question and the test that would settle it.
6. **Outcome:** whether the complete user objective was met, including reliability and later effects.

The goal is not to sound certain. It is to make the next correct action obvious and the final conclusion hard to misread.

## Source ideas

- [Alexander Popov's CVE-2026-31695 investigation](https://a13xp0p0v.github.io/2026/11/02/CVE-2026-31695.html): minimizing a weak-looking crash, tracing the race, checking generated bytes against ground truth, testing timing hypotheses, revising tactics, and validating behavior after the initial breakthrough.
- Local source: `NEGATIVE-SPACE-AUDIT-PLATFORM-AGNOSTIC.md`: valid-envelope probes, producer and layer mapping, baseline calibration, stateful negatives, evidence labels, and the distinction between masked and absent behavior.
