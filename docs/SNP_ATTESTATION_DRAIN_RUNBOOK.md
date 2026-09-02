# Runbook for the SEV-SNP attestation drain

Use this runbook for terminal attestation evidence from `tee_k` or `tee_t`.

## Terminal evidence

Either of the following conditions starts a terminal drain:

- The attestation error is `ENOTTY` or contains `inappropriate ioctl for device`.
- The kernel log contains one line with both `disabling` and `vmpck`.

The VMPCK condition is permanent for the current VM boot. Only a VM reset restores the VMPCK secrets page.

An ordinary attestation error does not start this drain. The ordinary health thresholds remain three failures and six failures.

After three consecutive ordinary failures, the member reports unhealthy. After six consecutive failures, it starts the existing rate-limited self-reset path.

A successful attestation clears an ordinary failure sequence. The minimum interval between ordinary self-reset attempts remains 15 minutes.

## Drain behavior

Each TEE member owns an independent local drain controller. TEE_K and TEE_T act independently.

The members send no drain messages. They do not agree on the drain.

Terminal evidence starts this sequence:

1. The member closes its local admission immediately.
2. The member cancels its local heartbeat loop and refresh loop.
3. The router makes the whole pair unavailable after the heartbeat of either member becomes stale.
4. The member waits for its loop-stop acknowledgment, zero active sessions, and zero admission reservations.
5. The member attempts one VM reset.

The normal reset requires zero active sessions and zero admission reservations. It also requires the loop-stop acknowledgment.

At the start of the drain, the controller records the absolute cached-attestation expiry. This expiry is the hard reset deadline.

If the cached-attestation expiry is absent or expired, the reset starts after the loop cancellation request. It does not wait for the loop-stop acknowledgment, active sessions, or admission reservations.

If a future cached-attestation expiry occurs, the reset starts at that time. Stuck loops, reservations, and sessions do not extend the deadline.

Current sessions use the cached attestation before the cached-attestation expiry. The controller does not add a fixed grace interval.

TEE_K rejects a new session after successful client authentication and before authoritative session creation.

TEE_T rejects a new control-channel `SessionCreated` registration. An existing registered TEE_T session can still activate through `/ws`.

An in-flight router registration can finish after the drain request. The loop-stop acknowledgment waits for the local call to return.

No registration call remains after `attestation drain loops stopped`. A successful in-guest reset call does not return to the old process.

A returned or denied reset leaves the old process in the drain state. The old process does not open admission or make a second reset attempt.

AWS attestation expiry and failure timing differ. The recorded cached-attestation expiry is the only hard deadline on both platforms.

## Monitoring

Keep this alert policy and condition name:

- Policy: `SNP TEE attestation wedge / self-reset`
- Condition: `attestation terminal wedge or self-reset (tee_k/tee_t)`
- Project: `new-reclaim-architecture`

Use this Cloud Logging filter for the alert condition:

```text
resource.type="gce_instance"
resource.labels.project_id="new-reclaim-architecture"
(jsonPayload.service="tee_k" OR jsonPayload.service="tee_t")
(
  jsonPayload.message="terminal attestation wedge detected; drain requested"
  OR jsonPayload.message="attestation wedged past self-heal threshold; self-resetting VM"
  OR jsonPayload.message="attestation drain attempting VM reset"
  OR jsonPayload.message="attestation drain reset returned; TEE remains draining"
  OR jsonPayload.message="attestation self-heal disabled (SNP_ATTEST_SELFHEAL=0)"
  OR jsonPayload.message="attestation-broker reset failed; staying up (evicted) for manual reset"
  OR jsonPayload.message="self-reset reboot failed; staying up (evicted) for manual reset"
)
```

The implementation emits these drain messages:

- `terminal attestation wedge detected; drain requested`
- `attestation drain started`
- `attestation drain loop cancellation requested`
- `attestation drain loop stop acknowledgment unavailable`
- `attestation drain waiting for sessions`
- `attestation drain loops stopped`
- `attestation drain attempting VM reset`
- `attestation drain reset returned; TEE remains draining`

The implementation also emits these health and reset messages:

- `attestation generation failed`
- `terminal attestation failure diagnostics`
- `attestation failure diagnostics`
- `attestation recovered`
- `attestation wedged past self-heal threshold; self-resetting VM`
- `attestation self-heal disabled (SNP_ATTEST_SELFHEAL=0)`
- `attestation-broker reset failed; staying up (evicted) for manual reset`
- `self-reset reboot failed; staying up (evicted) for manual reset`
- `Rejecting authenticated client: attestation drain in progress`

Read these fields to monitor the drain and inspect the attestation diagnostics:

- `cached_attestation_expiry`
- `active_sessions`
- `admission_reservations`
- `loops_stopped`
- `reason`
- `consecutive_failures`
- `terminal_wedge`
- `errno`
- `errno_num`
- `sev_guest_present`
- `sev_guest_mode`
- `sev_guest_stat_err`
- `kmsg`

The reset reason is `sessions_drained` or `cached_attestation_expired`.

## Operator procedure

1. Read `instance_id`, `project_id`, and `zone` from the alert.
2. In Logs Explorer, set the time range to include the alert start time.
3. Use this filter with the values from the alert:

```text
resource.type="gce_instance"
resource.labels.project_id="PROJECT_ID"
resource.labels.instance_id="INSTANCE_ID"
resource.labels.zone="ZONE"
(jsonPayload.service="tee_k" OR jsonPayload.service="tee_t")
```

4. Set these variables from the alert. Then resolve the numeric instance ID to one VM instance name:

```bash
PROJECT_ID="PROJECT_ID"
ZONE="ZONE"
INSTANCE_ID="INSTANCE_ID"
INSTANCE_NAME="$(gcloud compute instances list \
  --project="${PROJECT_ID}" --zones="${ZONE}" \
  --filter="id=${INSTANCE_ID}" \
  --format="value(name)" \
  --limit=1)"
printf '%s\n' "${INSTANCE_NAME}"
```

5. If the command prints no name, make sure that the alert values are correct.
6. If the command still prints no name, stop.
7. Read the drain messages in timestamp order.
8. Read `cached_attestation_expiry`, `active_sessions`, `admission_reservations`, and `loops_stopped` in each wait message.
9. Use this filter to find direct `ENOTTY` evidence:

```text
(
  (
    jsonPayload.message="attestation generation failed"
    jsonPayload.error:"inappropriate ioctl for device"
  )
  OR
  (
    (
      jsonPayload.message="attestation failure diagnostics"
      OR jsonPayload.message="terminal attestation failure diagnostics"
    )
    jsonPayload.errno_num=25
  )
)
```

10. Use this filter to find VMPCK evidence:

```text
jsonPayload.message="terminal attestation failure diagnostics"
```

If one of these messages exists, the automatic reset did not complete:

- `attestation drain reset returned; TEE remains draining`
- `attestation self-heal disabled (SNP_ATTEST_SELFHEAL=0)`
- `attestation-broker reset failed; staying up (evicted) for manual reset`
- `self-reset reboot failed; staying up (evicted) for manual reset`

CAUTION: If the automatic reset did not complete, use the manual reset command in step 11. A manual reset terminates all local sessions.

11. If the automatic reset did not complete, reset the affected VM:

```bash
gcloud compute instances reset "${INSTANCE_NAME}" \
  --zone="${ZONE}" \
  --project="${PROJECT_ID}"
```

12. After the VM resets, run this command:

```bash
gcloud compute instances describe "${INSTANCE_NAME}" \
  --zone="${ZONE}" \
  --project="${PROJECT_ID}" \
  --format="value(status)"
```

13. If the command output is not `RUNNING`, keep the incident open.
14. In Logs Explorer, set the time range to start after the VM reset.
15. After the affected VM reset, use this filter to find `registered with router`:

```text
resource.type="gce_instance"
resource.labels.project_id="PROJECT_ID"
resource.labels.instance_id="INSTANCE_ID"
resource.labels.zone="ZONE"
jsonPayload.message="registered with router"
```

16. Read `pair_id` from the newest message.
17. Use this project filter with the `pair_id` from step 16:

```text
resource.labels.project_id="PROJECT_ID"
jsonPayload.message="pair status changed"
jsonPayload.pair_id="PAIR_ID"
jsonPayload.to="ready"
```

18. If the filter returns no message, keep the incident open.
19. Use the terminal-evidence filters from steps 9 and 10 again.
20. If terminal evidence occurs again, keep the incident open.
21. If terminal evidence occurs again, attach the new logs to the incident.
