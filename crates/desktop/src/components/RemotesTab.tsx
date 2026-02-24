import { Link2, Plus, ShieldX, Signal } from "lucide-react";
import { useMemo, useState } from "react";
import type { AddRemoteRequest, PairingResult, RemoteServer } from "../lib/types";
import { GlassCard } from "./GlassCard";

interface RemotesTabProps {
  enabled: boolean;
  remotes: RemoteServer[];
  onAddRemote: (request: AddRemoteRequest) => Promise<PairingResult>;
  onRemoveRemote: (remoteId: string) => Promise<void>;
  onRevokeRemoteSession?: (remoteId: string) => Promise<void>;
}

const hasRequiredInput = (value: string) => value.trim().length > 0;

const endpointLooksLikeHostPort = (endpoint: string): boolean => {
  const trimmed = endpoint.trim();
  if (!trimmed) {
    return false;
  }
  if (trimmed.startsWith("[")) {
    const closingBracket = trimmed.indexOf("]");
    return closingBracket > 1 && trimmed.slice(closingBracket + 1).startsWith(":");
  }

  const parts = trimmed.split(":");
  if (parts.length < 2) {
    return false;
  }

  const port = Number(parts[parts.length - 1]);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    return false;
  }

  const host = parts.slice(0, -1).join(":").trim();
  return host.length > 0;
};

export function RemotesTab({
  enabled,
  remotes,
  onAddRemote,
  onRemoveRemote,
  onRevokeRemoteSession,
}: RemotesTabProps) {
  const [name, setName] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [pairingCode, setPairingCode] = useState("");
  const [relayFingerprint, setRelayFingerprint] = useState("");
  const [permissions, setPermissions] = useState("full");
  const [sessionTtlSeconds, setSessionTtlSeconds] = useState("86400");
  const [latestProof, setLatestProof] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  const hasPairingCode = useMemo(() => hasRequiredInput(pairingCode), [pairingCode]);
  const hasRelayFingerprint = useMemo(
    () => hasRequiredInput(relayFingerprint),
    [relayFingerprint],
  );
  const endpointIsValid = useMemo(() => endpointLooksLikeHostPort(endpoint), [endpoint]);
  const canSubmit =
    Boolean(name.trim()) &&
    Boolean(endpoint.trim()) &&
    hasPairingCode &&
    hasRelayFingerprint &&
    endpointIsValid &&
    !isSubmitting;

  return (
    <div className="space-y-4">
      <GlassCard>
        <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
          <div>
            <h2 className="text-lg font-semibold text-text">Remotes</h2>
            <p className="text-sm text-text/70">QUIC + Noise pairing state for server sync.</p>
          </div>
          <div className="inline-flex items-center gap-2 rounded-lg border border-accent/25 bg-surface/60 px-3 py-2 text-sm text-accent/80">
            <Signal className="h-4 w-4" />
            {enabled ? "Server sync enabled" : "Server sync disabled"}
          </div>
        </div>
      </GlassCard>

      {!enabled ? (
        <GlassCard className="border-dashed border-accent/35">
          <p className="text-sm text-accent/90">
            Enable `Server Sync` in Settings before adding remotes.
          </p>
        </GlassCard>
      ) : null}

      <GlassCard>
        <h3 className="mb-3 text-sm font-semibold uppercase tracking-[0.16em] text-accent/70">Add New Remote</h3>
        <p className="mb-3 text-xs text-text/70">Endpoint accepts IP:port or hostname. Pairing code and server fingerprint are required.</p>
        <form
          className="grid gap-3 md:grid-cols-2"
          onSubmit={async (event) => {
            event.preventDefault();
            if (!canSubmit) {
              setSubmitError("Provide a valid endpoint, pairing code, and server fingerprint.");
              return;
            }
            setSubmitError(null);
            setIsSubmitting(true);
            try {
              const result = await onAddRemote({
                name: name.trim(),
                endpoint: endpoint.trim(),
                pairingCode: pairingCode.trim() || undefined,
                relayFingerprint: relayFingerprint.trim() || undefined,
                permissions,
                sessionTtlSeconds: Number(sessionTtlSeconds) || undefined,
              });
              setLatestProof(result.noiseProof);
              setName("");
              setEndpoint("");
              setPairingCode("");
              setRelayFingerprint("");
              setPermissions("full");
              setSessionTtlSeconds("86400");
            } catch (error) {
              setSubmitError(String(error));
            } finally {
              setIsSubmitting(false);
            }
          }}
        >
          <input
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="Remote name"
            className="rounded-lg border border-accent/20 bg-surface/70 px-3 py-2 text-sm text-text outline-none"
            required
          />
          <input
            value={endpoint}
            onChange={(event) => setEndpoint(event.target.value)}
            placeholder="host:port (example: 10.0.0.5:51820)"
            className={endpoint.trim() && !endpointIsValid ? "rounded-lg border border-rose-300 bg-rose-950/20 px-3 py-2 text-sm text-text outline-none" : "rounded-lg border border-accent/20 bg-surface/70 px-3 py-2 text-sm text-text outline-none"}
            required
          />
          <input
            value={pairingCode}
            onChange={(event) => setPairingCode(event.target.value)}
            placeholder="Pairing code"
            className="rounded-lg border border-accent/20 bg-surface/70 px-3 py-2 text-sm text-text outline-none"
            required
          />
          <input
            value={relayFingerprint}
            onChange={(event) => setRelayFingerprint(event.target.value)}
            placeholder="Server fingerprint (SHA-256 hex)"
            className="rounded-lg border border-accent/20 bg-surface/70 px-3 py-2 text-sm text-text outline-none"
            required
          />
          <select
            value={permissions}
            onChange={(event) => setPermissions(event.target.value)}
            className="rounded-lg border border-accent/20 bg-surface/70 px-3 py-2 text-sm text-text outline-none"
          >
            <option value="full">full</option>
            <option value="push_only">push_only</option>
            <option value="read_only">read_only</option>
          </select>
          <input
            value={sessionTtlSeconds}
            onChange={(event) => setSessionTtlSeconds(event.target.value)}
            placeholder="Session TTL seconds"
            className="rounded-lg border border-accent/20 bg-surface/70 px-3 py-2 text-sm text-text outline-none"
          />
          <button
            type="submit"
            disabled={!enabled || !canSubmit}
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-accent px-3 py-2 text-sm font-semibold text-slate-950 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <Plus className="h-4 w-4" /> {isSubmitting ? "Pairing..." : "Pair and Add"}
          </button>
        </form>

        {submitError ? <p className="mt-3 text-xs text-rose-200">{submitError}</p> : null}
        {latestProof ? (
          <div className="mt-3 rounded-lg border border-accent/10 bg-surface/50 p-3 text-xs text-text/75">
            Noise proof: <span className="font-mono">{latestProof}</span>
          </div>
        ) : null}
      </GlassCard>

      <GlassCard>
        <h3 className="mb-3 text-sm font-semibold uppercase tracking-[0.16em] text-accent/70">Configured Remotes</h3>
        <div className="space-y-2">
          {remotes.map((remote) => (
            <div
              key={remote.id}
              className="flex flex-col gap-2 rounded-lg border border-accent/10 bg-surface/45 p-3 transition hover:border-accent/25 md:flex-row md:items-center md:justify-between"
            >
              <div>
                <div className="flex items-center gap-2 text-sm font-semibold text-text">
                  <Link2 className="h-4 w-4" /> {remote.name}
                </div>
                <p className="text-xs text-text/70">{remote.endpoint}</p>
                <p className="text-xs text-text/60">
                  {remote.keyCount} keys | last sync {remote.lastSync ?? "never"} | policy {remote.permissions}
                </p>
                {remote.requiresRepairing ? (
                  <p className="text-xs text-amber-200">Session revoked. Re-pair required.</p>
                ) : null}
              </div>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => onRemoveRemote(remote.id)}
                  className="inline-flex items-center gap-2 rounded-lg border border-rose-200/30 px-3 py-2 text-xs text-rose-100"
                >
                  <ShieldX className="h-4 w-4" /> Remove + Remote Erase
                </button>
                <button
                  type="button"
                  onClick={() => onRevokeRemoteSession?.(remote.id)}
                  className="inline-flex items-center gap-2 rounded-lg border border-amber-200/30 px-3 py-2 text-xs text-amber-100"
                >
                  Revoke Session
                </button>
              </div>
            </div>
          ))}
          {remotes.length === 0 ? (
            <div className="rounded-lg border border-dashed border-accent/15 p-3 text-sm text-text/60">No remotes configured.</div>
          ) : null}
        </div>
      </GlassCard>
    </div>
  );
}
