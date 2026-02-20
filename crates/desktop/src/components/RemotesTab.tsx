import { Link2, Plus, ShieldX, Signal } from "lucide-react";
import { useMemo, useState } from "react";
import type { AddRemoteRequest, PairingResult, RemoteServer } from "../lib/types";
import { GlassCard } from "./GlassCard";

interface RemotesTabProps {
  enabled: boolean;
  remotes: RemoteServer[];
  onAddRemote: (request: AddRemoteRequest) => Promise<PairingResult>;
  onRemoveRemote: (remoteId: string) => Promise<void>;
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

export function RemotesTab({ enabled, remotes, onAddRemote, onRemoveRemote }: RemotesTabProps) {
  const [name, setName] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [pairingCode, setPairingCode] = useState("");
  const [relayFingerprint, setRelayFingerprint] = useState("");
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
          <div className="inline-flex items-center gap-2 rounded-lg border border-white/20 bg-surface/60 px-3 py-2 text-sm text-text/80">
            <Signal className="h-4 w-4" />
            {enabled ? "Server sync enabled" : "Server sync disabled"}
          </div>
        </div>
      </GlassCard>

      {!enabled ? (
        <GlassCard className="border-dashed border-amber-200/35">
          <p className="text-sm text-amber-100/90">
            Enable `Server Sync` in Settings before adding remotes.
          </p>
        </GlassCard>
      ) : null}

      <GlassCard>
        <h3 className="mb-3 text-sm font-semibold uppercase tracking-[0.16em] text-text/70">Add New Remote</h3>
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
              });
              setLatestProof(result.noiseProof);
              setName("");
              setEndpoint("");
              setPairingCode("");
              setRelayFingerprint("");
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
            className="rounded-lg border border-white/15 bg-surface/70 px-3 py-2 text-sm text-text outline-none"
            required
          />
          <input
            value={endpoint}
            onChange={(event) => setEndpoint(event.target.value)}
            placeholder="host:port (example: 10.0.0.5:51820)"
            className={endpoint.trim() && !endpointIsValid ? "rounded-lg border border-rose-300 bg-rose-950/20 px-3 py-2 text-sm text-text outline-none" : "rounded-lg border border-white/15 bg-surface/70 px-3 py-2 text-sm text-text outline-none"}
            required
          />
          <input
            value={pairingCode}
            onChange={(event) => setPairingCode(event.target.value)}
            placeholder="Pairing code"
            className="rounded-lg border border-white/15 bg-surface/70 px-3 py-2 text-sm text-text outline-none"
            required
          />
          <input
            value={relayFingerprint}
            onChange={(event) => setRelayFingerprint(event.target.value)}
            placeholder="Server fingerprint (SHA-256 hex)"
            className="rounded-lg border border-white/15 bg-surface/70 px-3 py-2 text-sm text-text outline-none"
            required
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
          <div className="mt-3 rounded-lg border border-white/10 bg-surface/50 p-3 text-xs text-text/75">
            Noise proof: <span className="font-mono">{latestProof}</span>
          </div>
        ) : null}
      </GlassCard>

      <GlassCard>
        <h3 className="mb-3 text-sm font-semibold uppercase tracking-[0.16em] text-text/70">Configured Remotes</h3>
        <div className="space-y-2">
          {remotes.map((remote) => (
            <div
              key={remote.id}
              className="flex flex-col gap-2 rounded-lg border border-white/10 bg-surface/45 p-3 md:flex-row md:items-center md:justify-between"
            >
              <div>
                <div className="flex items-center gap-2 text-sm font-semibold text-text">
                  <Link2 className="h-4 w-4" /> {remote.name}
                </div>
                <p className="text-xs text-text/70">{remote.endpoint}</p>
                <p className="text-xs text-text/60">
                  {remote.keyCount} keys | last sync {remote.lastSync ?? "never"}
                </p>
              </div>
              <button
                type="button"
                onClick={() => onRemoveRemote(remote.id)}
                className="inline-flex items-center gap-2 rounded-lg border border-rose-200/30 px-3 py-2 text-xs text-rose-100"
              >
                <ShieldX className="h-4 w-4" /> Remove + Remote Erase
              </button>
            </div>
          ))}
          {remotes.length === 0 ? (
            <div className="rounded-lg border border-dashed border-white/15 p-3 text-sm text-text/60">No remotes configured.</div>
          ) : null}
        </div>
      </GlassCard>
    </div>
  );
}
