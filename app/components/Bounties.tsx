"use client";

import React, { useCallback, useEffect, useState } from "react";
import { Trophy, Plus, RefreshCw, Clock, Coins, Send, CheckCircle2, XCircle, AlertTriangle } from "lucide-react";
import { walletWrite } from "@/lib/wallet";
import { genToWei } from "@/lib/units";

const LANGUAGES = ["Solidity", "Vyper", "Rust", "Move", "Cairo", "Python (GenLayer)", "TypeScript", "Go", "Other"];

type Fees = { escrowFeeBps: number; escrowFeePercent: number; submitFeeWei: string; submitFeeGen: string };

const rid = () => crypto.randomUUID().split("-")[0];

const statusStyle: Record<string, string> = {
  OPEN: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
  CLAIMED: "bg-indigo-500/10 text-indigo-300 border-indigo-500/30",
  EXPIRED: "bg-slate-500/10 text-slate-300 border-slate-600",
  CANCELLED: "bg-slate-500/10 text-slate-300 border-slate-600"
};

function timeLeft(deadline: number) {
  const s = deadline - Math.floor(Date.now() / 1000);
  if (s <= 0) return "deadline passed";
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  return d > 0 ? `${d}d ${h}h left` : `${h}h ${Math.floor((s % 3600) / 60)}m left`;
}

export default function Bounties({
  wallet,
  onLog
}: {
  wallet: string | null;
  onLog: (m: string) => void;
}) {
  const [bounties, setBounties] = useState<any[]>([]);
  const [fees, setFees] = useState<Fees | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [showCreate, setShowCreate] = useState(false);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [language, setLanguage] = useState("Solidity");
  const [criteria, setCriteria] = useState("");
  const [reward, setReward] = useState("0.1");
  const [days, setDays] = useState("7");
  const [creating, setCreating] = useState(false);
  const [createMsg, setCreateMsg] = useState<string | null>(null);

  const [openId, setOpenId] = useState<string | null>(null);
  const [mode, setMode] = useState<"github" | "manual">("github");
  const [repoUrl, setRepoUrl] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<Record<string, string>>({});
  const [outcome, setOutcome] = useState<Record<string, any>>({});

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/bounties?limit=50");
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      setBounties(data.bounties ?? []);
      setFees(data.fees ?? null);
    } catch (e: any) {
        setError("Bounties need the v10 contract, which isn't deployed on this network yet.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const me = wallet?.toLowerCase() ?? "";

  const createBounty = async () => {
    if (!wallet) { setCreateMsg("Error: connect your wallet first."); return; }
    const lines = criteria.split("\n").map(l => l.trim()).filter(Boolean);
    if (!title.trim() || !description.trim()) { setCreateMsg("Error: a title and description are required."); return; }
    if (lines.length < 1 || lines.length > 10) { setCreateMsg("Error: enter 1 to 10 acceptance criteria, one per line."); return; }
    const d = Number(days);
    if (!Number.isInteger(d) || d < 1 || d > 30) { setCreateMsg("Error: the deadline must be 1 to 30 days."); return; }
    const wei = genToWei(reward);
    if (wei <= 0n) { setCreateMsg("Error: enter a positive reward in GEN."); return; }

    setCreating(true);
    setCreateMsg("Confirm the transaction in your wallet...");
    try {
      const id = `bounty_${Date.now()}_${rid()}`;
      const tx = await walletWrite(
        wallet, "create_bounty",
        [id, title.trim(), description.trim(), language, lines.join("\n"), BigInt(d)],
        wei
      );
      setCreateMsg(`Bounty created. Tx: ${tx.hash}`);
      onLog(`Bounty created (${reward} GEN reward). Tx: ${tx.hash}`);
      setTitle(""); setDescription(""); setCriteria("");
      await load();
    } catch (e: any) {
      setCreateMsg(`Error: ${e?.message || e}`);
    } finally {
      setCreating(false);
    }
  };

  const submitSolution = async (b: any) => {
    if (!wallet) { setMsg(m => ({ ...m, [b.id]: "Error: connect your wallet first." })); return; }
    if (!fees) { setMsg(m => ({ ...m, [b.id]: "Error: fee schedule not loaded yet." })); return; }
    const say = (t: string) => setMsg(m => ({ ...m, [b.id]: t }));
    setBusy(true);
    setOutcome(o => ({ ...o, [b.id]: null }));
    try {
      say("Pinning your code to an exact commit and hashing it...");
      const res = await fetch("/api/bounty/bundle", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(mode === "github" ? { url: repoUrl } : { code })
      });
      const bundle = await res.json();
      if (bundle.error) throw new Error(bundle.error);

      say(`Confirm in your wallet: ${fees.submitFeeGen} GEN submission fee (non-refundable). Validators then judge your code, which can take a few minutes...`);
      const submissionId = `sol_${Date.now()}_${rid()}`;
      const tx = await walletWrite(
        wallet, "submit_bounty_solution",
        [b.id, submissionId, bundle.repoUrl, bundle.commitSha, bundle.contentHash, bundle.scopeManifest, bundle.payload],
        BigInt(fees.submitFeeWei),
        { retries: 120 }
      );
      onLog(`Bounty solution finalized. Tx: ${tx.hash}`);

      const vr = await fetch(`/api/lookup?type=verdict&submissionId=${encodeURIComponent(submissionId)}`);
      const v = await vr.json();
      if (v.found) setOutcome(o => ({ ...o, [b.id]: { ...v.data, txHash: tx.hash, truncated: bundle.truncated } }));
      say(v.found && v.data.accepted ? "Accepted. The reward was sent to your wallet." : "Judged. See the result below.");
      await load();
    } catch (e: any) {
      say(`Error: ${e?.message || e}`);
    } finally {
      setBusy(false);
    }
  };

  const refund = async (b: any) => {
    if (!wallet) return;
    setBusy(true);
    setMsg(m => ({ ...m, [b.id]: "Confirm the refund in your wallet..." }));
    try {
      const tx = await walletWrite(wallet, "refund_bounty", [b.id]);
      setMsg(m => ({ ...m, [b.id]: `Refunded. Tx: ${tx.hash}` }));
      onLog(`Bounty refunded. Tx: ${tx.hash}`);
      await load();
    } catch (e: any) {
      setMsg(m => ({ ...m, [b.id]: `Error: ${e?.message || e}` }));
    } finally {
      setBusy(false);
    }
  };

  const input = "w-full bg-slate-950 border border-slate-800 rounded-xl py-2 px-3 text-xs text-slate-200 focus:outline-none focus:border-indigo-500 transition";

  return (
    <section className="p-6 rounded-2xl border border-slate-800 bg-[#0B0F19]/80 backdrop-blur-xl shadow-2xl space-y-5">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-slate-300 font-bold">
          <Trophy className="w-4 h-4 text-amber-400" /> Open bounties
        </div>
        <div className="flex items-center gap-2">
          <button onClick={load} className="p-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-300 hover:border-indigo-500/50 transition" title="Refresh">
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          </button>
          <button
            onClick={() => setShowCreate(v => !v)}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium bg-indigo-600/20 border border-indigo-500/40 text-indigo-200 hover:bg-indigo-600/30 transition"
          >
            <Plus className="w-3.5 h-3.5" /> Post a bounty
          </button>
        </div>
      </div>

      <p className="text-[11px] text-slate-400 leading-relaxed">
        Post the contract you need and lock a reward. The first solution that GenLayer validators judge both secure and compliant with every acceptance criterion
        is paid automatically. Validators read the code; they do not run it, so write criteria that can be checked by reading.
      </p>

      {fees && (
        <div className="flex items-start gap-2 p-3 rounded-xl bg-amber-500/5 border border-amber-500/20 text-[11px] text-amber-200/90 leading-relaxed">
          <Coins className="w-3.5 h-3.5 mt-0.5 shrink-0" />
          <span>
            Platform fees: <b>{fees.escrowFeePercent}%</b> of a reward is kept when a solution is accepted (also applies to escrow releases).
            Each solution submission costs <b>{fees.submitFeeGen} GEN</b>, which is not refunded if the solution is rejected. Refunds to a bounty owner are free.
          </span>
        </div>
      )}

      {showCreate && (
        <div className="space-y-2.5 p-4 rounded-xl bg-slate-950/60 border border-slate-800">
          <input className={input} placeholder="Title (e.g. ERC-20 token with a 1% burn)" value={title} onChange={e => setTitle(e.target.value)} maxLength={120} />
          <textarea className={`${input} h-24`} placeholder="Describe the contract you want built" value={description} onChange={e => setDescription(e.target.value)} maxLength={2000} />
          <div className="grid grid-cols-3 gap-2">
            <div className="col-span-1">
              <input className={input} list="bounty-langs" value={language} onChange={e => setLanguage(e.target.value)} maxLength={40} placeholder="Language" />
              <datalist id="bounty-langs">{LANGUAGES.map(l => <option key={l} value={l} />)}</datalist>
            </div>
            <input className={input} placeholder="Reward (GEN)" value={reward} onChange={e => setReward(e.target.value)} />
            <input className={input} placeholder="Deadline (days, 1-30)" value={days} onChange={e => setDays(e.target.value)} />
          </div>
          <textarea className={`${input} h-24 font-mono`} placeholder={"Acceptance criteria, one per line (max 10)\nMust expose transfer and balanceOf\nNo owner-only function can move user funds"} value={criteria} onChange={e => setCriteria(e.target.value)} />
          <button
            onClick={createBounty}
            disabled={creating || !wallet}
            className="w-full py-2.5 rounded-xl text-xs font-medium bg-indigo-600 text-white hover:bg-indigo-500 transition disabled:opacity-50"
          >
            {creating ? "Creating..." : wallet ? `Lock ${reward || "0"} GEN and post bounty` : "Connect a wallet to post a bounty"}
          </button>
          {createMsg && <p className={`text-[11px] break-all ${createMsg.startsWith("Error") ? "text-rose-400" : "text-emerald-400"}`}>{createMsg}</p>}
        </div>
      )}

      {error && <p className="text-[11px] text-rose-400">{error}</p>}
      {!loading && !error && bounties.length === 0 && <p className="text-[11px] text-slate-500">No bounties yet. Post the first one.</p>}

      <div className="space-y-3">
        {bounties.map(b => {
          const expired = b.deadline <= Math.floor(Date.now() / 1000);
          const isOwner = me && me === String(b.owner).toLowerCase();
          const canRefund = isOwner && b.status === "OPEN" && (b.submissions === 0 || expired);
          const canSubmit = b.status === "OPEN" && !expired && !isOwner;
          const out = outcome[b.id];
          return (
            <div key={b.id} className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-3">
              <div className="flex items-start justify-between gap-3">
                <div className="space-y-1 min-w-0">
                  <div className="text-sm font-semibold text-slate-100 break-words">{b.title}</div>
                  <div className="flex flex-wrap items-center gap-2 text-[10px] font-mono text-slate-400">
                    <span className="px-2 py-0.5 rounded-full bg-slate-900 border border-slate-800">{b.language}</span>
                    <span className="flex items-center gap-1"><Clock className="w-3 h-3" />{b.status === "OPEN" ? timeLeft(b.deadline) : b.status.toLowerCase()}</span>
                    <span>{b.submissions} submission{b.submissions === 1 ? "" : "s"}</span>
                  </div>
                </div>
                <div className="text-right shrink-0">
                  <div className="text-sm font-mono font-bold text-amber-300">{b.rewardGen} GEN</div>
                  <span className={`inline-block mt-1 text-[10px] px-2 py-0.5 rounded-full border font-mono ${statusStyle[b.status] ?? statusStyle.CANCELLED}`}>{b.status}</span>
                </div>
              </div>

              <p className="text-[11px] text-slate-400 leading-relaxed whitespace-pre-wrap break-words">{b.description}</p>
              <ol className="list-decimal pl-4 space-y-0.5 text-[11px] text-slate-300">
                {b.criteria.map((c: string, i: number) => <li key={i} className="break-words">{c}</li>)}
              </ol>

              {b.status === "CLAIMED" && (
                <p className="text-[11px] text-indigo-300 break-all">Won by {b.winner}. Paid {b.payoutGen} GEN after the platform fee.</p>
              )}

              <div className="flex flex-wrap gap-2">
                {canSubmit && (
                  <button onClick={() => setOpenId(openId === b.id ? null : b.id)} className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium bg-emerald-600/20 border border-emerald-500/40 text-emerald-300 hover:bg-emerald-600/30 transition">
                    <Send className="w-3.5 h-3.5" /> Submit a solution
                  </button>
                )}
                {canRefund && (
                  <button onClick={() => refund(b)} disabled={busy} className="px-3 py-2 rounded-xl text-xs font-medium bg-slate-900 border border-slate-700 text-slate-300 hover:border-slate-600 transition disabled:opacity-50">
                    Refund my reward
                  </button>
                )}
                {isOwner && b.status === "OPEN" && !canRefund && (
                  <span className="text-[10px] text-slate-500 self-center">Submissions exist, so you can refund after the deadline.</span>
                )}
              </div>

              {openId === b.id && canSubmit && (
                <div className="space-y-2 pt-2 border-t border-slate-800">
                  <div className="flex gap-2 text-[11px]">
                    {(["github", "manual"] as const).map(m => (
                      <button key={m} onClick={() => setMode(m)} className={`px-3 py-1 rounded-lg border ${mode === m ? "border-indigo-500/60 text-indigo-200 bg-indigo-500/10" : "border-slate-800 text-slate-400"}`}>
                        {m === "github" ? "GitHub link" : "Paste code"}
                      </button>
                    ))}
                  </div>
                  {mode === "github"
                    ? <input className={input} placeholder="https://github.com/owner/repo (or a PR / file link)" value={repoUrl} onChange={e => setRepoUrl(e.target.value)} />
                    : <textarea className={`${input} h-36 font-mono`} placeholder="Paste your contract code" value={code} onChange={e => setCode(e.target.value)} />}
                  <button
                    onClick={() => submitSolution(b)}
                    disabled={busy || !wallet || (mode === "github" ? !/^https:\/\/github\.com\//.test(repoUrl) : !code.trim())}
                    className="w-full py-2.5 rounded-xl text-xs font-medium bg-emerald-600 text-white hover:bg-emerald-500 transition disabled:opacity-50"
                  >
                    {busy ? "Working..." : wallet ? `Submit (fee ${fees?.submitFeeGen ?? "..."} GEN)` : "Connect a wallet to submit"}
                  </button>
                </div>
              )}

              {msg[b.id] && <p className={`text-[11px] break-all ${msg[b.id].startsWith("Error") ? "text-rose-400" : "text-slate-300"}`}>{msg[b.id]}</p>}

              {out && (
                <div className={`p-3 rounded-xl border text-[11px] space-y-2 ${out.accepted ? "border-emerald-500/30 bg-emerald-500/5" : "border-rose-500/30 bg-rose-500/5"}`}>
                  <div className="flex items-center gap-2 font-semibold">
                    {out.accepted ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <XCircle className="w-4 h-4 text-rose-400" />}
                    {out.accepted ? "Accepted" : "Not accepted"}: security {out.status}, requirements {out.meets_requirements ? "met" : "not met"}
                  </div>
                  {(out.criteria ?? []).map((c: any) => (
                    <div key={c.id} className="flex gap-2">
                      <span className={c.met ? "text-emerald-400" : "text-rose-400"}>{c.met ? "met" : "unmet"}</span>
                      <span className="text-slate-300 break-words">#{c.id}{c.note ? `: ${c.note}` : ""}</span>
                    </div>
                  ))}
                  {(out.findings ?? []).map((f: any, i: number) => (
                    <div key={i} className="text-slate-400 break-words"><b>{f.severity}</b> {f.type}: {f.summary}</div>
                  ))}
                  {out.truncated && (
                    <div className="flex items-center gap-1.5 text-amber-300"><AlertTriangle className="w-3 h-3" /> Part of your source exceeded the review budget and was truncated.</div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}
