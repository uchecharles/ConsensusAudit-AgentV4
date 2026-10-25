// app/api/bounty/bundle/route.ts
// Prepares the exact content a solver will submit: pinned to a commit, hashed, scoped.
// Nothing is written on chain and no key is used. The solver's own wallet then sends
// submit_bounty_solution, so the contract sees the real solver as the sender and the contract
// recomputes the content hash itself.
import { NextResponse } from 'next/server';
import { checkRateLimit } from '@/lib/rate-limit';
import { resolveBundle } from '@/lib/audit-input';
import { IngestError } from '@/lib/github-pin';

export const maxDuration = 60;
export const runtime = 'nodejs';

export async function POST(req: Request) {
  try {
    const ip = req.headers.get('x-forwarded-for')?.split(',')[0].trim() || 'unknown';
    const rl = await checkRateLimit(ip);
    if (!rl.allowed) return NextResponse.json({ error: `Rate limit exceeded. Try again in ${rl.retryAfterSeconds}s.` }, { status: 429 });

    const body = await req.json();
    const { bundle } = await resolveBundle({ url: body.url, code: body.code, allowedExtensions: body.allowedExtensions }, { pinToPrior: false });
    return NextResponse.json({
      payload: bundle.payload,
      repoUrl: bundle.repoUrl,
      commitSha: bundle.commitSha,
      contentHash: bundle.contentHash,
      scopeManifest: bundle.scopeManifest,
      scopeHash: bundle.scopeHash,
      truncated: bundle.truncated,
      files: bundle.manifest.files.map(f => ({ path: f.p, bytes: f.n, included: f.i, truncated: f.t === 1 }))
    });
  } catch (e: any) {
    const status = e instanceof IngestError ? e.status : 500;
    return NextResponse.json({ error: e?.message || String(e) }, { status });
  }
}
