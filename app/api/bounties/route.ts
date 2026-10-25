// app/api/bounties/route.ts
// READ-ONLY listing of open bounties and the current fee schedule. Creating a bounty, submitting
// a solution, and refunding are all signed by the user's own wallet in the browser.
import { NextResponse } from 'next/server';
import { getReadClient, GENLAYER_CONTRACT_ADDRESS, weiToGen } from '@/lib/genlayer';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

function shape(b: any) {
  return {
    ...b,
    rewardGen: weiToGen(b.reward ?? '0'),
    payoutGen: weiToGen(b.payout ?? '0'),
    attemptsTotal: Object.values(b.attempts ?? {}).reduce((n: number, v: any) => n + Number(v), 0),
    attempts: undefined // keep per-wallet attempt counts out of the list payload
  };
}

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const id = searchParams.get('id');
  const client = getReadClient();
  const call = (functionName: string, args: any[] = []) =>
    client.readContract({ address: GENLAYER_CONTRACT_ADDRESS, functionName: functionName as any, args });

  try {
    if (id) {
      if (id.length > 128) return NextResponse.json({ error: 'Invalid id.' }, { status: 400 });
      const raw = (await call('get_bounty', [id])) as string;
      if (!raw) return NextResponse.json({ found: false });
      return NextResponse.json({ found: true, bounty: shape(JSON.parse(raw)) });
    }

    const offset = Math.max(0, Math.floor(Number(searchParams.get('offset') ?? '0')) || 0);
    const limit = Math.min(50, Math.max(1, Math.floor(Number(searchParams.get('limit') ?? '20')) || 20));
    const [rows, total, feesRaw] = await Promise.all([
      call('list_bounties', [offset, limit]) as Promise<string[]>,
      call('get_total_bounties') as Promise<number>,
      call('get_fees') as Promise<string>
    ]);
    const fees = JSON.parse(feesRaw);
    return NextResponse.json({
      total: Number(total ?? 0),
      bounties: (rows ?? []).map(r => shape(JSON.parse(r))),
      fees: {
        escrowFeeBps: fees.escrow_fee_bps,
        escrowFeePercent: fees.escrow_fee_bps / 100,
        submitFeeWei: fees.submit_fee_wei,
        submitFeeGen: weiToGen(fees.submit_fee_wei),
        accruedWei: fees.accrued_wei,
        accruedGen: weiToGen(fees.accrued_wei)
      }
    });
  } catch (error: any) {
    return NextResponse.json({ error: error?.message || String(error) }, { status: 500 });
  }
}
