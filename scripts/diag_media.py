"""Diagnose iCourse media URLs.

For a given course, print every candidate media URL the API exposes for each
lecture, then run ffprobe on each one to show whether it actually carries an
audio stream.

Usage (inside the repo, after deps installed):
    DIAG_COURSE_ID=37439 python -u scripts/diag_media.py
    DIAG_COURSE_ID=37439 DIAG_SUB_IDS=659643 python -u scripts/diag_media.py
"""
import inspect
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import main as m  # noqa: E402
from src.api.icourse import ICourseClient  # noqa: E402

CAND_FIELDS = ("preview_url", "url", "video_url", "play_url", "mp4_url", "path")


def build_session():
    for name in ("login_with_retry", "login", "build_session", "make_session"):
        fn = getattr(m, name, None)
        if not callable(fn):
            continue
        try:
            sig = inspect.signature(fn)
        except (TypeError, ValueError):
            continue
        required = [
            p for p in sig.parameters.values()
            if p.default is inspect.Parameter.empty
            and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
        ]
        if not required:
            print("[diag] login via main.%s()" % name, flush=True)
            return fn()
        print("[diag] skip main.%s (needs args)" % name, flush=True)
    raise SystemExit("[diag] no usable login helper in main.py")


def probe(url):
    try:
        r = subprocess.run(
            [
                "ffprobe", "-v", "error",
                "-show_entries", "stream=index,codec_type,codec_name,channels,sample_rate",
                "-of", "json", "-timeout", "20000000", url,
            ],
            capture_output=True, text=True, timeout=300,
        )
        streams = json.loads(r.stdout or "{}").get("streams", [])
        if not streams:
            tail = (r.stderr or "").strip().splitlines()
            return "NO_STREAM " + (tail[-1][:150] if tail else "")
        parts = []
        for s in streams:
            t = s.get("codec_type")
            if t == "audio":
                parts.append("AUDIO idx=%s %s %sch %sHz" % (
                    s.get("index"), s.get("codec_name"),
                    s.get("channels"), s.get("sample_rate")))
            elif t == "video":
                parts.append("video idx=%s %s" % (s.get("index"), s.get("codec_name")))
            else:
                parts.append("%s idx=%s" % (t, s.get("index")))
        return " | ".join(parts)
    except Exception as e:
        return "PROBE_ERR " + str(e)[:150]


def collect(label, obj, out):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, dict):
                for f in CAND_FIELDS:
                    if isinstance(v.get(f), str) and v[f].startswith("http"):
                        out.append(("%s[%s].%s" % (label, k, f), v[f]))
            elif isinstance(v, str) and v.startswith("http"):
                out.append(("%s.%s" % (label, k), v))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            collect("%s[%d]" % (label, i), v, out)


def main_run():
    course_id = os.environ.get("DIAG_COURSE_ID", "").strip()
    only = [x.strip() for x in os.environ.get("DIAG_SUB_IDS", "").split(",") if x.strip()]
    dump_all = os.environ.get("DIAG_ALL", "") == "1"
    if not course_id:
        print("[diag] DIAG_COURSE_ID not set")
        return

    vpn = build_session()
    client = ICourseClient(vpn)

    detail = client.get_course_detail(course_id)
    print("== course %s | %s | %s" % (
        course_id, detail.get("title"), detail.get("teacher")), flush=True)

    for lec in detail.get("lectures", []):
        sub_id = str(lec.get("sub_id"))
        if only and sub_id not in only:
            continue
        if not only and not dump_all and not lec.get("has_playback"):
            continue
        print("\n===== lecture %s  %s  has_playback=%s" % (
            sub_id, lec.get("sub_title"), lec.get("has_playback")), flush=True)
        try:
            info = client.get_sub_info(course_id, sub_id)
        except Exception as e:
            print("   sub_info ERROR: %s" % e, flush=True)
            continue

        print("   info keys: %s" % sorted(info.keys()), flush=True)
        cands = []
        collect("video_list", info.get("video_list"), cands)
        for f in ("playurl", "play_url", "video_url", "audio_url", "audioUrl"):
            v = info.get(f)
            if isinstance(v, str) and v.startswith("http"):
                cands.append((f, v))
        collect("content", info.get("content"), cands)

        seen, uniq = set(), []
        for name, url in cands:
            if url in seen:
                continue
            seen.add(url)
            uniq.append((name, url))

        print("   %d candidate url(s)" % len(uniq), flush=True)
        for name, url in uniq:
            print("   - %s\n       %s\n       -> %s" % (
                name, url[:170], probe(url)), flush=True)


main_run()
