"""Parse IOS / IOS-XE running-config ACL sections and search for an IP."""

from __future__ import annotations

import ipaddress
import re


def parse_running_config(config_text: str) -> dict[str, list[str]]:
    """Return {acl_name: [ace_line, ...]} for extended (and standard) ACLs.

    Keeps sequence numbers and original order. Ignores remarks structure
    except keeping them as ACE lines (they never match an IP search unless
    the IP is inside the remark text, which is acceptable).
    """
    acls: dict[str, list[str]] = {}
    current: str | None = None

    for raw in config_text.splitlines():
        line = raw.strip()
        if not line or line == "!":
            # '!' ends current ACL block
            if line == "!":
                current = None
            continue
        m = re.match(r"^ip access-list (?:extended|standard)\s+(\S+)", line, re.IGNORECASE)
        if m:
            current = m.group(1)
            acls.setdefault(current, [])
            continue
        # numbered / named classic ACL header like "access-list 100 permit ..." - skip
        if current is not None:
            # ACE lines are indented in running-config, but be lenient:
            # anything inside the block until '!' or next acl header is an ACE.
            acls[current].append(line)
    return acls


def find_ip(acls: dict[str, list[str]], ip: str) -> dict[str, list[str]]:
    """Filter ACLs to only ACE lines containing the IP as a whole token."""
    pat = re.compile(r"(?<![0-9.])" + re.escape(ip) + r"(?![0-9.])")
    found: dict[str, list[str]] = {}
    for name, aces in acls.items():
        hits = [a for a in aces if pat.search(a)]
        if hits:
            found[name] = hits
    return found


def find_text(acls: dict[str, list[str]], query: str) -> dict[str, list[str]]:
    """Filter ACLs to the person's block(s) + any matching lines.

    Case-insensitive. Used for person (remark) search: "roman",
    "PAKHOLOK" and "Roman Pakholok" all match the block
      5961 remark Roman Pakholok
      5962 permit ...
      5966 remark Roman Pakholok (koniec)
    and return it whole, so the results show WHERE the person has access,
    not just the remark lines. A remark hit without a closing remark
    extends to the next remark (or end of ACL). Non-remark lines matching
    the query are returned individually, as before.
    """
    q = (query or "").strip().lower()
    if not q:
        return {}
    # pasting a whole closing remark still finds its block
    oq = q[:len(q) - len("(koniec)")].strip() if q.endswith("(koniec)") else q

    def _parse(ace: str) -> tuple[str, str]:
        """(kind, text) with the sequence number stripped."""
        m = re.match(r"^\s*(?:\d+\s+)?(permit|deny|remark)\b\s*(.*)$",
                     ace, re.IGNORECASE)
        if not m:
            return ("other", ace.strip())
        return (m.group(1).lower(), m.group(2).strip())

    def _is_close(text: str) -> bool:
        return text.lower().endswith("(koniec)")

    found: dict[str, list[str]] = {}
    for name, aces in acls.items():
        kinds = [_parse(a)[0] for a in aces]
        texts = [_parse(a)[1] for a in aces]
        keep = [False] * len(aces)
        # 1) plain substring hits (any line kind)
        for i, ace in enumerate(aces):
            if q in ace.lower():
                keep[i] = True
        # 2) block expansion: remark <owner> .. remark <owner> (koniec)
        pending: dict[str, int] = {}  # owner_lower -> open index
        for i, ace in enumerate(aces):
            if kinds[i] != "remark":
                continue
            text = texts[i]
            if _is_close(text):
                owner = text[:len(text) - len("(koniec)")].strip().lower()
                if owner in pending and oq in owner:
                    for j in range(pending[owner], i + 1):
                        keep[j] = True
                    del pending[owner]
            else:
                owner = text.lower()
                if oq in owner:
                    pending[owner] = i
        # opens never closed: extend to the next remark (or end of ACL)
        for owner, open_idx in pending.items():
            end_idx = len(aces)
            for j in range(open_idx + 1, len(aces)):
                if kinds[j] == "remark":
                    end_idx = j
                    break
            for j in range(open_idx, end_idx):
                keep[j] = True
        hits = [ace for ace, k in zip(aces, keep) if k]
        if hits:
            found[name] = hits
    return found


def format_results(found: dict[str, list[str]], negate: bool = False) -> str:
    """Format exactly like the requested example.

    Normal:
        Name_of_ACL
            1490 permit ip host ... host 172.26.98.116
    Negated:
        ip access-list extended Name_of_ACL
            no 1490 permit ip host ... host 172.26.98.116
    """
    blocks: list[str] = []
    for name, aces in found.items():
        if negate:
            blocks.append(f"ip access-list extended {name}")
            for ace in aces:
                blocks.append(f"    no {ace}")
        else:
            blocks.append(f"{name}")
            for ace in aces:
                blocks.append(f"    {ace}")
    return "\n".join(blocks)


def format_cli_script(results: list[tuple], negate: bool = False) -> str:
    """Build a paste-ready CLI script from search results.

    `results` is a list of (host, found_dict, err) tuples as stored by the GUI.
    Only paste-safe lines are emitted:
      - device context as IOS comments ("! Device: x" - ignored by the parser)
      - "ip access-list extended NAME" headers (also added in normal mode,
        where the display shows the bare name which alone is not a command)
      - ACE lines, prefixed with "no " when negated
    Error / no-result sections are skipped. The script ends with a trailing
    newline so the last line executes on paste (final Enter).
    Returns "" when there is nothing pasteable.
    """
    out: list[str] = []
    for host, found, err in results:
        if err or not found:
            continue
        out.append(f"! Device: {host}")
        for name, aces in found.items():
            out.append(f"ip access-list extended {name}")
            prefix = "no " if negate else ""
            for ace in aces:
                out.append(f"    {prefix}{ace}")
    if not out:
        return ""
    return "\n".join(out) + "\n"


def _subnet_acls(s: dict) -> tuple[str, str]:
    """Return (acl_in, acl_out), supporting the legacy single 'acl' key."""
    acl_in = str(s.get("acl_in", "") or s.get("acl", "")).strip()
    acl_out = str(s.get("acl_out", "") or s.get("acl", "")).strip()
    return acl_in, acl_out


def normalize_subnet(s: dict) -> dict:
    """Migrate a subnet entry to {"subnet", "acl_in", "acl_out"} shape."""
    acl_in, acl_out = _subnet_acls(s)
    return {"subnet": str(s.get("subnet", "")).strip(),
            "acl_in": acl_in, "acl_out": acl_out}


def resolve_acl_for_ip(subnets: list[dict], ip: str) -> tuple[str, str, str] | None:
    """Find the (ACL-IN, ACL-OUT) pair for an IP via longest-prefix match.

    `subnets` items: {"subnet": "10.207.156.0/24", "acl_in": "...", "acl_out": "..."}
    (legacy single "acl" key is honored for both directions).
    Returns (acl_in, acl_out, subnet_str) or None when nothing matches.
    """
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None
    best: tuple[str, str, str] | None = None
    best_len = -1
    for s in subnets:
        try:
            net = ipaddress.ip_network(str(s.get("subnet", "")).strip(), strict=False)
        except ValueError:
            continue
        acl_in, acl_out = _subnet_acls(s)
        if not (acl_in or acl_out):
            continue
        if addr in net and net.prefixlen > best_len:
            best = (acl_in, acl_out, str(net))
            best_len = net.prefixlen
    return best


def extract_seq_numbers(aces: list[str]) -> set[int]:
    """Sequence numbers already used in an ACL (leading integers of ACE lines)."""
    taken: set[int] = set()
    for ace in aces:
        m = re.match(r"^\s*(\d+)\s+(?:permit|deny|remark)\b", ace, re.IGNORECASE)
        if m:
            try:
                taken.add(int(m.group(1)))
            except ValueError:
                pass
    return taken


def clean_owner(owner: str) -> str:
    """Sanitize the person name for IOS remarks (single spaces, max 100)."""
    return re.sub(r"\s+", " ", (owner or "").strip())[:100]


def owner_end_mark(owner: str) -> str:
    """Closing remark text bracketing the computer's block ("" when no owner)."""
    owner = clean_owner(owner)
    return f"{owner} (koniec)" if owner else ""


def find_pc_entries(entries: list[str], pc_ip: str, owner: str = ""
                    ) -> list[tuple[int, str, bool]]:
    """Existing entries of this computer's block, in ACL order.

    Returns [(seq, ace_text_without_seq, reemit), ...]:
      - permit/deny lines referencing `pc_ip` (whole-token match) are
        re-emitted verbatim as part of the new contiguous block,
      - the block's own remark lines (`remark <owner>` /
        `remark <owner> (koniec)`) are delete-only, so regeneration never
        leaves stale duplicate remarks behind.
    Other remarks are never touched.
    """
    pat = re.compile(r"(?<![0-9.])" + re.escape(pc_ip.strip()) + r"(?![0-9.])")
    owner = clean_owner(owner)
    end = owner_end_mark(owner)
    out: list[tuple[int, str, bool]] = []
    for ace in entries or []:
        m = re.match(r"^\s*(\d+)\s+(permit|deny|remark)\b", ace, re.IGNORECASE)
        if not m:
            continue
        try:
            seq = int(m.group(1))
        except ValueError:
            continue
        rest = ace[m.end(1):].strip()
        kind = m.group(2).lower()
        if kind in ("permit", "deny"):
            if pat.search(ace):
                out.append((seq, rest, True))  # verbatim ACE, seq stripped
        elif owner and kind == "remark":
            text = re.sub(r"(?i)^remark\b\s*", "", rest)
            if text == owner or text == end:
                out.append((seq, rest, False))
    return out


def collapse_ips(ips: list[str]) -> list:
    """Collapse adjacent IPv4 hosts into minimal exact-cover networks.

    E.g. .206 + .207 -> 10.0.0.206/31 ; .204-.207 -> 10.0.0.204/30.
    Only merges when the supernet covers exactly the entered addresses.
    Returns ipaddress.IPv4Network list, sorted.
    """
    nets = []
    for ip in ips:
        try:
            nets.append(ipaddress.ip_network(ip.strip() + "/32"))
        except ValueError:
            continue
    return sorted(ipaddress.collapse_addresses(nets))


def fmt_endpoint(net) -> str:
    """/32 -> 'host A', anything bigger -> 'NETWORK WILDCARD'."""
    if net.prefixlen == 32:
        return f"host {net.network_address}"
    return f"{net.network_address} {net.hostmask}"


RESEQUENCE_STEP = (10, 10)


def _parse_endpoint(tokens: list[str], i: int) -> tuple[dict, int]:
    """Parse one ACE endpoint at tokens[i]. Returns (ep, next_i).

    ep = {"kind": "any"|"host"|"net"|"opaque", "text": str, "ip": int|None}.
    Unknown shapes (object-group, ...) stay opaque: exact-text grouping
    only, never merged or moved.
    """
    import ipaddress as _ip

    def _mk(kind, text, ip=None):
        return ({"kind": kind, "text": text, "ip": ip}, i + 1)

    if i >= len(tokens):
        return ({"kind": "opaque", "text": "", "ip": None}, i)
    tok = tokens[i]
    low = tok.lower()
    if low == "any":
        return ({"kind": "any", "text": "any", "ip": 0}, i + 1)
    if low == "host" and i + 1 < len(tokens):
        try:
            addr = _ip.ip_address(tokens[i + 1])
            return ({"kind": "host", "text": f"host {tokens[i + 1]}",
                     "ip": int(addr)}, i + 2)
        except ValueError:
            pass
    if low in ("addrgroup", "object-group") and i + 1 < len(tokens):
        return ({"kind": "opaque",
                 "text": f"{tok} {tokens[i + 1]}", "ip": None}, i + 2)
    if i + 1 < len(tokens):
        try:
            addr = _ip.ip_address(tok)
            wild = _ip.ip_address(tokens[i + 1])
            net = _ip.ip_network((int(addr),
                                  (~int(wild)) & 0xFFFFFFFF), strict=False)
            return ({"kind": "net",
                     "text": f"{tok} {tokens[i + 1]}",
                     "ip": int(net.network_address)}, i + 2)
        except ValueError:
            pass
    else:
        try:
            addr = _ip.ip_address(tok)
            return ({"kind": "host", "text": f"host {tok}",
                     "ip": int(addr)}, i + 1)
        except ValueError:
            pass
    return ({"kind": "opaque", "text": tok, "ip": None}, i + 1)


_PORT_OPS = ("eq", "neq", "lt", "gt", "range")


def _parse_port_spec(tokens: list[str], i: int) -> tuple[str, int]:
    """Parse optional src-port spec (eq www / range 1 2). Returns (text, next_i)."""
    if i < len(tokens) and tokens[i].lower() in _PORT_OPS:
        op = tokens[i].lower()
        take = 3 if op == "range" else 2
        return (" ".join(tokens[i:i + take]), min(i + take, len(tokens)))
    return ("", i)


def parse_ace(ace: str) -> dict | None:
    """Parse one ACE line into a dict (None when not an ACE).

    Result: {"seq", "kind" (permit/deny/remark/other), "action", "proto",
    "src"/"dst" endpoint dicts, "src_opts", "options", "text" (no seq),
    "raw"}. Unparseable shapes are kind "other"/opaque and are never
    merged or moved by the optimizer (only renumbered in place).
    """
    m = re.match(r"^\s*(?:(\d+)\s+)?(permit|deny|remark)\b\s*(.*)$",
                 ace, re.IGNORECASE)
    if not m:
        return None
    seq = None
    try:
        seq = int(m.group(1)) if m.group(1) is not None else None
    except ValueError:
        pass
    kind = m.group(2).lower()
    rest = m.group(3).strip()
    if kind == "remark":
        return {"seq": seq, "kind": "remark", "text": rest, "raw": ace.strip()}
    tokens = rest.split()
    if len(tokens) < 3:
        # e.g. truncated line: keep verbatim (with action word), never
        # merged or moved - only renumbered in place.
        text = re.sub(r"\s+", " ", f"{kind} {rest}").strip()
        return {"seq": seq, "kind": "other", "text": text, "raw": ace.strip()}
    action = kind
    proto = tokens[0].lower()
    src, i = _parse_endpoint(tokens, 1)
    src_opts, i = _parse_port_spec(tokens, i)
    dst, i = _parse_endpoint(tokens, i)
    options = re.sub(r"\s+", " ", " ".join(tokens[i:])).strip()
    text = re.sub(r"\s+", " ", f"{kind} {rest}").strip()
    return {"seq": seq, "kind": action, "action": action, "proto": proto,
            "src": src, "dst": dst, "src_opts": src_opts.lower(),
            "options": options.lower(), "text": text, "raw": ace.strip()}


def _ace_units(entries: list[str]) -> list[dict]:
    """Group entries into units: {"remarks": [...], "ace": parsed|None}.

    Remark lines attach to the FOLLOWING ace (our generator convention);
    trailing remarks attach to the preceding unit (or stand alone).
    """
    units: list[dict] = []
    pending: list[str] = []
    for ace in entries or []:
        p = parse_ace(ace)
        if p is None:
            continue
        if p["kind"] == "remark":
            pending.append(p["text"])
            continue
        units.append({"remarks": pending, "ace": p})
        pending = []
    if pending:
        if units:
            units[-1]["remarks"].extend(pending)
        else:
            units.append({"remarks": pending, "ace": None})
    return units


def _unit_key(unit: dict, sort_side: str) -> tuple | None:
    """Sort key or None when the unit must not move."""
    ace = unit.get("ace")
    if ace is None or ace.get("kind") not in ("permit", "deny"):
        return None
    for side in ("src", "dst"):
        if ace[side].get("kind") == "opaque":
            return None
    ep = ace["src"] if sort_side == "src" else ace["dst"]
    if ep.get("ip") is None:
        return None
    return (ep["ip"],)


def _swappable(u1: dict, u2: dict, sort_side: str) -> bool:
    """True when two units may change order without changing semantics.

    Only within the same action/proto/ports/shape: same-action rules yield
    the same verdict regardless of order; different protos/ports never
    match the same packet... (conservative: exact same shape required).
    """
    a, b = u1.get("ace"), u2.get("ace")
    if a is None or b is None:
        return False
    if a.get("kind") not in ("permit", "deny"):
        return False
    if b.get("kind") != a["kind"]:
        return False
    if a.get("proto") != b.get("proto"):
        return False
    if a.get("src_opts") != b.get("src_opts"):
        return False
    if a.get("options") != b.get("options"):
        return False
    other = "dst" if sort_side == "src" else "src"
    if a[other].get("text") != b[other].get("text"):
        return False
    if _unit_key(u1, sort_side) is None or _unit_key(u2, sort_side) is None:
        return False
    return True


def optimize_acl(entries: list[str], sort_side: str = "src") -> dict:
    """Propose an optimized version of one ACL's entries.

    Safe transforms only: exact-duplicate removal, exact-cover CIDR
    aggregation of host entries (same action/proto/ports/shape, remark-free
    units), and reordering limited to provably swappable pairs (same
    action + shape, so first-match semantics cannot change). Remarks stay
    attached to their entry. Output is renumbered 10, 20, 30...

    Returns {"deletes": [old seqs], "lines": ["10 remark ...", ...],
             "stats": {"before", "after", "dup", "merged", "remarks"}}.
    """
    import ipaddress as _ip

    if sort_side not in ("src", "dst"):
        sort_side = "src"
    other = "dst" if sort_side == "src" else "src"
    units = _ace_units(entries)
    stats = {"before": len(entries or []), "after": 0, "dup": 0,
             "merged": 0, "remarks": 0}

    # 1) exact duplicates (same ace shape, remarks transferred when possible)
    seen: dict[tuple, int] = {}
    kept: list[dict] = []
    for u in units:
        ace = u.get("ace")
        if ace is None or ace.get("kind") not in ("permit", "deny"):
            kept.append(u)
            continue
        key = (ace["kind"], ace["proto"], ace["src"]["text"],
               ace["dst"]["text"], ace["src_opts"], ace["options"])
        if key in seen:
            stats["dup"] += 1
            prev = kept[seen[key]]
            if not prev["remarks"] and u["remarks"]:
                prev["remarks"] = list(u["remarks"])
            continue
        seen[key] = len(kept)
        kept.append(u)
    units = kept

    # 2) CIDR aggregation of remark-free all-host groups (exact cover only)
    groups: dict[tuple, list[int]] = {}
    for idx, u in enumerate(units):
        ace = u.get("ace")
        if (ace is None or ace.get("kind") not in ("permit", "deny")
                or u["remarks"] or ace[sort_side].get("kind") != "host"):
            continue
        gkey = (ace["kind"], ace["proto"], ace[other]["text"],
                ace["src_opts"], ace["options"])
        groups.setdefault(gkey, []).append(idx)
    merged: dict[int, list[dict]] = {}  # old index -> fresh units
    consumed: set[int] = set()
    for gkey, idxs in groups.items():
        if len(idxs) < 2:
            continue
        nets = sorted(_ip.ip_network(f"{units[i]['ace'][sort_side]['text'].split()[1]}/32")
                      for i in idxs)
        collapsed = sorted(_ip.collapse_addresses(nets))
        if len(collapsed) >= len(nets):
            continue  # nothing merges
        stats["merged"] += len(nets) - len(collapsed)
        action, proto, other_text, src_opts, options = gkey
        new_units: list[dict] = []
        for net in collapsed:
            if net.prefixlen == 32:
                ep_text = f"host {net.network_address}"
            else:
                ep_text = f"{net.network_address} {net.hostmask}"
            if sort_side == "src":
                src_t, dst_t = ep_text, other_text
            else:
                src_t, dst_t = other_text, ep_text
            text = f"{action} {proto} {src_t}"
            if src_opts:
                text += f" {src_opts}"
            text += f" {dst_t}"
            if options:
                text += f" {options}"
            parsed = parse_ace(text)
            if parsed is None:  # pragma: no cover - built from valid parts
                continue
            new_units.append({"remarks": [], "ace": parsed})
        if new_units:
            merged[idxs[0]] = new_units
            consumed.update(idxs[1:])
    if consumed:
        rebuilt: list[dict] = []
        for i, u in enumerate(units):
            if i in consumed:
                continue
            if i in merged:
                rebuilt.extend(merged[i])
            else:
                rebuilt.append(u)
        units = rebuilt

    # 3) constrained bubble sort by sort-side IP (swappable pairs only)
    def _key(u):
        k = _unit_key(u, sort_side)
        return k[0] if k else None

    moved = True
    while moved:
        moved = False
        for i in range(len(units) - 1):
            k1, k2 = _key(units[i]), _key(units[i + 1])
            if (k1 is not None and k2 is not None and k1 > k2
                    and _swappable(units[i], units[i + 1], sort_side)):
                units[i], units[i + 1] = units[i + 1], units[i]
                moved = True

    # 4) renumber + collect deletes
    deletes: list[int] = []
    for ace in entries or []:
        p = parse_ace(ace)
        if p and p.get("seq") is not None:
            deletes.append(p["seq"])
    lines: list[str] = []
    n = 10
    for u in units:
        for r in u["remarks"]:
            stats["remarks"] += 1
            lines.append(f"{n} remark {r}")
            n += 10
        ace = u.get("ace")
        if ace is not None and ace.get("kind") in ("permit", "deny", "other"):
            lines.append(f"{n} {ace['text']}")
            n += 10
    stats["after"] = len(lines)
    return {"deletes": deletes, "lines": lines, "stats": stats}


def build_full_script(pc_ip: str,
                      groups: list[tuple[str, str, str, list]],
                      do_in: bool = True, do_out: bool = True,
                      starts: dict[str, int] | None = None,
                      taken: dict[str, set[int]] | None = None,
                      owner: str = "",
                      relocate: dict[str, list[tuple[int, str, bool]]] | None = None) -> str:
    """Build the full paste script: conf t / deletes / resequences / stanzas / end / wr.

    `groups`: [(acl_in, acl_out, note, [collapsed nets])] in output order.
    `starts`: {acl_name: first seq to try} - defaults to max(taken)+1
      (or 10 when the ACL is empty). Taken numbers are always skipped.
    `owner`: optional person name - emitted as a numbered `remark` line
      before the permit entries of every stanza (sanitized, max 100 chars),
      plus a closing `remark "<owner> (koniec)"` after them so the whole
      block for this computer stays visually grouped.
    `relocate`: {acl_name: [(old_seq, ace_text, reemit), ...]} - existing
      entries of this computer's block, found by find_pc_entries(). They are
      deleted first (`no <seq>`, before any resequence); permit/deny lines
      are re-emitted verbatim as part of the new contiguous block, so
      everything for this computer (remark + old + new entries) lands in
      one place. ACLs that only have relocated entries still get their own
      stanza + resequences.
    No indentation - exactly the CLI paste format.
    Ends with a trailing newline so the last line executes on paste.
    """
    taken = taken or {}
    starts = starts or {}
    relocate = relocate or {}
    owner = clean_owner(owner)
    end_mark = owner_end_mark(owner)
    lines: list[str] = ["conf t"]
    involved: list[str] = []  # ACLs in resequence/stanza order
    for acl_in, acl_out, _note, _nets in groups:
        if do_in and acl_in:
            involved.append(acl_in)
        if do_out and acl_out:
            involved.append(acl_out)

    def _reloc(acl: str) -> list[tuple[int, str, bool]]:
        if acl in relocate:
            return relocate[acl]
        low = acl.lower()
        for name, entries in relocate.items():
            if name.lower() == low:
                return entries
        return []

    # relocation-only ACLs (old entries, no new nets) still need stanzas
    seen = set()
    uniq: list[str] = []
    for a in involved:
        if a.lower() in seen:
            continue
        seen.add(a.lower())
        uniq.append(a)
    involved = uniq
    for name in relocate:
        if not any(name == a or name.lower() == a.lower() for a in involved):
            involved.append(name)
    # old entries are deleted BEFORE the first resequence (old numbers valid)
    for acl in involved:
        old = _reloc(acl)
        if not old:
            continue
        lines.append(f"ip access-list extended {acl}")
        for seq, _ace, _keep in old:
            lines.append(f"no {seq}")
    r_start, r_step = RESEQUENCE_STEP
    for acl in involved:
        lines.append(f"ip access-list resequence {acl} {r_start} {r_step}")
    lines.append("")

    next_free: dict[str, int] = {}

    def default_start(acl: str) -> int:
        used = taken.get(acl, set())
        return (max(used) + 1) if used else 10

    def alloc(acl: str) -> int:
        if acl not in next_free:
            base = starts.get(acl, default_start(acl))
            next_free[acl] = base if base >= 1 else 1
        used = taken.get(acl, set())
        n = next_free[acl]
        while n in used:
            n += 1
        next_free[acl] = n + 1
        return n

    first_group = True
    for acl in involved:
        old = _reloc(acl)
        # new nets for this ACL from all groups (IN and OUT sides)
        in_list: list = []
        out_list: list = []
        for acl_in, acl_out, _note, nets in groups:
            if do_in and acl_in == acl:
                in_list.extend(nets)
            if do_out and acl_out == acl:
                out_list.extend(nets)
        if not old and not in_list and not out_list:
            continue
        if not first_group:
            lines.append("")
        first_group = False
        lines.append(f"ip access-list extended {acl}")
        if owner:
            lines.append(f"{alloc(acl)} remark {owner}")
        seen_aces: set[str] = set()  # drop exact duplicates (old vs new overlap)
        for _seq, ace, keep in old:
            if not keep:
                continue  # stale own remark: deleted above, not re-emitted
            if ace in seen_aces:
                continue
            seen_aces.add(ace)
            lines.append(f"{alloc(acl)} {ace}")
        for net in in_list:
            ace = f"permit ip {fmt_endpoint(net)} host {pc_ip}"
            if ace in seen_aces:
                continue
            seen_aces.add(ace)
            lines.append(f"{alloc(acl)} {ace}")
        for net in out_list:
            ace = f"permit ip host {pc_ip} {fmt_endpoint(net)}"
            if ace in seen_aces:
                continue
            seen_aces.add(ace)
            lines.append(f"{alloc(acl)} {ace}")
        if end_mark:
            lines.append(f"{alloc(acl)} remark {end_mark}")
    lines.append("")
    for acl in involved:
        lines.append(f"ip access-list resequence {acl} {r_start} {r_step}")
    lines.append("end")
    lines.append("wr")
    return "\n".join(lines) + "\n"


def build_acl_script(pc_ip: str, cam_ips: list[str], acl_in: str, acl_out: str,
                     do_in: bool = True, do_out: bool = True,
                     seq_start: int | None = None,
                     acl_source: str = "") -> str:
    """Single-group wrapper around build_grouped_acl_script."""
    return build_grouped_acl_script(
        pc_ip, [(acl_in, acl_out, acl_source, list(cam_ips))],
        do_in, do_out, seq_start)


def build_grouped_acl_script(pc_ip: str,
                             groups: list[tuple[str, str, str, list[str]]],
                             do_in: bool = True, do_out: bool = True,
                             seq_start: int | None = None) -> str:
    """Build paste-ready extended ACL blocks, grouped per subnet mapping.

    `groups`: list of (acl_in, acl_out, note, cams), e.g. note
    "subnet 10.207.156.0/23" or "manual". One "! PC:" header, then per
    group a "!" comment (safe - global config mode between stanzas) plus
    the IN and/or OUT stanzas:
      IN  (ACL-IN):  permit ip host <cam> host <pc>   (cameras -> computer)
      OUT (ACL-OUT): permit ip host <pc> host <cam>   (computer -> cameras)
    Sequence numbers (if given) continue across groups. Ends with a
    trailing newline so the last line executes on paste.
    """
    lines: list[str] = [f"! PC: {pc_ip}"]
    seq = seq_start

    def emit(ace: str):
        nonlocal seq
        if seq is not None:
            lines.append(f"    {seq} {ace}")
            seq += 1
        else:
            lines.append(f"    {ace}")

    for acl_in, acl_out, note, cams in groups:
        if note:
            lines.append(f"! {note} -> {acl_in or '-'} / {acl_out or '-'}")
        if do_in and acl_in:
            lines.append(f"ip access-list extended {acl_in}")
            lines.append(f"    remark IN: cameras -> {pc_ip}")
            for cam in cams:
                emit(f"permit ip host {cam} host {pc_ip}")
        if do_out and acl_out:
            lines.append(f"ip access-list extended {acl_out}")
            lines.append(f"    remark OUT: {pc_ip} -> cameras")
            for cam in cams:
                emit(f"permit ip host {pc_ip} host {cam}")
    return "\n".join(lines) + "\n"
