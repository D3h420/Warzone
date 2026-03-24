from __future__ import annotations

import argparse
import html
import importlib
import json
import os
import subprocess
import sys
from pathlib import Path

REQUIRED_PACKAGES = {
    "folium": "folium",
    "pandas": "pandas",
}

COLUMNS = [
    "MAC",
    "SSID",
    "AuthMode",
    "FirstSeen",
    "Channel",
    "RSSI",
    "CurrentLatitude",
    "CurrentLongitude",
    "AltitudeMeters",
    "AccuracyMeters",
    "Type",
]

# Fields after AuthMode are stable in Wigle logs, while SSID can contain commas.
TAIL_FIELDS_COUNT = 8
POINT_COORD_DECIMALS = 6

folium = None
pd = None


def ensure_dependencies() -> tuple[object, object]:
    project_dir = Path(__file__).resolve().parent
    venv_dir = project_dir / ".warzone_venv"
    python_bin = venv_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    running_in_target_venv = Path(sys.prefix).resolve() == venv_dir.resolve()

    # If the local virtualenv is ready, prefer it silently for future runs.
    if not running_in_target_venv and python_bin.exists():
        check_venv = subprocess.run(
            [str(python_bin), "-c", "import folium, pandas"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if check_venv.returncode == 0:
            os.execv(str(python_bin), [str(python_bin), *sys.argv])

    missing: list[str] = []
    for module_name, package_name in REQUIRED_PACKAGES.items():
        try:
            importlib.import_module(module_name)
        except ModuleNotFoundError:
            missing.append(package_name)

    if missing:
        print(f"Missing packages: {', '.join(missing)}")
        answer = input("Install them automatically and continue? [Y/n]: ").strip().lower()
        if answer not in ("", "y", "yes"):
            raise SystemExit("Canceled by user.")

        try:
            if not python_bin.exists():
                subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True)
            subprocess.run([str(python_bin), "-m", "pip", "install", "--upgrade", "pip"], check=True)
            subprocess.run([str(python_bin), "-m", "pip", "install", *missing], check=True)
        except (OSError, subprocess.CalledProcessError):
            packages = " ".join(missing)
            raise SystemExit(
                "Automatic dependency install failed.\n"
                f"Install manually and run again: python3 -m pip install {packages}"
            )

        if not running_in_target_venv:
            print("Restarting in local virtual environment...")
            os.execv(str(python_bin), [str(python_bin), *sys.argv])

    folium_module = importlib.import_module("folium")
    pandas_module = importlib.import_module("pandas")
    return folium_module, pandas_module


def read_text_with_fallback(path: Path) -> str:
    data = path.read_bytes()
    for encoding in ("utf-8", "cp1250", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def parse_wigle_line(line: str) -> dict[str, str] | None:
    parts = [fragment.strip() for fragment in line.strip().split(",")]
    if len(parts) < len(COLUMNS):
        return None

    tail = parts[-TAIL_FIELDS_COUNT:]
    left = parts[:-TAIL_FIELDS_COUNT]
    if len(left) < 3:
        return None

    return {
        "MAC": left[0],
        "SSID": ",".join(left[1:-1]).strip(),
        "AuthMode": left[-1],
        "FirstSeen": tail[0],
        "Channel": tail[1],
        "RSSI": tail[2],
        "CurrentLatitude": tail[3],
        "CurrentLongitude": tail[4],
        "AltitudeMeters": tail[5],
        "AccuracyMeters": tail[6],
        "Type": tail[7],
    }


def parse_log_file(path: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    lines = read_text_with_fallback(path).splitlines()
    if len(lines) < 3:
        return rows

    for line in lines[2:]:
        if not line.strip():
            continue
        parsed = parse_wigle_line(line)
        if parsed is None:
            continue
        parsed["SourceFile"] = path.name
        rows.append(parsed)
    return rows


def normalize_ssid(value: str) -> str:
    return value.strip().casefold()


def normalize_mac(value: str) -> str:
    cleaned = "".join(char for char in value if char.isalnum())
    if len(cleaned) == 12:
        return cleaned.casefold()
    return ""


def load_whitelist(path: Path) -> set[str]:
    if not path.exists():
        path.write_text(
            "# One Wi-Fi name (SSID) per line.\n"
            "# Empty lines and lines starting with # are ignored.\n",
            encoding="utf-8",
        )
        return set()

    names: set[str] = set()
    for line in read_text_with_fallback(path).splitlines():
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        names.add(normalize_ssid(item))
    return names


def load_cracked_potfile(path: Path) -> tuple[set[str], set[str]]:
    cracked_ssids: set[str] = set()
    cracked_bssids: set[str] = set()
    if not path.exists():
        return cracked_ssids, cracked_bssids

    for raw_line in read_text_with_fallback(path).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":", 3)
        if len(parts) < 4:
            continue

        bssid_raw, _client_raw, ssid_raw, _password_raw = parts
        bssid = normalize_mac(bssid_raw)
        ssid = normalize_ssid(ssid_raw)
        if bssid:
            cracked_bssids.add(bssid)
        if ssid:
            cracked_ssids.add(ssid)
    return cracked_ssids, cracked_bssids


def network_key(ssid: str, mac: str) -> str:
    cleaned_ssid = ssid.strip()
    if cleaned_ssid:
        return f"ssid:{normalize_ssid(cleaned_ssid)}"
    return f"mac:{mac.strip().casefold()}"


def is_open_network(auth_mode: str) -> bool:
    value = auth_mode.strip().casefold()
    return ("open" in value) or (value in {"", "none", "[]"})


def marker_radius(rssi: float) -> float:
    # Keep marker size compact and readable.
    clamped = max(-90.0, min(-45.0, float(rssi)))
    ratio = (clamped + 90.0) / 45.0
    return round(4.3 + ratio * 1.9, 2)


def stacked_point_radius(network_count: int) -> float:
    # Radius for one marker that represents many networks in the same coordinates.
    return round(4.6 + min(5.4, max(0, network_count - 1) * 0.22), 2)


def build_networks_dataframe(
    log_dir: Path, whitelist: set[str], cracked_ssids: set[str], cracked_bssids: set[str]
) -> tuple[object, int]:
    all_rows: list[dict[str, str]] = []
    for log_file in sorted(log_dir.glob("*.log")):
        all_rows.extend(parse_log_file(log_file))

    if not all_rows:
        return pd.DataFrame(), 0

    df = pd.DataFrame(all_rows)
    for column in ("CurrentLatitude", "CurrentLongitude", "RSSI", "AltitudeMeters", "AccuracyMeters", "Channel"):
        df[column] = pd.to_numeric(df[column], errors="coerce")

    df = df.dropna(subset=["CurrentLatitude", "CurrentLongitude", "RSSI"])
    df = df[
        (df["CurrentLatitude"].between(-90, 90))
        & (df["CurrentLongitude"].between(-180, 180))
        & (df["CurrentLatitude"] != 0)
        & (df["CurrentLongitude"] != 0)
    ]

    if df.empty:
        return pd.DataFrame(), 0

    df["SSID"] = df["SSID"].fillna("").astype(str).str.strip()
    df["AuthMode"] = df["AuthMode"].fillna("").astype(str).str.strip()
    df["Type"] = df["Type"].fillna("WIFI").astype(str).str.strip()

    skipped_by_whitelist = 0
    if whitelist:
        keep_mask = ~df["SSID"].map(normalize_ssid).isin(whitelist)
        skipped_by_whitelist = int((~keep_mask).sum())
        df = df[keep_mask].copy()

    if df.empty:
        return pd.DataFrame(), skipped_by_whitelist

    df["IsOpen"] = df["AuthMode"].map(is_open_network)
    df["NetworkKey"] = df.apply(lambda row: network_key(str(row["SSID"]), str(row["MAC"])), axis=1)

    strongest_networks = (
        df.sort_values(by=["RSSI", "AccuracyMeters", "FirstSeen"], ascending=[False, True, True], na_position="last")
        .drop_duplicates(subset=["NetworkKey"], keep="first")
        .copy()
    )
    strongest_networks["MarkerRadius"] = strongest_networks["RSSI"].map(marker_radius)
    strongest_networks["IsCracked"] = strongest_networks.apply(
        lambda row: (
            normalize_ssid(str(row["SSID"])) in cracked_ssids
            or normalize_mac(str(row["MAC"])) in cracked_bssids
        ),
        axis=1,
    )
    return strongest_networks, skipped_by_whitelist


def add_dashboard(map_object: object, networks_df: object, map_name: str) -> None:
    total_networks = len(networks_df)
    open_networks = int(networks_df["IsOpen"].sum())
    cracked_networks = int(networks_df["IsCracked"].sum())
    # "Secured" includes cracked networks. "Cracked" is a subset for visibility.
    secured_networks = int((~networks_df["IsOpen"]).sum())
    search_df = networks_df.copy()
    search_df["PointLat"] = search_df["CurrentLatitude"].round(POINT_COORD_DECIMALS)
    search_df["PointLon"] = search_df["CurrentLongitude"].round(POINT_COORD_DECIMALS)

    point_counts = (
        search_df.groupby(["PointLat", "PointLon"], as_index=False)
        .agg(PointNetworks=("NetworkKey", "count"))
        .copy()
    )

    search_df = search_df[search_df["SSID"].astype(str).str.strip() != ""].copy()
    search_entries: list[dict[str, object]] = []
    if not search_df.empty:
        search_df["_SSIDNorm"] = search_df["SSID"].map(normalize_ssid)
        search_df = (
            search_df.sort_values(by=["RSSI", "FirstSeen"], ascending=[False, True], na_position="last")
            .drop_duplicates(subset=["_SSIDNorm"], keep="first")
            .merge(point_counts, on=["PointLat", "PointLon"], how="left")
        )

        for _, row in search_df.iterrows():
            if bool(row["IsCracked"]):
                status = "cracked"
            elif bool(row["IsOpen"]):
                status = "open"
            else:
                status = "secured"

            search_entries.append(
                {
                    "ssid": str(row["SSID"]),
                    "ssid_norm": normalize_ssid(str(row["SSID"])),
                    "lat": float(row["PointLat"]),
                    "lon": float(row["PointLon"]),
                    "point_networks": int(row["PointNetworks"]) if pd.notna(row["PointNetworks"]) else 1,
                    "status": status,
                }
            )

    search_entries.sort(key=lambda item: str(item["ssid"]).casefold())
    suggestion_options = "".join(
        f"<option value=\"{html.escape(str(item['ssid']))}\"></option>" for item in search_entries
    )
    search_payload = json.dumps(search_entries, ensure_ascii=False)
    search_hint = (
        f"Indexed SSIDs: {len(search_entries)}"
        if search_entries
        else "No visible SSID names available for search."
    )

    stats_html = f"""
    <style>
      .warzone-panel {{
        position: fixed;
        top: 14px;
        left: 14px;
        z-index: 9999;
        width: 284px;
        border-radius: 12px;
        background: linear-gradient(150deg, rgba(8, 14, 26, 0.92), rgba(24, 9, 38, 0.86));
        backdrop-filter: blur(8px) saturate(125%);
        box-shadow:
          0 0 0 1px rgba(125, 249, 255, 0.2),
          0 12px 28px rgba(0, 0, 0, 0.45),
          0 0 22px rgba(188, 19, 254, 0.18);
        padding: 11px 13px;
        font-family: "Avenir Next", "Segoe UI", sans-serif;
        color: #dbe4f3;
      }}
      .warzone-title {{
        margin: 0 0 6px 0;
        font-size: 18px;
        letter-spacing: 0.04em;
        font-weight: 600;
        color: #95f8ff;
      }}
      .warzone-row {{
        margin: 2px 0;
        font-size: 15px;
        line-height: 1.25;
        color: #ecf2ff;
      }}
      .warzone-legend {{
        margin-top: 8px;
        border-top: 1px solid rgba(149, 248, 255, 0.22);
        padding-top: 8px;
        font-size: 14px;
        line-height: 1.3;
        color: #d6def0;
      }}
      .warzone-filters {{
        margin-top: 9px;
        border-top: 1px solid rgba(149, 248, 255, 0.2);
        padding-top: 8px;
      }}
      .warzone-filter-row {{
        display: flex;
        gap: 6px;
      }}
      .warzone-filter-btn {{
        flex: 1;
        border-radius: 8px;
        border: 1px solid rgba(125, 249, 255, 0.32);
        background: rgba(9, 30, 49, 0.88);
        color: #d9ecff;
        font-size: 12px;
        font-weight: 600;
        padding: 7px 8px;
        cursor: pointer;
        transition: filter 0.18s ease, transform 0.18s ease;
      }}
      .warzone-filter-btn:hover {{
        filter: brightness(1.08);
      }}
      .warzone-filter-btn:active {{
        transform: translateY(1px);
      }}
      .warzone-filter-btn.is-active {{
        color: #0b1d2d;
      }}
      .warzone-filter-btn--cracked.is-active {{
        border-color: #8defff;
        background: linear-gradient(165deg, #8befff, #42daff);
        box-shadow: 0 0 10px rgba(79, 232, 255, 0.32);
      }}
      .warzone-filter-btn--open.is-active {{
        border-color: #95ffce;
        background: linear-gradient(165deg, #8dffc8, #3ee58f);
        box-shadow: 0 0 10px rgba(62, 229, 143, 0.28);
      }}
      .warzone-filter-status {{
        margin-top: 6px;
        min-height: 1.2em;
        font-size: 12px;
        color: #8fa6c9;
      }}
      .warzone-search {{
        margin-top: 9px;
        border-top: 1px solid rgba(149, 248, 255, 0.18);
        padding-top: 8px;
      }}
      .warzone-search-label {{
        display: block;
        font-size: 12px;
        letter-spacing: 0.03em;
        color: #9cd6e7;
        margin-bottom: 5px;
      }}
      .warzone-search-row {{
        display: flex;
        gap: 6px;
      }}
      .warzone-search-input {{
        flex: 1;
        min-width: 0;
        border-radius: 8px;
        border: 1px solid rgba(125, 249, 255, 0.28);
        background: rgba(3, 11, 23, 0.9);
        color: #f3f8ff;
        padding: 7px 8px;
        outline: none;
        font-size: 13px;
      }}
      .warzone-search-input::placeholder {{
        color: #7e93b6;
      }}
      .warzone-search-input:focus {{
        border-color: rgba(125, 249, 255, 0.7);
        box-shadow: 0 0 0 2px rgba(79, 232, 255, 0.15);
      }}
      .warzone-search-btn {{
        border-radius: 8px;
        border: 1px solid rgba(125, 249, 255, 0.42);
        background: linear-gradient(165deg, rgba(0, 130, 170, 0.74), rgba(42, 165, 220, 0.75));
        color: #e8fbff;
        font-size: 12px;
        font-weight: 600;
        padding: 0 10px;
        cursor: pointer;
      }}
      .warzone-search-btn:hover {{
        filter: brightness(1.08);
      }}
      .warzone-search-status {{
        margin-top: 6px;
        min-height: 1.2em;
        font-size: 12px;
        color: #8fa6c9;
      }}
      .dot {{
        display: inline-block;
        width: 9px;
        height: 9px;
        border-radius: 99px;
        margin-right: 6px;
      }}
      .warzone-point-wrapper {{
        background: transparent !important;
        border: 0 !important;
      }}
      .warzone-marker {{
        transition: opacity 0.16s ease;
      }}
      .warzone-point {{
        position: relative;
        display: flex;
        align-items: center;
        justify-content: center;
        border-radius: 999px;
        border: 2px solid;
        box-sizing: border-box;
        font-family: "Avenir Next", "Segoe UI", sans-serif;
        font-weight: 700;
        user-select: none;
      }}
      .warzone-point-count {{
        line-height: 1;
        text-align: center;
      }}
      .warzone-point-badge {{
        position: absolute;
        top: -5px;
        right: -5px;
        width: 14px;
        height: 14px;
        border-radius: 999px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 9px;
        background: rgba(3, 20, 30, 0.96);
        border: 1px solid #7be9ff;
        color: #92f4ff;
        box-shadow: 0 0 10px rgba(76, 230, 255, 0.55);
      }}
      .warzone-point--secured {{
        color: #ffe9ee;
        border-color: #ff9fb1;
        background: radial-gradient(circle at 35% 28%, #ff7b99 0%, #ff3f66 60%, #b40b31 100%);
        box-shadow:
          0 0 0 1px rgba(34, 4, 10, 0.75),
          0 0 10px rgba(255, 74, 108, 0.5);
      }}
      .warzone-point--open {{
        color: #eafff2;
        border-color: #9dffd2;
        background: radial-gradient(circle at 35% 28%, #5bff9c 0%, #1fe27d 62%, #0a8b47 100%);
        box-shadow:
          0 0 0 1px rgba(3, 20, 13, 0.72),
          0 0 10px rgba(40, 242, 133, 0.5);
      }}
      .warzone-point--cracked {{
        color: #052130;
        border-color: #ccf6ff;
        background: radial-gradient(circle at 35% 28%, #b8f8ff 0%, #49ddff 58%, #0073a8 100%);
        box-shadow:
          0 0 0 1px rgba(2, 17, 24, 0.76),
          0 0 12px rgba(70, 226, 255, 0.65);
      }}
      .leaflet-popup-content-wrapper {{
        background: rgba(7, 11, 20, 0.97);
        color: #e8eef9;
        border: 1px solid rgba(125, 249, 255, 0.22);
        box-shadow: 0 12px 32px rgba(0, 0, 0, 0.55);
      }}
      .leaflet-popup-tip {{
        background: rgba(7, 11, 20, 0.97);
      }}
    </style>
    <div class="warzone-panel">
      <p class="warzone-title">Warzone Wi-Fi Map</p>
      <p class="warzone-row"><b>Networks:</b> {total_networks}</p>
      <p class="warzone-row"><b>Cracked:</b> {cracked_networks}</p>
      <div class="warzone-legend">
        <div><span class="dot" style="background:#40e67e;"></span> Open: {open_networks}</div>
        <div><span class="dot" style="background:#ff4a4a;"></span> Secured: {secured_networks}</div>
        <div><span class="dot" style="background:#4fe8ff;"></span> Cracked: {cracked_networks} (🔓)</div>
      </div>
      <div class="warzone-filters">
        <label class="warzone-search-label">Map Filters</label>
        <div class="warzone-filter-row">
          <button id="warzone-filter-cracked" class="warzone-filter-btn warzone-filter-btn--cracked" type="button" aria-pressed="false">Cracked</button>
          <button id="warzone-filter-open" class="warzone-filter-btn warzone-filter-btn--open" type="button" aria-pressed="false">Open</button>
        </div>
        <div id="warzone-filter-status" class="warzone-filter-status">Filter: all markers</div>
      </div>
      <div class="warzone-search">
        <label class="warzone-search-label" for="warzone-search-input">Find Network (SSID)</label>
        <div class="warzone-search-row">
          <input id="warzone-search-input" class="warzone-search-input" list="warzone-search-list" placeholder="Type SSID..." autocomplete="off"/>
          <button id="warzone-search-btn" class="warzone-search-btn" type="button">Find</button>
        </div>
        <datalist id="warzone-search-list">{suggestion_options}</datalist>
        <div id="warzone-search-status" class="warzone-search-status">{search_hint}</div>
      </div>
    </div>
    <script>
      (function() {{
        const SEARCH_DATA = {search_payload};
        const MAP_VAR_NAME = "{map_name}";
        const input = document.getElementById("warzone-search-input");
        const button = document.getElementById("warzone-search-btn");
        const status = document.getElementById("warzone-search-status");
        const crackedFilterButton = document.getElementById("warzone-filter-cracked");
        const openFilterButton = document.getElementById("warzone-filter-open");
        const filterStatus = document.getElementById("warzone-filter-status");
        if (!input || !button || !status || !crackedFilterButton || !openFilterButton || !filterStatus) {{
          return;
        }}
        const mapFilters = {{ cracked: false, open: false }};

        const searchByName = new Map();
        for (const item of SEARCH_DATA) {{
          searchByName.set(item.ssid_norm, item);
        }}

        const markerPassesFilters = (markerEl) => {{
          if (!mapFilters.cracked && !mapFilters.open) {{
            return true;
          }}
          const hasCracked = markerEl.classList.contains("warzone-marker--has-cracked");
          const isAllOpen = markerEl.classList.contains("warzone-marker--all-open");
          if (mapFilters.cracked && mapFilters.open) {{
            return hasCracked || isAllOpen;
          }}
          if (mapFilters.cracked) {{
            return hasCracked;
          }}
          return isAllOpen;
        }};

        const updateFilterButtons = () => {{
          crackedFilterButton.classList.toggle("is-active", mapFilters.cracked);
          crackedFilterButton.setAttribute("aria-pressed", mapFilters.cracked ? "true" : "false");
          openFilterButton.classList.toggle("is-active", mapFilters.open);
          openFilterButton.setAttribute("aria-pressed", mapFilters.open ? "true" : "false");
        }};

        const applyMarkerFilters = () => {{
          const markerElements = document.querySelectorAll(".warzone-marker");
          let totalMarkers = 0;
          let visibleMarkers = 0;
          markerElements.forEach((markerEl) => {{
            totalMarkers += 1;
            const shouldShow = markerPassesFilters(markerEl);
            markerEl.style.opacity = shouldShow ? "1" : "0";
            markerEl.style.visibility = shouldShow ? "visible" : "hidden";
            markerEl.style.pointerEvents = shouldShow ? "" : "none";
            if (shouldShow) {{
              visibleMarkers += 1;
            }}
          }});

          let filterLabel = "all markers";
          if (mapFilters.cracked && mapFilters.open) {{
            filterLabel = "cracked or open";
          }} else if (mapFilters.cracked) {{
            filterLabel = "cracked only";
          }} else if (mapFilters.open) {{
            filterLabel = "open only";
          }}
          filterStatus.textContent = `Filter: ${{filterLabel}} · showing ${{visibleMarkers}}/${{totalMarkers}} points`;
        }};

        const toggleFilter = (kind) => {{
          mapFilters[kind] = !mapFilters[kind];
          updateFilterButtons();
          applyMarkerFilters();
        }};

        const findEntry = (query) => {{
          const normalized = query.trim().toLowerCase();
          if (!normalized) {{
            return null;
          }}
          if (searchByName.has(normalized)) {{
            return searchByName.get(normalized);
          }}
          for (const entry of SEARCH_DATA) {{
            if (entry.ssid_norm.includes(normalized)) {{
              return entry;
            }}
          }}
          return null;
        }};

        const openPointPopup = (mapObj, entry) => {{
          mapObj.setView([entry.lat, entry.lon], Math.max(mapObj.getZoom(), 17), {{ animate: true }});
          let match = null;
          mapObj.eachLayer((layer) => {{
            if (match || !layer.getLatLng) {{
              return;
            }}
            const ll = layer.getLatLng();
            if (Math.abs(ll.lat - entry.lat) < 0.0000006 && Math.abs(ll.lng - entry.lon) < 0.0000006) {{
              match = layer;
            }}
          }});
          if (match && match.openPopup) {{
            window.setTimeout(() => match.openPopup(), 140);
          }}
        }};

        const runSearch = (mapObj) => {{
          const entry = findEntry(input.value);
          if (!entry) {{
            status.textContent = input.value.trim() ? "SSID not found on map." : "{search_hint}";
            return;
          }}
          status.textContent = `${{entry.ssid}} · ${{entry.status}} · point networks: ${{entry.point_networks}}`;
          openPointPopup(mapObj, entry);
        }};

        const bind = () => {{
          const mapObj = window[MAP_VAR_NAME];
          if (!mapObj) {{
            window.setTimeout(bind, 120);
            return;
          }}
          if (input.dataset.bound === "1") {{
            return;
          }}
          input.dataset.bound = "1";
          updateFilterButtons();
          crackedFilterButton.addEventListener("click", () => toggleFilter("cracked"));
          openFilterButton.addEventListener("click", () => toggleFilter("open"));
          button.addEventListener("click", () => runSearch(mapObj));
          input.addEventListener("change", () => runSearch(mapObj));
          input.addEventListener("keydown", (event) => {{
            if (event.key === "Enter") {{
              event.preventDefault();
              runSearch(mapObj);
            }}
          }});
          mapObj.on("zoomend", applyMarkerFilters);
          mapObj.on("moveend", applyMarkerFilters);
          window.setTimeout(applyMarkerFilters, 120);
        }};

        bind();
      }})();
    </script>
    """
    map_object.get_root().html.add_child(folium.Element(stats_html))


def build_point_popup(group_df: object) -> str:
    sorted_group = group_df.sort_values(
        by=["IsCracked", "IsOpen", "RSSI", "SSID"], ascending=[False, False, False, True]
    )
    total = len(sorted_group)
    open_count = int(sorted_group["IsOpen"].sum())
    cracked_count = int(sorted_group["IsCracked"].sum())
    secured_count = total - open_count

    rows_html: list[str] = []
    max_rows = 120
    for _, row in sorted_group.head(max_rows).iterrows():
        ssid = row["SSID"] if row["SSID"] else "(hidden SSID)"
        if bool(row["IsCracked"]):
            icon = "🔓"
            sec = "<span style='color:#67ebff; font-weight:700;'>Cracked</span>"
            icon_dot = "#4fe8ff"
        elif bool(row["IsOpen"]):
            icon = "●"
            sec = "<span style='color:#48f39a; font-weight:700;'>Open</span>"
            icon_dot = "#40e67e"
        else:
            icon = "🔒"
            sec = "<span style='color:#ff708f; font-weight:700;'>Secured</span>"
            icon_dot = "#ff4a6a"

        channel = int(row["Channel"]) if pd.notna(row["Channel"]) else "-"
        rows_html.append(
            "<tr>"
            "<td style='padding:2px 6px 2px 0; white-space:nowrap;'>"
            f"<span style='color:{icon_dot};'>{icon}</span>"
            "</td>"
            f"<td style='padding:2px 6px 2px 0;'>{html.escape(str(ssid))}</td>"
            f"<td style='padding:2px 6px; text-align:right;'>{int(row['RSSI'])}</td>"
            f"<td style='padding:2px 0 2px 6px;'>{sec}</td>"
            f"<td style='padding:2px 0 2px 10px; color:#9fb3d9;'>{channel}</td>"
            "</tr>"
        )

    more_count = total - max_rows
    more_html = (
        f"<div style='margin-top:6px; color:#9fb3d9;'>... and {more_count} more networks</div>"
        if more_count > 0
        else ""
    )

    return (
        "<div style=\"font-family:'Avenir Next','Segoe UI',sans-serif; font-size:12px; line-height:1.3;\">"
        f"<div style='font-size:13px; font-weight:600; margin-bottom:4px;'>Point networks: {total}</div>"
        f"<div style='margin-bottom:6px;'>Open: {open_count} | Secured: {secured_count} | Cracked: {cracked_count}</div>"
        "<div style='max-height:220px; overflow:auto; border-top:1px solid rgba(125,249,255,0.2); padding-top:6px;'>"
        "<table style='border-collapse:collapse; width:100%;'>"
        "<thead><tr>"
        "<th style='text-align:left; padding-right:6px;'>•</th>"
        "<th style='text-align:left;'>SSID</th>"
        "<th style='text-align:right;'>RSSI</th>"
        "<th style='text-align:left; padding-left:6px;'>Type</th>"
        "<th style='text-align:left; padding-left:10px; color:#9fb3d9;'>Ch</th>"
        "</tr></thead>"
        f"<tbody>{''.join(rows_html)}</tbody>"
        "</table>"
        f"{more_html}"
        "</div>"
        "</div>"
    )


def build_map(networks_df: object) -> object:
    center_lat = networks_df["CurrentLatitude"].mean()
    center_lon = networks_df["CurrentLongitude"].mean()
    map_object = folium.Map(
        location=[center_lat, center_lon],
        zoom_start=13,
        tiles="CartoDB dark_matter",
        prefer_canvas=True,
    )

    point_df = networks_df.copy()
    point_df["PointLat"] = point_df["CurrentLatitude"].round(POINT_COORD_DECIMALS)
    point_df["PointLon"] = point_df["CurrentLongitude"].round(POINT_COORD_DECIMALS)

    for (point_lat, point_lon), group in point_df.groupby(["PointLat", "PointLon"], sort=False):
        network_count = len(group)
        open_count = int(group["IsOpen"].sum())
        cracked_count = int(group["IsCracked"].sum())

        if cracked_count > 0:
            marker_class = "warzone-point warzone-point--cracked"
        elif open_count == network_count:
            marker_class = "warzone-point warzone-point--open"
        else:
            marker_class = "warzone-point warzone-point--secured"

        popup_content = build_point_popup(group)
        marker_size = int(round(stacked_point_radius(network_count) * 3.6))
        marker_size = max(17, min(36, marker_size))
        font_size = 10 if network_count < 10 else 9 if network_count < 100 else 8
        cracked_badge = "<span class='warzone-point-badge'>🔓</span>" if cracked_count > 0 else ""
        marker_html = (
            f"<div class='{marker_class}' style='width:{marker_size}px; height:{marker_size}px;'>"
            f"<span class='warzone-point-count' style='font-size:{font_size}px;'>{network_count}</span>"
            f"{cracked_badge}</div>"
        )
        wrapper_classes = ["warzone-point-wrapper", "warzone-marker"]
        if open_count > 0:
            wrapper_classes.append("warzone-marker--has-open")
        if open_count == network_count:
            wrapper_classes.append("warzone-marker--all-open")
        if cracked_count > 0:
            wrapper_classes.append("warzone-marker--has-cracked")
        tooltip = folium.Tooltip(
            f"Networks: {network_count} | Open: {open_count} | Cracked: {cracked_count}",
            sticky=True,
        )

        folium.Marker(
            location=[float(point_lat), float(point_lon)],
            icon=folium.DivIcon(
                html=marker_html,
                icon_size=(marker_size, marker_size),
                icon_anchor=(marker_size // 2, marker_size // 2),
                class_name=" ".join(wrapper_classes),
            ),
            z_index_offset=450 + network_count,
            popup=folium.Popup(popup_content, max_width=460),
            tooltip=tooltip,
        ).add_to(map_object)

    add_dashboard(map_object, networks_df, map_object.get_name())
    return map_object


def main() -> None:
    global folium
    global pd
    folium, pd = ensure_dependencies()

    parser = argparse.ArgumentParser(description="Build a Wi-Fi map from Wigle log files.")
    parser.add_argument("--logs-dir", default="logs", help="Directory containing .log files (default: logs)")
    parser.add_argument("--whitelist", default="whitelist.txt", help="Whitelist file with SSIDs to ignore")
    parser.add_argument("--potfile", default="wpa-sec.founds.potfile", help="Potfile with cracked Wi-Fi credentials")
    parser.add_argument("--output", default="wifi_map.html", help="Output HTML file path")
    args = parser.parse_args()

    logs_dir = Path(args.logs_dir)
    if not logs_dir.exists() or not logs_dir.is_dir():
        raise SystemExit(f"Logs directory not found: {logs_dir}")

    whitelist_path = Path(args.whitelist)
    whitelist = load_whitelist(whitelist_path)
    potfile_path = Path(args.potfile)
    cracked_ssids, cracked_bssids = load_cracked_potfile(potfile_path)

    networks_df, skipped_by_whitelist = build_networks_dataframe(
        logs_dir, whitelist, cracked_ssids, cracked_bssids
    )
    if networks_df.empty:
        raise SystemExit("No valid Wi-Fi records left after filtering.")

    wifi_map = build_map(networks_df)
    output_path = Path(args.output)
    try:
        wifi_map.save(output_path.as_posix())
    except PermissionError:
        raise SystemExit(
            f"No permission to write {output_path}. "
            "Run with sudo or remove/replace the existing file created by root."
        )

    open_networks = int(networks_df["IsOpen"].sum())
    cracked_networks = int(networks_df["IsCracked"].sum())
    secured_networks = int((~networks_df["IsOpen"]).sum())
    print(f"Done: map saved to {output_path}")
    print(
        f"Networks: {len(networks_df)} | "
        f"Open: {open_networks} | Cracked: {cracked_networks} | "
        f"Secured: {secured_networks} | Whitelist skipped: {skipped_by_whitelist}"
    )


if __name__ == "__main__":
    main()
