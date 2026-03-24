# Warzone - offline Wi-Fi Map
<img width="1536" height="1024" alt="warzone" src="https://github.com/user-attachments/assets/930eec6d-7f70-4d32-b4de-e0a9093b6541" />

<p align="center">
  Build a clean, high-contrast Wi-Fi intelligence map from raw Wigle logs.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-1f6feb?style=for-the-badge" alt="Python 3.10+" />
  <img src="https://img.shields.io/badge/Map-Folium-0b7285?style=for-the-badge" alt="Folium" />
  <img src="https://img.shields.io/badge/Data-Pandas-364fc7?style=for-the-badge" alt="Pandas" />
  <img src="https://img.shields.io/badge/Format-Wigle%20.log-2f9e44?style=for-the-badge" alt="Wigle log format" />
</p>

## Why This Project Exists

This script was created because I did not want to publish Wi-Fi data from my own neighborhood to public internet services.

It was inspired by the Pygle utility from Evil-M5Project:
[Pygle by 7h30th3r0n3](https://github.com/7h30th3r0n3/Evil-M5Project/tree/main/utilities/Pygle)

That project gave me a great starting point, but I wanted additional workflow features such as:

- `wpa-sec` integration
- `whitelist` support
- easier filtering focused on open networks

## Why This Repo Hits Hard

<img src="https://github.com/user-attachments/assets/0c1c1673-8e0d-424a-8227-c4c48e075e0d" width="75%">

- Imports `.log` files from `logs/` and generates `wifi_map.html`.
- Groups networks by point, adds status colors, crack/open/secured split, and fast SSID search.
- Includes optional `wpa-sec` enrichment and SSID whitelist filtering.
- Auto-checks dependencies (`folium`, `pandas`) and offers one-shot install.

## Direct Wigle Compatibility

You can drop logs directly from popular projects/devices that export the common Wigle format, including:

- [projectZero](https://github.com/C5Lab/projectZero) (JanOS based)
- [MonsterC5](https://github.com/C5Lab/M5MonsterC5-CardputerADV)
- [ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder)

No conversion step required, as long as the source uses the standard Wigle log structure.

## Quick Start

```bash
python3 warzone.py
```

If `wifi_map.html` was created earlier by root and you hit a permission error. So You need to remove it first

```bash
sudo python3 warzone.py
```

Check resoults:

```bash
wifi_map.html
```

## Project Layout

```text
.
|-- warzone.py
|-- logs/
|-- whitelist.txt
|-- wpa-sec.founds.potfile
`-- wifi_map.html
```

## Optional Inputs

### `whitelist.txt`

- One SSID per line.
- Matching SSIDs are ignored on map output.
- Empty lines and lines starting with `#` are skipped.

### `wpa-sec.founds.potfile`

- Keep the file next to `warzone.py`.
- Expected format: `BSSID:CLIENT:SSID:PASSWORD`.
- Matching networks are marked as cracked on the map.

## Dependency Handling

On startup, the script verifies `folium` and `pandas`.
If missing, it prompts `Y/n` and can install dependencies automatically into a local virtual environment.
