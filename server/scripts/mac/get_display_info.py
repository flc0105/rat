#!/usr/bin/env python3
import subprocess


def main():
    result = subprocess.run(['system_profiler', 'SPDisplaysDataType'], capture_output=True, text=True)
    lines = result.stdout.split('\n')

    displays = []
    current = {}
    for line in lines:
        line = line.strip()
        if line.startswith('Graphics/Displays:'):
            continue
        if ':' in line:
            key, val = line.split(':', 1)
            key = key.strip()
            val = val.strip()
            if key == 'Resolution':
                current['resolution'] = val
            elif key == 'Retina':
                current['retina'] = val
            elif key == 'Display Type':
                current['type'] = val
            elif key == 'VRAM (Total)':
                current['vram'] = val
            elif key == 'Vendor':
                current['vendor'] = val
            elif line.startswith('    ') and not current:
                current['name'] = key if not key.startswith('    ') else line.strip()

    print(f"Display: {current.get('name', 'Unknown')}")
    print(f"Type: {current.get('type', 'Unknown')}")
    print(f"Resolution: {current.get('resolution', 'Unknown')}")
    print(f"Retina: {current.get('retina', 'No')}")
    print(f"VRAM: {current.get('vram', 'Unknown')}")
    print(f"Vendor: {current.get('vendor', 'Unknown')}")


if __name__ == '__main__':
    main()