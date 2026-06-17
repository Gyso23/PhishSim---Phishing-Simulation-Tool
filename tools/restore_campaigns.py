"""
Restore utility for PhishSim campaign backups.

This script will extract the DB copy from a backup zip produced by `tools/backup_campaigns.py` and
write it to a destination path (by default `data/campaigns_restored_<ts>.db`).

Usage:
  python tools/restore_campaigns.py backups/campaigns_backup_20230101T000000Z.zip
  python tools/restore_campaigns.py backups/mybackup.zip --to data/campaigns_restored.db

If you want to replace the live DB, pass --replace-live but be careful (you should stop the app first).
"""
import argparse
from pathlib import Path
import zipfile
from datetime import datetime
import shutil

DEFAULT_OUT_DIR = Path('data')


def extract_db_from_zip(zip_path: Path, dest_path: Path, replace_live=False):
    if not zip_path.exists():
        raise FileNotFoundError(f"Backup not found: {zip_path}")

    with zipfile.ZipFile(zip_path, 'r') as zf:
        # Find a file that looks like campaigns_db_*.db
        db_candidates = [n for n in zf.namelist() if n.endswith('.db')]
        if not db_candidates:
            raise RuntimeError('No DB copy found in archive')
        db_name = db_candidates[0]
        print(f"Found DB archive entry: {db_name}")

        with zf.open(db_name) as src, open(dest_path, 'wb') as dst:
            shutil.copyfileobj(src, dst)

    return dest_path


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Restore PhishSim DB from backup zip')
    parser.add_argument('zipfile', help='Backup zip file produced by tools/backup_campaigns.py')
    parser.add_argument('--to', help='Destination DB file path (default: data/campaigns_restored_<ts>.db)')
    parser.add_argument('--replace-live', action='store_true', help='Replace the live DB (data/campaigns.db) - dangerous!')
    args = parser.parse_args()

    zip_path = Path(args.zipfile)
    ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    out_default = DEFAULT_OUT_DIR / f'campaigns_restored_{ts}.db'
    dest = Path(args.to) if args.to else out_default

    if args.replace_live:
        confirm = input('Are you sure you want to replace the live DB at data/campaigns.db? Type YES to continue: ')
        if confirm != 'YES':
            print('Aborted by user')
            raise SystemExit(1)
        dest = Path('data/campaigns.db')

    dest.parent.mkdir(parents=True, exist_ok=True)

    try:
        restored = extract_db_from_zip(zip_path, dest)
        print(f"Restored DB written to: {restored}")
        print('You can point the application to this DB or inspect it with sqlite3/browser tools.')
    except Exception as e:
        print(f"Failed to restore DB: {e}")
        raise
