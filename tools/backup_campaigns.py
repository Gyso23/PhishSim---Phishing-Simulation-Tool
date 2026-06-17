"""
Backup utility for PhishSim campaign data.

This script will:
 - Copy the original SQLite DB (default: data/campaigns.db) into backups/
 - Export each table as a JSON file into a timestamped temporary directory
 - Create a zip archive containing the DB copy and JSON table dumps

Usage:
  python tools/backup_campaigns.py            # uses default data/campaigns.db
  python tools/backup_campaigns.py --db other.db --out backups/mybackup.zip

"""
import sqlite3
import json
import argparse
from pathlib import Path
import shutil
from datetime import datetime
import zipfile
import tempfile

DEFAULT_DB = Path('data/campaigns.db')
BACKUP_DIR = Path('backups')


def list_tables(conn):
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
    return [r[0] for r in cur.fetchall()]


def dump_table_to_json(conn, table, out_path):
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM {table}")
    cols = [c[0] for c in cur.description]
    rows = cur.fetchall()
    data = [dict(zip(cols, row)) for row in rows]
    with open(out_path, 'w', encoding='utf-8') as fh:
        json.dump(data, fh, default=str, indent=2)
    return len(data)


def make_backup(db_path: Path, out_zip: Path = None):
    if not db_path.exists():
        raise FileNotFoundError(f"DB not found: {db_path}")

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    if out_zip is None:
        out_zip = BACKUP_DIR / f'campaigns_backup_{ts}.zip'

    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        # Copy DB file
        db_copy = td_path / f'campaigns_db_{ts}.db'
        shutil.copy2(db_path, db_copy)

        # Open connection to source DB and dump tables
        conn = sqlite3.connect(str(db_path))
        try:
            tables = list_tables(conn)
            counts = {}
            tables_dir = td_path / 'tables'
            tables_dir.mkdir(parents=True, exist_ok=True)

            for t in tables:
                out_file = tables_dir / f'{t}.json'
                n = dump_table_to_json(conn, t, out_file)
                counts[t] = n
        finally:
            conn.close()

        # Create zip
        with zipfile.ZipFile(out_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
            # add db copy
            zf.write(db_copy, arcname=db_copy.name)
            # add JSON dumps
            for f in (tables_dir).glob('*.json'):
                zf.write(f, arcname=f'tables/{f.name}')

    return out_zip, counts


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Backup PhishSim campaign DB and tables')
    parser.add_argument('--db', default=str(DEFAULT_DB), help='Path to SQLite DB to backup')
    parser.add_argument('--out', help='Output zip file path (default: backups/campaigns_backup_<ts>.zip)')
    args = parser.parse_args()

    db_path = Path(args.db)
    out_zip = Path(args.out) if args.out else None

    try:
        zpath, counts = make_backup(db_path, out_zip)
        print(f"Backup created: {zpath}")
        print("Table row counts:")
        for t, n in counts.items():
            print(f"  - {t}: {n}")
    except Exception as e:
        print(f"Failed to create backup: {e}")
        raise
