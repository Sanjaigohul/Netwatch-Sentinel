"""
run.py – NIDS Sentinel main entry point

Usage
─────
  # Quick start (simulation, no dataset needed):
  python run.py

  # Train on one dataset then start:
  python run.py --train --datasets cicids2017:/data/CICIDS2017

  # Train on multiple datasets:
  python run.py --train \\
      --datasets cicids2017:/data/CIC,nslkdd:/data/NSL,unswnb15:/data/UNSW

  # Train only (don't start server):
  python run.py --train-only --datasets auto:/data/my_data.csv

  # Live capture (requires root):
  sudo python run.py --live
"""

import sys, os, argparse, logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  [%(name)s]  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("nids")

ap = argparse.ArgumentParser(description="NIDS Sentinel",
                             formatter_class=argparse.RawDescriptionHelpFormatter,
                             epilog=__doc__)
ap.add_argument("--live",        action="store_true", help="Live Scapy capture (needs root)")
ap.add_argument("--train",       action="store_true", help="Train models before starting")
ap.add_argument("--train-only",  action="store_true", help="Train and exit (no server)")
ap.add_argument("--datasets",    type=str, default="",
                help="Comma-separated type:path pairs. Types: cicids2017,nslkdd,unswnb15,cicddos2019,kddcup99,custom,auto")
ap.add_argument("--synthetic",   action="store_true", help="Force include synthetic data alongside real")
ap.add_argument("--no-synthetic",action="store_true", help="Use real datasets only (skip synthetic)")
ap.add_argument("--max-rows",    type=int, default=150_000, help="Max rows per dataset file")
ap.add_argument("--xgb",         action="store_true", help="Use XGBoost classifier")
ap.add_argument("--host",        type=str, default="0.0.0.0")
ap.add_argument("--port",        type=int, default=5000)
ap.add_argument("--debug",       action="store_true")
args = ap.parse_args()

# ── Config overrides ──────────────────────────────────────────────────────────
from config import Config
Config.SIMULATION_MODE = not args.live
Config.HOST  = args.host
Config.PORT  = args.port
Config.DEBUG = args.debug

# ── Parse dataset specs ───────────────────────────────────────────────────────
specs: list[tuple[str, str]] = []
for token in args.datasets.split(","):
    token = token.strip()
    if not token:
        continue
    if ":" in token:
        dtype, path = token.split(":", 1)
        specs.append((dtype.strip().lower(), path.strip()))
    else:
        specs.append(("auto", token))

inc_syn = True
if args.no_synthetic and specs:
    inc_syn = False
if args.synthetic:
    inc_syn = True

# ── Train ─────────────────────────────────────────────────────────────────────
if args.train or args.train_only:
    logger.info("=" * 60)
    logger.info("Training mode")
    if specs:
        logger.info(f"Datasets: {specs}")
    else:
        logger.info("No datasets specified – using synthetic data")
    logger.info("=" * 60)

    from backend.train.train_all import train_all
    train_all(
        dataset_specs=specs,
        include_synthetic=inc_syn,
        max_rows_per_ds=args.max_rows,
        use_xgb=args.xgb,
    )

    if args.train_only:
        logger.info("Training complete. Exiting (--train-only).")
        sys.exit(0)

# ── Start server ──────────────────────────────────────────────────────────────
from backend.app import app, socketio, start_system

logger.info("=" * 60)
logger.info("  NIDS Sentinel – Starting")
logger.info(f"  Mode    : {'SIMULATION' if Config.SIMULATION_MODE else 'LIVE CAPTURE'}")
logger.info(f"  URL     : http://{args.host}:{args.port}")
logger.info(f"  Login   : admin / nids@2024")
logger.info("=" * 60)

start_system()
socketio.run(app, host=Config.HOST, port=Config.PORT,
             debug=Config.DEBUG, use_reloader=False,
             allow_unsafe_werkzeug=True)
