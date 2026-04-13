"""
CloudGuard Pro CSPM v3 — pytest configuration with detailed logging
"""
import logging
import os
import sys

# Point to in-memory DB for tests
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["SEED_DEMO_DATA"] = "false"
os.environ["LOG_DIR"] = "/tmp/cloudguard_test_logs"

# Detailed logging during tests
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)-8s %(name)-40s %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ]
)
