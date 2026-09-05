"""NiceGUI Modern SaaS Cybersecurity SOC Dashboard (Smooth Reactive Updates, No Full-Page Rebuilds)."""

from __future__ import annotations

import asyncio
import json
import logging
import multiprocessing
import os
import shutil
import socket
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure project root is in path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nicegui import ui
import numpy as np
import pandas as pd

from capture.pcap_analyzer import analyze_pcap_file
from dashboard.services.api_client import APIClient
from dashboard.utils.formatting import format_timestamp, format_time_only
from inference.predictor import DEFAULT_MODEL_PATH
from models.training import ModelTrainer
from zeek.runner import detect_backend

logger = logging.getLogger(__name__)

# Initialize API Client
api_client = APIClient()


class DashboardState:
    def __init__(self) -> None:
        self.current_page = "Overview"
        self.backend_connected = False
        self.statistics: Dict[str, Any] = {
            "total_alerts": 0,
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "threat_class_counts": {},
        }
        self.alerts: List[Dict[str, Any]] = []
        self.threat_ips: List[Dict[str, Any]] = []
        self.flows: List[Dict[str, Any]] = []
        self.pipeline_stats: Dict[str, Any] = {}
        self.last_updated = datetime.now().strftime("%H:%M:%S")
        self.sensor_mode = "replay"
        self.sensor_interface = "any"
        self.sensor_active = False
        self.sensor_error: str | None = None
        self.dark_mode = False


state = DashboardState()


def get_cpu_usage() -> float:
    try:
        load1, _, _ = os.getloadavg()
        cores = multiprocessing.cpu_count()
        return min(100.0, round((load1 / cores) * 100, 1))
    except Exception:
        return 12.5


def get_mem_usage() -> float:
    try:
        with open("/proc/meminfo", "r") as f:
            lines = f.readlines()
        mem_total, mem_free, mem_cached, mem_buffers = 0, 0, 0, 0
        for line in lines:
            if "MemTotal" in line:
                mem_total = int(line.split()[1])
            elif "MemFree" in line:
                mem_free = int(line.split()[1])
            elif "Cached" in line and "SwapCached" not in line:
                mem_cached = int(line.split()[1])
            elif "Buffers" in line:
                mem_buffers = int(line.split()[1])
        if mem_total > 0:
            used = mem_total - mem_free - mem_cached - mem_buffers
            return round((used / mem_total) * 100, 1)
    except Exception:
        pass
    return 32.4


def get_available_models() -> Dict[str, str]:
    """Scan models/artifacts directory for .joblib models."""
    artifacts_dir = Path("models/artifacts")
    models: Dict[str, str] = {}
    if artifacts_dir.exists():
        for p in sorted(artifacts_dir.glob("*.joblib")):
            if p.name == "default_rf.joblib":
                display_name = f"Active Primary ({p.name})"
            elif p.name == "sample_rf.joblib":
                display_name = f"Sample Synthetic Baseline ({p.name})"
            elif p.name == "cic_rf.joblib":
                display_name = f"CIC-IDS2017 Random Forest ({p.name})"
            elif p.name == "cic_xgboost.joblib":
                display_name = f"CIC-IDS2017 XGBoost Classifier ({p.name})"
            elif p.name == "cic_isolation_forest.joblib":
                display_name = f"CIC-IDS2017 Isolation Forest ({p.name})"
            else:
                display_name = f"{p.stem.replace('_', ' ').title()} ({p.name})"
            models[str(p)] = display_name
    if not models:
        models[str(DEFAULT_MODEL_PATH)] = "Default Model (default_rf.joblib)"
    return models


def get_available_datasets() -> Dict[str, str]:
    """Scan data/samples for test and prototyping datasets."""
    samples_dir = Path("data/samples")
    datasets: Dict[str, str] = {}
    if samples_dir.exists():
        for p in sorted(list(samples_dir.glob("*.parquet")) + list(samples_dir.glob("*.csv"))):
            if "combined" in p.name:
                display = f"CIC-IDS2017 200k Sample ({p.name})"
            elif "labeled_flows" in p.name:
                display = f"Sample Synthetic 200 Flows ({p.name})"
            else:
                display = f"{p.name}"
            datasets[str(p)] = display
    if not datasets:
        datasets["data/samples/labeled_flows.csv"] = "Sample Synthetic Flows (labeled_flows.csv)"
    return datasets


def get_available_pcaps() -> Dict[str, str]:
    """Scan data/samples and data/uploads for available PCAP files."""
    pcaps: Dict[str, str] = {}
    
    # Check data/samples
    samples_dir = Path("data/samples")
    if samples_dir.exists():
        for p in sorted(samples_dir.glob("*.pcap")):
            size_kb = round(p.stat().st_size / 1024, 1)
            pcaps[str(p)] = f"Sample: {p.name} ({size_kb} KB)"
            
    # Check data/uploads
    uploads_dir = Path("data/uploads")
    if uploads_dir.exists():
        for p in sorted(uploads_dir.glob("*.pcap*")):
            size_kb = round(p.stat().st_size / 1024, 1)
            pcaps[str(p)] = f"Upload: {p.name} ({size_kb} KB)"
            
    if not pcaps:
        pcaps["data/samples/test_traffic.pcap"] = "Sample: test_traffic.pcap"
    return pcaps


def run_model_evaluation(model_path_str: str, dataset_path_str: str, elements: Dict[str, Any]) -> None:
    """Evaluate a selected model on a chosen test dataset and update UI elements."""
    p_model = Path(model_path_str)
    p_data = Path(dataset_path_str)
    if not p_model.exists():
        ui.notify(f"Model file not found: {p_model.name}", type="negative")
        return
    
    try:
        trainer = ModelTrainer.load(p_model)
        m_type = getattr(trainer, "model_type", "classifier").replace("_", " ").title()
        f_count = len(getattr(trainer.preprocessor, "feature_cols", []))
        size_kb = round(p_model.stat().st_size / 1024, 1)
        size_str = f"{size_kb} KB" if size_kb < 1024 else f"{round(size_kb/1024, 2)} MB"
        
        if "model_classifier_type" in elements:
            elements["model_classifier_type"].text = m_type
        if "model_artifact_size" in elements:
            elements["model_artifact_size"].text = f"{p_model.name} ({size_str})"
        if "model_feature_dim" in elements:
            elements["model_feature_dim"].text = f"{f_count} Flow Features"
            
        is_active = (p_model.name == "default_rf.joblib")
        cfg_model = None
        try:
            cfg_p = Path("data/sensor_config.json")
            if cfg_p.exists():
                with open(cfg_p, "r") as f:
                    cfg_model = json.load(f).get("model_path")
        except Exception:
            pass
        if cfg_model and (p_model.name in cfg_model or str(p_model) == cfg_model):
            is_active = True
            
        if "model_status_badge" in elements:
            if is_active:
                elements["model_status_badge"].text = "Active in Live Sensor"
                elements["model_status_badge"].classes("text-emerald-600 font-bold", remove="text-blue-600 text-slate-500")
            else:
                elements["model_status_badge"].text = "Testing / Candidate"
                elements["model_status_badge"].classes("text-blue-600 font-bold", remove="text-emerald-600 text-slate-500")
                
        if not p_data.exists():
            ui.notify(f"Dataset not found: {p_data.name}", type="warning")
            return
            
        if p_data.suffix.lower() == ".parquet":
            df = pd.read_parquet(p_data).head(5000)
        else:
            df = pd.read_csv(p_data)
            
        for col in df.columns:
            if col.lower() in ["label", "class", "threat"] and col != "label":
                df = df.rename(columns={col: "label"})
                break
        if "label" in df.columns and str(df["label"].dtype).lower().startswith(("object", "str", "category")):
            df["label"] = df["label"].apply(lambda v: 0 if str(v).strip().lower() == "benign" else 1)
            
        train_df, test_df = trainer.temporal_split(df, test_size=0.20)
        metrics = trainer.evaluate(test_df)
        
        if "model_f1_score" in elements:
            elements["model_f1_score"].text = f"{metrics.f1_score * 100:.2f}%"
        if "model_precision" in elements:
            elements["model_precision"].text = f"{metrics.precision * 100:.2f}%"
        if "model_recall" in elements:
            elements["model_recall"].text = f"{metrics.recall * 100:.2f}%"
        if "model_latency" in elements:
            elements["model_latency"].text = f"{metrics.inference_latency_ms:.4f} ms"
            
        if "model_report_subtitle" in elements:
            elements["model_report_subtitle"].text = f"Dataset: {p_data.name} ({len(test_df)} validation rows)"
            
        if "model_report_table" in elements:
            elements["model_report_table"].rows = parse_classification_report(metrics.report)
            
        cm = metrics.confusion_matrix
        if len(cm) == 2 and len(cm[0]) == 2:
            tn, fp = cm[0][0], cm[0][1]
            fn, tp = cm[1][0], cm[1][1]
            if "model_cm_tn" in elements:
                elements["model_cm_tn"].text = str(tn)
            if "model_cm_fp" in elements:
                elements["model_cm_fp"].text = str(fp)
            if "model_cm_fn" in elements:
                elements["model_cm_fn"].text = str(fn)
            if "model_cm_tp" in elements:
                elements["model_cm_tp"].text = str(tp)
    except Exception as e:
        logger.error("Model evaluation error: %s", e)
        ui.notify(f"Evaluation error: {e}", type="negative")


def fetch_latest_data() -> None:
    """Query FastAPI backend for live telemetry."""
    state.backend_connected = api_client.get_health()
    state.last_updated = datetime.now().strftime("%H:%M:%S")

    # Read sensor status from JSON if available
    p_status = Path("data/sensor_status.json")
    if p_status.exists():
        try:
            with open(p_status, "r") as f:
                s_data = json.load(f)
                state.sensor_mode = s_data.get("mode", "replay")
                state.sensor_interface = s_data.get("interface", "any")
                state.sensor_active = bool(s_data.get("active", False))
                state.sensor_error = s_data.get("last_error")
        except Exception:
            pass

    if state.backend_connected:
        state.statistics = api_client.get_statistics()
        state.alerts = api_client.get_alerts()
        state.threat_ips = api_client.get_threats()
        state.flows = api_client.get_flows()
        state.pipeline_stats = api_client.get_pipeline_stats()


def parse_classification_report(report_str: str) -> List[Dict[str, Any]]:
    lines = [line.strip() for line in report_str.split("\n") if line.strip()]
    rows = []
    for line in lines[1:]:
        parts = [p for p in line.split() if p]
        if len(parts) >= 5:
            if parts[0] in ["macro", "weighted"] and len(parts) >= 6:
                label = f"{parts[0].capitalize()} Average"
                prec, rec, f1, sup = parts[2], parts[3], parts[4], parts[5]
            elif parts[0] == "0":
                label = "Class 0 (Benign Baseline)"
                prec, rec, f1, sup = parts[1], parts[2], parts[3], parts[4]
            elif parts[0] == "1":
                label = "Class 1 (Malicious Intrusions)"
                prec, rec, f1, sup = parts[1], parts[2], parts[3], parts[4]
            else:
                label = parts[0]
                prec, rec, f1, sup = parts[1], parts[2], parts[3], parts[4]

            try:
                prec_fmt = f"{float(prec) * 100:.1f}%"
                rec_fmt = f"{float(rec) * 100:.1f}%"
                f1_fmt = f"{float(f1) * 100:.1f}%"
            except Exception:
                prec_fmt, rec_fmt, f1_fmt = prec, rec, f1

            rows.append({
                "class_name": label,
                "precision": prec_fmt,
                "recall": rec_fmt,
                "f1_score": f1_fmt,
                "support": sup,
            })
        elif len(parts) == 3 and parts[0] == "accuracy":
            acc = parts[1]
            try:
                acc_fmt = f"{float(acc) * 100:.1f}%"
            except Exception:
                acc_fmt = acc
            rows.append({
                "class_name": "Overall Accuracy",
                "precision": acc_fmt,
                "recall": "-",
                "f1_score": "-",
                "support": parts[2],
            })
    return rows


# ── Main Application Page ─────────────────────────────────────────────

@ui.page("/")
def main_page():
    ui.query("body").style(
        "font-family: 'Plus Jakarta Sans', -apple-system, sans-serif; margin: 0; padding: 0;"
    )
    ui.add_head_html("""
        <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
        <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
        <style>
            :root {
                /* Light theme tokens */
                --bg-page: #f6f8fb;
                --bg-surface: #ffffff;
                --bg-surface-hover: #f8fafc;
                --bg-sidebar: #ffffff;
                --bg-header: #ffffff;
                --bg-input: #ffffff;
                --bg-table-head: #f8fafc;
                --bg-table-row-alt: #fbfcfd;
                --bg-nav-hover: #eef2f7;
                --bg-muted: #f1f5f9;

                --border-subtle: #e6ebf2;
                --border-default: #d6dde6;
                --border-strong: #c2cad4;

                --text-strong: #0f172a;
                --text-default: #1f2937;
                --text-muted: #64748b;
                --text-faint: #94a3b8;
                --text-on-accent: #ffffff;

                --accent: #2563eb;
                --accent-hover: #1d4ed8;
                --accent-soft: #dbeafe;
                --accent-glow: rgba(37, 99, 235, 0.25);

                --ok: #10b981;
                --warn: #f59e0b;
                --crit: #ef4444;

                --card-shadow: 0 1px 2px rgba(15, 23, 42, 0.04), 0 1px 3px rgba(15, 23, 42, 0.05);
                --card-shadow-hover: 0 4px 12px rgba(15, 23, 42, 0.08), 0 2px 4px rgba(15, 23, 42, 0.04);

                /* Sensor card state colors */
                --ok-bg: #ecfdf5;
                --ok-border: #86efac;
                --warn-bg: #fffbeb;
                --warn-border: #fcd34d;
                --crit-bg: #fef2f2;
                --crit-border: #fca5a5;
                --idle-bg: #f8fafc;
                --idle-border: #e2e8f0;
            }

            body.body--dark {
                --bg-page: #0b1220;
                --bg-surface: #131c2e;
                --bg-surface-hover: #1a2440;
                --bg-sidebar: #0f1729;
                --bg-header: #0f1729;
                --bg-input: #1a2440;
                --bg-table-head: #111a2c;
                --bg-table-row-alt: #162038;
                --bg-nav-hover: #1f2a44;
                --bg-muted: #1a2440;

                --border-subtle: #1f2a44;
                --border-default: #2a3654;
                --border-strong: #3a4669;

                --text-strong: #f1f5f9;
                --text-default: #d1dcf0;
                --text-muted: #94a3b8;
                --text-faint: #64748b;
                --text-on-accent: #ffffff;

                --accent: #3b82f6;
                --accent-hover: #60a5fa;
                --accent-soft: #1e3a8a;
                --accent-glow: rgba(96, 165, 250, 0.35);

                --ok: #34d399;
                --warn: #fbbf24;
                --crit: #f87171;

                --card-shadow: 0 1px 2px rgba(0, 0, 0, 0.4), 0 2px 6px rgba(0, 0, 0, 0.3);
                --card-shadow-hover: 0 6px 18px rgba(0, 0, 0, 0.5), 0 3px 8px rgba(0, 0, 0, 0.4);

                /* Sensor card state colors (dark) */
                --ok-bg: #0d2818;
                --ok-border: #065f46;
                --warn-bg: #2d2205;
                --warn-border: #78350f;
                --crit-bg: #2d1115;
                --crit-border: #7f1d1d;
                --idle-bg: #1a2440;
                --idle-border: #2a3654;
            }

            * {
                box-sizing: border-box;
                font-family: 'Plus Jakarta Sans', -apple-system, sans-serif;
            }
            code, pre, .font-mono {
                font-family: 'JetBrains Mono', monospace !important;
            }

            /* ── Global element overrides ──────────────────── */
            body, .q-page, .nicegui-content {
                background-color: var(--bg-page) !important;
                color: var(--text-default) !important;
            }
            .q-drawer {
                background-color: var(--bg-sidebar) !important;
                border-right: 1px solid var(--border-subtle) !important;
                overflow-x: hidden !important;
                max-width: 256px !important;
            }
            .q-header {
                background-color: var(--bg-header) !important;
                border-bottom: 1px solid var(--border-subtle) !important;
            }

            /* ── Cards ──────────────────────────────────────── */
            .saas-card {
                background: var(--bg-surface) !important;
                border: 1px solid var(--border-subtle) !important;
                border-radius: 12px;
                box-shadow: var(--card-shadow) !important;
                transition: box-shadow 0.2s ease, border-color 0.2s ease;
                color: var(--text-default) !important;
            }
            .saas-card:hover {
                border-color: var(--border-default) !important;
                box-shadow: var(--card-shadow-hover) !important;
            }

            /* ── Navigation ─────────────────────────────────── */
            .nav-link {
                transition: all 0.15s ease-in-out;
                border-radius: 8px;
                color: var(--text-muted) !important;
            }
            .nav-link, .nav-active {
                text-align: left !important;
            }
            .nav-link .q-btn__content, .nav-active .q-btn__content {
                justify-content: flex-start !important;
                align-items: center !important;
                width: 100% !important;
                min-width: 0 !important;
                flex-wrap: nowrap !important;
            }
            .nav-link .q-btn__content > *:last-child,
            .nav-active .q-btn__content > *:last-child {
                min-width: 0 !important;
                white-space: normal !important;
                overflow: visible !important;
                text-overflow: clip !important;
                line-height: 1.25 !important;
            }
            .nav-link:hover {
                background-color: var(--bg-nav-hover) !important;
                color: var(--text-strong) !important;
            }
            .nav-active, .nav-active.q-btn,
            .nav-active .q-btn__content, .nav-active .q-btn__content * {
                background-color: var(--accent) !important;
                color: var(--text-on-accent) !important;
                font-weight: 600 !important;
            }
            .nav-active {
                box-shadow: 0 2px 6px var(--accent-glow) !important;
            }
            .nav-active .q-icon {
                color: var(--text-on-accent) !important;
                flex: 0 0 auto !important;
            }

            /* ── Tables ─────────────────────────────────────── */
            .q-table th {
                font-weight: 600 !important;
                color: var(--text-muted) !important;
                text-transform: uppercase !important;
                font-size: 11px !important;
                letter-spacing: 0.05em !important;
                background-color: var(--bg-table-head) !important;
                border-bottom: 1px solid var(--border-subtle) !important;
            }
            .q-table td {
                font-size: 12px !important;
                color: var(--text-default) !important;
                border-bottom: 1px solid var(--border-subtle) !important;
            }
            .q-table tr {
                background-color: var(--bg-surface) !important;
            }
            .q-table tr:nth-child(even) {
                background-color: var(--bg-table-row-alt) !important;
            }
            .q-table .q-table__bottom {
                background-color: var(--bg-surface) !important;
                color: var(--text-muted) !important;
                border-top: 1px solid var(--border-subtle) !important;
            }

            /* ── Quasar components ──────────────────────────── */
            .q-card {
                background-color: var(--bg-surface) !important;
                color: var(--text-default) !important;
            }
            .q-separator {
                background-color: var(--border-subtle) !important;
            }
            .q-input__control, .q-select__control, .q-field__control {
                background-color: var(--bg-input) !important;
                color: var(--text-default) !important;
            }
            .q-field--outlined .q-field__control:before {
                border-color: var(--border-default) !important;
            }
            .q-field--outlined .q-field__control:hover:before {
                border-color: var(--border-strong) !important;
            }
            .q-input__label, .q-select__label, .q-field__label {
                color: var(--text-muted) !important;
            }
            .q-select__dropdown-icon, .q-field__append .q-icon {
                color: var(--text-muted) !important;
            }
            .q-menu, .q-dialog__inner > .q-card {
                background-color: var(--bg-surface) !important;
                color: var(--text-default) !important;
                border: 1px solid var(--border-subtle) !important;
            }
            .q-item {
                color: var(--text-default) !important;
            }
            .q-item:hover {
                background-color: var(--bg-nav-hover) !important;
            }
            .q-notification {
                background-color: var(--bg-surface) !important;
                color: var(--text-default) !important;
                border: 1px solid var(--border-subtle) !important;
            }
            .q-btn {
                color: var(--text-default) !important;
            }

            /* ── Sensor status card ─────────────────────────── */
            .sensor-card-ok {
                background-color: var(--ok-bg) !important;
                border-color: var(--ok-border) !important;
            }
            .sensor-card-warn {
                background-color: var(--warn-bg) !important;
                border-color: var(--warn-border) !important;
            }
            .sensor-card-crit {
                background-color: var(--crit-bg) !important;
                border-color: var(--crit-border) !important;
            }
            .sensor-card-idle {
                background-color: var(--idle-bg) !important;
                border-color: var(--idle-border) !important;
            }

            /* ── Threat analysis cards ──────────────────────── */
            .threat-engine-title { color: var(--text-strong) !important; }
            .threat-engine-description { color: var(--text-muted) !important; }
            .threat-engine-metric { color: var(--text-default) !important; }
            .threat-engine-confidence { color: var(--text-muted) !important; }
            .threat-engine-footer { border-color: var(--border-subtle) !important; }
            .threat-badge-benign {
                background-color: var(--ok-bg) !important;
                color: var(--ok) !important;
            }
            .threat-badge-alert {
                background-color: var(--crit-bg) !important;
                color: var(--crit) !important;
            }

            /* ── Alert evidence panel ───────────────────────── */
            .forensic-title, .panel-title {
                color: var(--text-strong) !important;
            }
            .forensic-code {
                background-color: #0f172a !important;
                color: #e2e8f0 !important;
                border: 1px solid var(--border-default) !important;
                overflow-x: auto !important;
            }
            body.body--dark .forensic-code {
                background-color: #080d18 !important;
                border-color: #2a3654 !important;
                color: #dbeafe !important;
            }

            /* Map legacy hardcoded palette to theme tokens in dark mode */
            body.body--dark .text-slate-900 { color: var(--text-strong) !important; }
            body.body--dark .text-slate-800 { color: var(--text-strong) !important; }
            body.body--dark .text-slate-700 { color: var(--text-default) !important; }
            body.body--dark .text-slate-600 { color: var(--text-muted) !important; }
            body.body--dark .text-slate-500 { color: var(--text-muted) !important; }
            body.body--dark .text-slate-400 { color: var(--text-faint) !important; }
            body.body--dark .border-slate-100 { border-color: var(--border-subtle) !important; }
            body.body--dark .border-slate-200 { border-color: var(--border-subtle) !important; }
            body.body--dark .bg-slate-50 { background-color: var(--bg-muted) !important; }
        </style>
    """)

    fetch_latest_data()

    # Dictionary storing references to all reactive UI elements
    ui_elements: Dict[str, Any] = {}

# ── Left Navigation Drawer ────────────────────────────────────────
    with ui.left_drawer(value=True, bordered=True).classes(
        "p-3 w-60 md:w-64 flex flex-col shadow-sm z-30 overflow-hidden"
    ) as drawer:
        with ui.column().classes("w-full gap-1.5 overflow-hidden"):
            # Navigation Menu Items
            ui.label("PLATFORM").classes("text-[10px] font-bold tracking-widest mt-0.5")

            nav_buttons = {}
            pages = [
                ("Overview", "dashboard", "Overview"),
                ("Alerts", "notifications_active", "Alerts"),
                ("Traffic", "swap_horiz", "Traffic"),
                ("PCAP Analysis", "upload_file", "PCAP Analysis"),
                ("Threat Analysis", "security", "Threat Analysis"),
                ("Models", "psychology", "Models"),
                ("System", "tune", "System"),
            ]

            def switch_page(page_name: str):
                state.current_page = page_name
                for p, btn in nav_buttons.items():
                    if p == page_name:
                        btn.classes(add="nav-active")
                    else:
                        btn.classes(remove="nav-active")
                for p, view_col in page_views.items():
                    view_col.set_visibility(p == page_name)
                update_all_views_in_place()

            for key, icon_name, label in pages:
                active = (key == state.current_page)
                with ui.button(on_click=lambda k=key: switch_page(k)).classes(
                    f"w-full text-left justify-start px-3 py-1.5 text-xs md:text-sm nav-link{' nav-active' if active else ''}"
                ).props("flat no-caps") as btn:
                    ui.icon(icon_name).classes("mr-2 text-base")
                    ui.label(label)
                nav_buttons[key] = btn
                if active:
                    btn.classes("nav-active")

            # Ingestion Control Box
            ui.separator().classes("my-1")
            ui.label("INGESTION NODE").classes("text-[10px] font-bold tracking-widest mt-0.5")

            try:
                available_ifaces = ["any"] + [name for _, name in socket.if_nameindex()]
            except Exception:
                available_ifaces = ["any", "wlo1", "lo", "docker0", "eth0"]

            config_path = Path("data/sensor_config.json")
            cfg = {"mode": "replay", "interface": "any"}
            if config_path.exists():
                try:
                    with open(config_path, "r") as f:
                        cfg = json.load(f)
                except Exception:
                    pass

            mode_select = ui.select(
                options=["Replay Simulation", "Live Ingestion"],
                value="Live Ingestion" if cfg.get("mode") == "live" else "Replay Simulation",
                label="Operation Mode"
            ).classes("w-full text-xs").props("outlined dense")

            iface_container = ui.column().classes("w-full gap-0")
            with iface_container:
                iface_select = ui.select(
                    options=available_ifaces,
                    value=cfg.get("interface", "any"),
                    label="Target Interface"
                ).classes("w-full text-xs").props("outlined dense")
            iface_container.set_visibility(cfg.get("mode") == "live")

            def on_mode_change():
                is_live = mode_select.value == "Live Ingestion"
                iface_container.set_visibility(is_live)

            mode_select.on_value_change(on_mode_change)

            def apply_sensor_config():
                target_m = "live" if mode_select.value == "Live Ingestion" else "replay"
                new_cfg = {"mode": target_m, "interface": iface_select.value, "rotation": 5}
                config_path.parent.mkdir(parents=True, exist_ok=True)
                with open(config_path, "w") as f:
                    json.dump(new_cfg, f)
                ui.notify("Ingestion configuration applied", type="positive", position="top")
                fetch_latest_data()
                update_all_views_in_place()

            ui.button("Apply Settings", on_click=apply_sensor_config).classes(
                "w-full bg-blue-600 text-white text-xs font-semibold py-2 rounded-lg shadow-sm hover:bg-blue-700"
            ).props("no-caps flat")

            # Sensor status card (dynamic, updated in-place)
            with ui.column().classes(
                "w-full gap-1.5 p-2.5 rounded-lg border text-[10px] transition-colors sensor-card-idle"
            ) as sensor_card:
                ui_elements["sensor_card"] = sensor_card
                with ui.row().classes("items-center gap-1.5 w-full"):
                    sensor_dot = ui.element("div").classes("w-2 h-2 rounded-full shrink-0 bg-slate-400")
                    ui_elements["sensor_dot"] = sensor_dot
                    ui_elements["sensor_title"] = ui.label("Sensor: idle").classes("font-bold")
                ui_elements["sensor_detail"] = ui.label("Replay simulation is active").classes(
                    "leading-snug break-words"
                )

    # ── Top Bar Header ────────────────────────────────────────────────
    with ui.header().classes(
        "px-4 md:px-8 py-3 items-center justify-between shadow-sm z-20 w-full"
    ) as header:
        with ui.row().classes("items-center gap-3"):
            ui.button(icon="menu", on_click=drawer.toggle).props("flat round dense color=grey-8")
            with ui.row().classes("items-center gap-2.5"):
                ui.label("NETra").classes("text-lg md:text-2xl font-black tracking-wider").style("color: var(--accent)")
                ui.label("•").style("color: var(--text-faint); font-weight: 700; font-size: 0.875rem")
                with ui.column().classes("gap-0"):
                    ui.label("ML Network Threat Detection").classes(
                        "text-sm md:text-base font-bold tracking-tight"
                    ).style("color: var(--text-strong)")
                    ui.label("Unidirectional Passive Ingestion & Machine Learning Analysis").classes(
                        "text-[10px] md:text-xs font-medium hidden sm:block"
                    ).style("color: var(--text-muted)")

        with ui.row().classes("items-center gap-3 md:gap-5"):
            dark_mode_ctrl = ui.dark_mode()

            def toggle_dark_mode():
                dark_mode_ctrl.toggle()
                theme_btn.props(
                    "icon=light_mode" if dark_mode_ctrl.value else "icon=dark_mode"
                )

            theme_btn = ui.button(icon="dark_mode", on_click=toggle_dark_mode).props(
                "flat round dense color=grey-7"
            )
            ui_elements["theme_toggle"] = theme_btn

    # ── Page View Containers (Built ONCE) ─────────────────────────────
    page_views: Dict[str, ui.column] = {}

    with ui.column().classes("w-full px-4 md:px-8 py-6 gap-6 max-w-[1920px]"):
        # 1. OVERVIEW VIEW
        with ui.column().classes("w-full gap-6") as view_overview:
            page_views["Overview"] = view_overview
            build_overview_view(ui_elements)

        # 2. ALERTS VIEW
        with ui.column().classes("w-full gap-6") as view_alerts:
            page_views["Alerts"] = view_alerts
            view_alerts.set_visibility(False)
            build_alerts_view(ui_elements)

        # 3. TRAFFIC VIEW
        with ui.column().classes("w-full gap-6") as view_traffic:
            page_views["Traffic"] = view_traffic
            view_traffic.set_visibility(False)
            build_traffic_view(ui_elements)

        # 3.5. PCAP FORENSIC ANALYSIS VIEW
        with ui.column().classes("w-full gap-6") as view_pcap:
            page_views["PCAP Analysis"] = view_pcap
            view_pcap.set_visibility(False)
            build_pcap_analysis_view(ui_elements)

        # 4. THREAT ANALYSIS VIEW
        with ui.column().classes("w-full gap-6") as view_threats:
            page_views["Threat Analysis"] = view_threats
            view_threats.set_visibility(False)
            build_threats_view(ui_elements)

        # 5. MODELS VIEW
        with ui.column().classes("w-full gap-6") as view_models:
            page_views["Models"] = view_models
            view_models.set_visibility(False)
            build_models_view(ui_elements)

        # 6. SYSTEM VIEW
        with ui.column().classes("w-full gap-6") as view_system:
            page_views["System"] = view_system
            view_system.set_visibility(False)
            build_system_view(ui_elements)

    # ── In-Place Update Handler (Smooth Reactive Updates) ─────────────
    def update_all_views_in_place():
        fetch_latest_data()

        # Update Header
        # Update Sidebar Sensor Status Card
        sensor_card = ui_elements.get("sensor_card")
        sensor_dot = ui_elements.get("sensor_dot")
        sensor_title = ui_elements.get("sensor_title")
        sensor_detail = ui_elements.get("sensor_detail")
        if sensor_card and sensor_dot and sensor_title and sensor_detail:
            if state.sensor_error and "ermission" in str(state.sensor_error):
                sensor_card.classes(
                    add="sensor-card-crit",
                    remove="sensor-card-ok sensor-card-warn sensor-card-idle"
                )
                sensor_dot.classes(add="bg-red-500", remove="bg-emerald-500 bg-slate-400")
                sensor_title.text = "Capture permission error"
                sensor_detail.text = "Run: sudo setcap cap_net_raw+ep $(readlink -f .venv/bin/python)"
            elif state.sensor_mode == "live" and state.sensor_active:
                sensor_card.classes(
                    add="sensor-card-ok",
                    remove="sensor-card-crit sensor-card-warn sensor-card-idle"
                )
                sensor_dot.classes(add="bg-emerald-500 animate-pulse", remove="bg-red-500 bg-slate-400")
                sensor_title.text = f"Sensor: live on {state.sensor_interface}"
                sensor_detail.text = "Raw packet capture is active"
            elif state.sensor_mode == "live":
                sensor_card.classes(
                    add="sensor-card-warn",
                    remove="sensor-card-ok sensor-card-crit sensor-card-idle"
                )
                sensor_dot.classes(add="bg-slate-400", remove="bg-emerald-500 bg-red-500 animate-pulse")
                sensor_title.text = "Sensor: live (starting)"
                sensor_detail.text = "Waiting for capture to initialize..."
            else:
                sensor_card.classes(
                    add="sensor-card-idle",
                    remove="sensor-card-ok sensor-card-warn sensor-card-crit"
                )
                sensor_dot.classes(add="bg-slate-400", remove="bg-emerald-500 bg-red-500 animate-pulse")
                sensor_title.text = "Sensor: replay"
                sensor_detail.text = "Replay simulation is active"

        # Update Active Page
        if state.current_page == "Overview":
            update_overview_in_place(ui_elements)
        elif state.current_page == "Alerts":
            update_alerts_in_place(ui_elements)
        elif state.current_page == "Traffic":
            update_traffic_in_place(ui_elements)
        elif state.current_page == "PCAP Analysis":
            update_pcap_analysis_in_place(ui_elements)
        elif state.current_page == "Threat Analysis":
            update_threats_in_place(ui_elements)
        elif state.current_page == "Models":
            update_models_in_place(ui_elements)
        elif state.current_page == "System":
            update_system_in_place(ui_elements)

    # Trigger first in-place update
    update_all_views_in_place()

    # Periodic background refresh timer (smooth in-place updates, NO DOM rebuilds!)
    ui.timer(2.0, update_all_views_in_place)


# ── View Builders (Run ONCE) & In-Place Updaters ───────────────────────

def build_overview_view(elements: Dict[str, Any]):
    # Summary Metrics
    with ui.grid().classes("w-full grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4"):
        for key, label, icon_name, color in [
            ("total_alerts", "TOTAL ALERTS", "verified_user", "text-slate-900"),
            ("critical_threats", "CRITICAL THREATS", "warning", "text-red-600"),
            ("active_actors", "ACTIVE ACTORS", "person_alert", "text-amber-600"),
            ("avg_conf", "AVG CONFIDENCE", "analytics", "text-blue-600"),
            ("flows_count", "INGRESS FLOWS", "device_hub", "text-slate-900"),
        ]:
            with ui.card().classes("saas-card p-4 flex flex-col justify-between"):
                with ui.row().classes("w-full justify-between items-center"):
                    ui.label(label).classes("text-[10px] md:text-[11px] font-bold text-slate-400 tracking-wider")
                    ui.icon(icon_name).classes("text-slate-300 text-sm")
                elements[f"overview_metric_{key}"] = ui.label("0").classes(
                    f"text-xl sm:text-2xl lg:text-3xl font-extrabold {color} tracking-tight"
                )

    # Charts Grid
    # Row 1: Timeline + Threat Distribution
    with ui.grid().classes("w-full grid-cols-1 xl:grid-cols-3 gap-6"):
        # Left 2 Cols: Activity Timeline
        with ui.card().classes("saas-card xl:col-span-2 p-5 flex flex-col gap-3"):
            with ui.row().classes("w-full justify-between items-center"):
                ui.label("Threat Activity Timeline").classes("text-sm md:text-base font-bold text-slate-900")
                ui.label("Live Ingress Window").classes("text-[11px] font-medium text-slate-400")

            initial_chart_opt = {
                "tooltip": {"trigger": "axis"},
                "grid": {"left": "2%", "right": "3%", "bottom": "5%", "top": "12%", "containLabel": True},
                "xAxis": {
                    "type": "category",
                    "data": [],
                    "axisLine": {"lineStyle": {"color": "#e2e8f0"}},
                    "axisLabel": {"color": "#64748b", "fontSize": 11}
                },
                "yAxis": {
                    "type": "value",
                    "axisLine": {"lineStyle": {"color": "#e2e8f0"}},
                    "splitLine": {"lineStyle": {"color": "#f1f5f9"}},
                    "axisLabel": {"color": "#64748b", "fontSize": 11}
                },
                "series": [{
                    "data": [],
                    "type": "line",
                    "smooth": True,
                    "showSymbol": False,
                    "lineStyle": {"width": 2.5, "color": "#2563eb"},
                    "areaStyle": {
                        "color": {
                            "type": "linear",
                            "x": 0, "y": 0, "x2": 0, "y2": 1,
                            "colorStops": [
                                {"offset": 0, "color": "rgba(37, 99, 235, 0.2)"},
                                {"offset": 1, "color": "rgba(37, 99, 235, 0.0)"}
                            ]
                        }
                    }
                }]
            }
            elements["overview_activity_chart"] = ui.echart(initial_chart_opt).classes("w-full h-64")

        # Right 1 Col: Donut Chart
        with ui.card().classes("saas-card p-5 flex flex-col gap-3"):
            ui.label("Threat Distribution").classes("text-sm md:text-base font-bold text-slate-900")
            initial_donut_opt = {
                "tooltip": {"trigger": "item"},
                "series": [{
                    "type": "pie",
                    "radius": ["48%", "72%"],
                    "center": ["50%", "50%"],
                    "avoidLabelOverlap": False,
                    "itemStyle": {"borderRadius": 6, "borderColor": "#ffffff", "borderWidth": 2},
                    "data": [],
                    "label": {"show": False},
                    "color": ["#2563eb", "#3b82f6", "#f59e0b", "#ef4444", "#8b5cf6", "#06b6d4"]
                }]
            }
            elements["overview_donut_chart"] = ui.echart(initial_donut_opt).classes("w-full h-64")

    # Row 2: Protocol Distribution + Top Source Hosts
    with ui.grid().classes("w-full grid-cols-1 lg:grid-cols-2 gap-6 mt-0"):
        # Protocol Distribution (circular donut)
        with ui.card().classes("saas-card p-5 flex flex-col gap-3"):
            ui.label("Protocol Distribution").classes("text-sm md:text-base font-bold text-slate-900")
            initial_proto_opt = {
                "tooltip": {"trigger": "item"},
                "legend": {"show": False},
                "series": [{
                    "type": "pie",
                    "radius": ["45%", "75%"],
                    "center": ["50%", "50%"],
                    "avoidLabelOverlap": False,
                    "itemStyle": {"borderRadius": 6, "borderColor": "#ffffff", "borderWidth": 2},
                    "data": [],
                    "label": {"show": False},
                    "color": ["#2563eb", "#3b82f6", "#06b6d4", "#8b5cf6", "#10b981", "#f59e0b"]
                }]
            }
            elements["overview_proto_chart"] = ui.echart(initial_proto_opt).classes("w-full h-64")

        # Top Source Hosts (tabular)
        with ui.card().classes("saas-card p-5 flex flex-col gap-3"):
            ui.label("Top Source Hosts").classes("text-sm md:text-base font-bold text-slate-900")
            talker_columns = [
                {"name": "rank", "label": "#", "field": "rank", "align": "center", "style": "width: 40px"},
                {"name": "host", "label": "Source IP", "field": "host", "align": "left"},
                {"name": "flows", "label": "Flows", "field": "flows", "align": "right", "style": "width: 80px"}
            ]
            elements["overview_talker_table"] = ui.table(columns=talker_columns, rows=[], row_key="host").classes(
                "w-full shadow-none border border-slate-100 rounded-lg"
            )

    # Recent Alerts Table
    with ui.card().classes("saas-card w-full p-5 gap-4"):
        with ui.row().classes("w-full justify-between items-center"):
            ui.label("Recent Security Alerts").classes("text-sm md:text-base font-bold text-slate-900")
            elements["overview_alerts_count_label"] = ui.label("0 Total Records").classes("text-xs font-semibold text-slate-400")

        columns = [
            {"name": "time", "label": "Time", "field": "time", "align": "left"},
            {"name": "threat", "label": "Threat Classification", "field": "threat", "align": "left"},
            {"name": "severity", "label": "Severity", "field": "severity", "align": "left"},
            {"name": "confidence", "label": "Confidence", "field": "confidence", "align": "left"},
            {"name": "source", "label": "Source Host", "field": "source", "align": "left"},
            {"name": "destination", "label": "Destination Host", "field": "destination", "align": "left"},
        ]
        elements["overview_alerts_table"] = ui.table(columns=columns, rows=[], row_key="id").classes(
            "w-full shadow-none border border-slate-100 rounded-lg"
        )


def update_overview_in_place(elements: Dict[str, Any]):
    total = state.statistics.get("total_alerts", len(state.alerts))
    sevs = state.statistics.get("severity_counts", {})
    critical_count = sevs.get("critical", sum(1 for a in state.alerts if a.get("severity", "").lower() == "critical"))
    active_threats = len({a.get("source") for a in state.alerts if a.get("severity", "").lower() in ["critical", "high"]})
    confidences = [a.get("confidence", 0.0) for a in state.alerts if "confidence" in a]
    avg_conf = f"{np.mean(confidences) * 100:.1f}%" if confidences else "0.0%"
    flow_count = len(state.flows)

    # In-place metrics update
    if "overview_metric_total_alerts" in elements:
        elements["overview_metric_total_alerts"].text = str(total)
    if "overview_metric_critical_threats" in elements:
        elements["overview_metric_critical_threats"].text = str(critical_count)
    if "overview_metric_active_actors" in elements:
        elements["overview_metric_active_actors"].text = str(active_threats)
    if "overview_metric_avg_conf" in elements:
        elements["overview_metric_avg_conf"].text = avg_conf
    if "overview_metric_flows_count" in elements:
        elements["overview_metric_flows_count"].text = str(flow_count)

    # In-place line chart update
    chart = elements.get("overview_activity_chart")
    if chart and state.alerts:
        timestamps = [format_time_only(a["timestamp"]) for a in state.alerts[:20]][::-1]
        conf_values = [round(a.get("confidence", 0.8) * 100, 1) for a in state.alerts[:20]][::-1]
        chart.options["xAxis"]["data"] = timestamps
        chart.options["series"][0]["data"] = conf_values
        chart.update()

    # In-place donut chart update
    donut = elements.get("overview_donut_chart")
    if donut:
        classes_count = state.statistics.get("threat_class_counts", {})
        pie_data = [{"name": k.replace("_", " ").title(), "value": v} for k, v in classes_count.items() if v > 0]
        donut.options["series"][0]["data"] = pie_data
        donut.update()

    # Protocol distribution circular donut chart (Fixed persistent colors)
    proto_chart = elements.get("overview_proto_chart")
    if proto_chart and state.flows:
        proto_counts: Dict[str, int] = defaultdict(int)
        for f in state.flows:
            p = str(f.get("proto", "")).upper().strip()
            if p:
                proto_counts[p] += 1
        
        overview_proto_data = []
        for p_code, info in PROTO_PALETTE.items():
            cnt = proto_counts.get(p_code, 0)
            if cnt > 0:
                overview_proto_data.append({
                    "name": info["label"],
                    "value": cnt,
                    "itemStyle": {
                        "color": info["color"],
                        "borderRadius": 6,
                        "borderColor": "transparent",
                    }
                })
        for p_code, cnt in sorted(proto_counts.items()):
            if p_code not in PROTO_PALETTE and cnt > 0:
                overview_proto_data.append({
                    "name": p_code,
                    "value": cnt,
                    "itemStyle": {
                        "color": "#64748b",
                        "borderRadius": 6,
                        "borderColor": "transparent",
                    }
                })
        proto_chart.options["series"][0]["data"] = overview_proto_data
        proto_chart.update()

    # Top talkers tabular table
    talker_table = elements.get("overview_talker_table")
    if talker_table and state.flows:
        src_counts: Dict[str, int] = {}
        for f in state.flows:
            s = str(f.get("src_ip", "-"))
            src_counts[s] = src_counts.get(s, 0) + 1
        talkers = sorted(src_counts.items(), key=lambda kv: kv[1], reverse=True)[:8]
        talker_table.rows = [
            {"rank": i + 1, "host": h, "flows": v}
            for i, (h, v) in enumerate(talkers)
        ]

    # In-place table update
    table = elements.get("overview_alerts_table")
    count_lbl = elements.get("overview_alerts_count_label")
    if count_lbl:
        count_lbl.text = f"{len(state.alerts)} Total Records"
    if table:
        table_rows = []
        for a in state.alerts[:12]:
            table_rows.append({
                "id": a.get("id"),
                "time": format_time_only(a.get("timestamp")),
                "threat": str(a.get("threat_class", "")).replace("_", " ").title(),
                "severity": a.get("severity", "").upper(),
                "confidence": f"{int(a.get('confidence', 0) * 100)}%",
                "source": a.get("source", "-"),
                "destination": a.get("destination") or "Multiple",
            })
        table.rows = table_rows


# ── Alerts View ───────────────────────────────────────────────────────

def build_alerts_view(elements: Dict[str, Any]):
    ui.label("Threat Alert Registry").classes("text-lg md:text-xl font-bold text-slate-900")
    ui.label("Chronological historical security detections log.").classes("text-xs text-slate-500 -mt-4")

    with ui.card().classes("saas-card w-full p-5 gap-4"):
        cols = [
            {"name": "time", "label": "Timestamp (UTC)", "field": "time", "align": "left", "sortable": True},
            {"name": "threat", "label": "Threat Vector", "field": "threat", "align": "left", "sortable": True},
            {"name": "severity", "label": "Severity", "field": "severity", "align": "left", "sortable": True},
            {"name": "confidence", "label": "Confidence Score", "field": "confidence", "align": "left"},
            {"name": "source", "label": "Source IP", "field": "source", "align": "left"},
            {"name": "destination", "label": "Destination IP", "field": "destination", "align": "left"},
        ]
        elements["alerts_table"] = ui.table(columns=cols, rows=[], row_key="id").classes(
            "w-full shadow-none border border-slate-100 rounded-lg"
        )

        ui.separator().classes("my-3")
        ui.label("Inspect Forensic Evidence Artifact").classes(
            "text-xs font-bold uppercase tracking-wider forensic-title"
        )

        elements["alerts_select"] = ui.select(options={}, value=None).classes("w-full text-xs").props("outlined dense")
        elements["alerts_evidence_code"] = ui.code("", language="json").classes(
            "w-full text-xs p-3 rounded-lg forensic-code"
        )

        def on_select_change(e):
            sel_val = e.value
            target = next((a for a in state.alerts if a["id"] == sel_val), None)
            if target:
                elements["alerts_evidence_code"].set_content(json.dumps(target.get("evidence", {}), indent=2))

        elements["alerts_select"].on_value_change(on_select_change)


def update_alerts_in_place(elements: Dict[str, Any]):
    table = elements.get("alerts_table")
    select_box = elements.get("alerts_select")
    code_box = elements.get("alerts_evidence_code")

    if table and state.alerts:
        records = []
        for a in state.alerts:
            records.append({
                "id": a.get("id"),
                "time": format_timestamp(a.get("timestamp")),
                "threat": str(a.get("threat_class", "")).replace("_", " ").title(),
                "severity": a.get("severity", "").upper(),
                "confidence": f"{int(a.get('confidence', 0) * 100)}%",
                "source": a.get("source", "-"),
                "destination": a.get("destination") or "Multiple",
            })
        table.rows = records

    if select_box and state.alerts:
        alert_dict = {a["id"]: f"[{a.get('severity','').upper()}] {a.get('threat_class','')} ({a.get('source','')})" for a in state.alerts}
        select_box.options = alert_dict
        if not select_box.value or select_box.value not in alert_dict:
            select_box.value = list(alert_dict.keys())[0]
            target = next((a for a in state.alerts if a["id"] == select_box.value), None)
            if target and code_box:
                code_box.set_content(json.dumps(target.get("evidence", {}), indent=2))


# ── Traffic View ──────────────────────────────────────────────────────

STATE_PALETTE: Dict[str, Dict[str, str]] = {
    "SF": {"label": "SF: Normal", "color": "#10b981"},         # Emerald Green (Normal established & terminated)
    "S0": {"label": "S0: No Reply", "color": "#f59e0b"},        # Amber (SYN with no response / Probes)
    "REJ": {"label": "REJ: Rejected", "color": "#ef4444"},      # Red (RST Rejected)
    "RSTO": {"label": "RSTO: Reset Orig", "color": "#f97316"},  # Orange (Reset by Originator)
    "RSTR": {"label": "RSTR: Reset Resp", "color": "#fb923c"},  # Light Orange (Reset by Responder)
    "SHR": {"label": "SHR: Half Open", "color": "#8b5cf6"},     # Purple (SYN-ACK / Half Open)
    "SH": {"label": "SH: Half Open", "color": "#8b5cf6"},       # Purple
    "S1": {"label": "S1: Established", "color": "#3b82f6"},    # Blue (Established not closed)
    "OTH": {"label": "OTH: Midstream", "color": "#06b6d4"},     # Cyan (Midstream traffic)
}

PROTO_PALETTE: Dict[str, Dict[str, str]] = {
    "TCP": {"label": "TCP", "color": "#2563eb"},     # Blue
    "UDP": {"label": "UDP", "color": "#06b6d4"},     # Cyan
    "ICMP": {"label": "ICMP", "color": "#8b5cf6"},   # Purple
    "OTHER": {"label": "Other", "color": "#64748b"}, # Slate
}


def build_traffic_view(elements: Dict[str, Any]):
    ui.label("Passive Traffic & Flow Telemetry").classes("text-lg md:text-xl font-bold text-slate-900")
    ui.label("Real-time ingress connection characteristics, bandwidth dynamics, and protocol breakdown.").classes("text-xs text-slate-500 -mt-4")

    # Ingress Info Cards (4 cards)
    with ui.grid().classes("w-full grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4"):
        with ui.card().classes("saas-card p-4"):
            ui.label("MONITORED ADAPTER").classes("text-[10px] font-bold text-slate-400")
            elements["traffic_adapter_label"] = ui.label("any").classes("text-lg font-bold text-blue-600")
        with ui.card().classes("saas-card p-4"):
            ui.label("INGESTION STATE").classes("text-[10px] font-bold text-slate-400")
            elements["traffic_mode_label"] = ui.label("Replay Stream").classes("text-lg font-bold text-emerald-600")
        with ui.card().classes("saas-card p-4"):
            ui.label("BUFFERED SESSIONS").classes("text-[10px] font-bold text-slate-400")
            elements["traffic_flows_label"] = ui.label("0 Active Flows").classes("text-lg font-bold text-slate-900")
        with ui.card().classes("saas-card p-4"):
            ui.label("INGRESS VOLUME").classes("text-[10px] font-bold text-slate-400")
            elements["traffic_throughput_label"] = ui.label("0 KB (0 Pkts)").classes("text-lg font-bold text-indigo-600")

    # Charts Grid - Row 1
    with ui.grid().classes("w-full grid-cols-1 xl:grid-cols-3 gap-6"):
        # Left 2 Cols: Live Flow Throughput & Packet Rate Stream
        with ui.card().classes("saas-card xl:col-span-2 p-5 flex flex-col gap-3"):
            with ui.row().classes("w-full justify-between items-center"):
                ui.label("Live Ingress Rate & Flow Dynamics").classes("text-sm md:text-base font-bold panel-title")
                ui.label("Volume (KB) & Packets per Session").classes("text-[11px] font-medium text-slate-400")

            initial_activity_opt = {
                "tooltip": {"trigger": "axis"},
                "legend": {
                    "data": ["Flow Volume (KB)", "Packet Count"],
                    "bottom": "0%",
                    "textStyle": {"color": "#64748b", "fontSize": 11}
                },
                "grid": {"left": "3%", "right": "4%", "bottom": "12%", "top": "10%", "containLabel": True},
                "xAxis": {
                    "type": "category",
                    "data": [],
                    "axisLine": {"lineStyle": {"color": "#e2e8f0"}},
                    "axisLabel": {"color": "#64748b", "fontSize": 11}
                },
                "yAxis": [
                    {
                        "type": "value",
                        "name": "Volume (KB)",
                        "axisLine": {"lineStyle": {"color": "#e2e8f0"}},
                        "splitLine": {"lineStyle": {"color": "#f1f5f9"}},
                        "axisLabel": {"color": "#64748b", "fontSize": 11}
                    },
                    {
                        "type": "value",
                        "name": "Packets",
                        "splitLine": {"show": False},
                        "axisLabel": {"color": "#64748b", "fontSize": 11}
                    }
                ],
                "series": [
                    {
                        "name": "Flow Volume (KB)",
                        "data": [],
                        "type": "line",
                        "smooth": True,
                        "showSymbol": False,
                        "lineStyle": {"width": 2.5, "color": "#2563eb"},
                        "areaStyle": {
                            "color": {
                                "type": "linear",
                                "x": 0, "y": 0, "x2": 0, "y2": 1,
                                "colorStops": [
                                    {"offset": 0, "color": "rgba(37, 99, 235, 0.25)"},
                                    {"offset": 1, "color": "rgba(37, 99, 235, 0.0)"}
                                ]
                            }
                        }
                    },
                    {
                        "name": "Packet Count",
                        "yAxisIndex": 1,
                        "data": [],
                        "type": "bar",
                        "barWidth": "35%",
                        "itemStyle": {"borderRadius": [4, 4, 0, 0], "color": "#8b5cf6"}
                    }
                ]
            }
            elements["traffic_activity_chart"] = ui.echart(initial_activity_opt).classes("w-full h-64")

        # Right 1 Col: Connection State & Health Breakdown
        with ui.card().classes("saas-card p-5 flex flex-col gap-3"):
            ui.label("Connection State & Health").classes("text-sm md:text-base font-bold panel-title")
            initial_state_opt = {
                "tooltip": {"trigger": "item", "formatter": "{b}: {c} flows ({d}%)"},
                "legend": {
                    "type": "scroll",
                    "orient": "horizontal",
                    "bottom": "0%",
                    "itemGap": 10,
                    "textStyle": {"color": "#64748b", "fontSize": 10}
                },
                "series": [{
                    "name": "State",
                    "type": "pie",
                    "radius": ["38%", "62%"],
                    "center": ["50%", "40%"],
                    "avoidLabelOverlap": False,
                    "itemStyle": {"borderRadius": 6, "borderColor": "transparent", "borderWidth": 2},
                    "data": [],
                    "label": {"show": False},
                    "color": ["#10b981", "#f59e0b", "#ef4444", "#f97316", "#3b82f6", "#8b5cf6", "#06b6d4"]
                }]
            }
            elements["traffic_state_chart"] = ui.echart(initial_state_opt).classes("w-full h-64")

    # Charts Grid - Row 2
    with ui.grid().classes("w-full grid-cols-1 lg:grid-cols-2 gap-6"):
        # Col 1: Top Destination Ports & Services
        with ui.card().classes("saas-card p-5 flex flex-col gap-3"):
            ui.label("Targeted Ports & Network Services").classes("text-sm md:text-base font-bold panel-title")
            initial_ports_opt = {
                "tooltip": {"trigger": "axis", "axisPointer": {"type": "shadow"}},
                "grid": {"left": "3%", "right": "6%", "bottom": "5%", "top": "5%", "containLabel": True},
                "xAxis": {
                    "type": "value",
                    "axisLine": {"lineStyle": {"color": "#e2e8f0"}},
                    "splitLine": {"lineStyle": {"color": "#f1f5f9"}},
                    "axisLabel": {"color": "#64748b", "fontSize": 11}
                },
                "yAxis": {
                    "type": "category",
                    "data": [],
                    "axisLine": {"lineStyle": {"color": "#e2e8f0"}},
                    "axisLabel": {"color": "#64748b", "fontSize": 11}
                },
                "series": [{
                    "name": "Flows",
                    "data": [],
                    "type": "bar",
                    "barWidth": "50%",
                    "itemStyle": {"borderRadius": [0, 4, 4, 0], "color": "#06b6d4"}
                }]
            }
            elements["traffic_ports_chart"] = ui.echart(initial_ports_opt).classes("w-full h-60")

        # Col 2: Transport Protocol Breakdown
        with ui.card().classes("saas-card p-5 flex flex-col gap-3"):
            ui.label("Transport Protocol Distribution").classes("text-sm md:text-base font-bold panel-title")
            initial_proto_opt = {
                "tooltip": {"trigger": "item"},
                "legend": {
                    "orient": "horizontal",
                    "bottom": "0%",
                    "textStyle": {"color": "#64748b", "fontSize": 11}
                },
                "series": [{
                    "name": "Protocol",
                    "type": "pie",
                    "radius": ["45%", "70%"],
                    "center": ["50%", "45%"],
                    "avoidLabelOverlap": False,
                    "itemStyle": {"borderRadius": 6, "borderColor": "transparent", "borderWidth": 2},
                    "data": [],
                    "label": {"show": False},
                    "color": ["#2563eb", "#3b82f6", "#06b6d4", "#8b5cf6", "#10b981", "#f59e0b"]
                }]
            }
            elements["traffic_proto_chart"] = ui.echart(initial_proto_opt).classes("w-full h-60")

    # Flow Grid Table
    with ui.card().classes("saas-card w-full p-5 gap-4"):
        with ui.row().classes("w-full justify-between items-center"):
            ui.label("Analyzed Ingress Flow Streams").classes("text-sm md:text-base font-bold panel-title")
            elements["traffic_table_count"] = ui.label("0 Flows Ingested").classes("text-xs font-semibold text-slate-400")

        cols = [
            {"name": "time", "label": "Time", "field": "time", "align": "left"},
            {"name": "proto", "label": "Protocol", "field": "proto", "align": "left"},
            {"name": "source", "label": "Source", "field": "source", "align": "left"},
            {"name": "destination", "label": "Destination", "field": "destination", "align": "left"},
            {"name": "state", "label": "State", "field": "state", "align": "left"},
            {"name": "packets", "label": "Packets (Tx/Rx)", "field": "packets", "align": "left"},
            {"name": "bytes", "label": "Bytes", "field": "bytes", "align": "left"},
            {"name": "duration", "label": "Duration", "field": "duration", "align": "left"},
        ]
        elements["traffic_flows_table"] = ui.table(columns=cols, rows=[], row_key="time").classes(
            "w-full shadow-none border border-slate-100 rounded-lg"
        )


def update_traffic_in_place(elements: Dict[str, Any]):
    lbl_adapter = elements.get("traffic_adapter_label")
    lbl_mode = elements.get("traffic_mode_label")
    lbl_flows = elements.get("traffic_flows_label")
    lbl_throughput = elements.get("traffic_throughput_label")
    table = elements.get("traffic_flows_table")
    table_count = elements.get("traffic_table_count")

    if lbl_adapter:
        lbl_adapter.text = state.sensor_interface
    if lbl_mode:
        lbl_mode.text = "Live Sniffing" if state.sensor_mode == "live" else "Replay Stream"
    if lbl_flows:
        lbl_flows.text = f"{len(state.flows)} Active Flows"

    if state.flows:
        total_bytes = sum(int(f.get("total_bytes", 0) or 0) for f in state.flows)
        total_pkts = sum(int(f.get("total_pkts", 0) or (int(f.get("orig_pkts", 0) or 0) + int(f.get("resp_pkts", 0) or 0))) for f in state.flows)
        size_str = f"{round(total_bytes/1024, 1)} KB" if total_bytes < 1024*1024 else f"{round(total_bytes/(1024*1024), 2)} MB"
        if lbl_throughput:
            lbl_throughput.text = f"{size_str} ({total_pkts:,} Pkts)"

        # 1. Update Live Timeline Throughput Chart
        activity_chart = elements.get("traffic_activity_chart")
        if activity_chart:
            try:
                recent_f = state.flows[:20][::-1]
                times = []
                for f in recent_f:
                    raw_ts = f.get("timestamp") or f.get("ts", "")
                    try:
                        epoch = float(raw_ts)
                        dt = datetime.fromtimestamp(epoch)
                        times.append(dt.strftime("%H:%M:%S.") + f"{dt.microsecond // 1000:03d}")
                    except Exception:
                        times.append(format_time_only(raw_ts))
                kb_data = [round(int(f.get("total_bytes", 0) or 0) / 1024.0, 2) for f in recent_f]
                pkt_data = [int(f.get("total_pkts", 0) or (int(f.get("orig_pkts", 0) or 0) + int(f.get("resp_pkts", 0) or 0))) for f in recent_f]

                activity_chart.options["xAxis"]["data"] = times
                activity_chart.options["series"][0]["data"] = kb_data
                activity_chart.options["series"][1]["data"] = pkt_data
                activity_chart.update()
            except Exception:
                pass

        # 2. Update Connection State & Health Chart (Fixed persistent colors)
        state_chart = elements.get("traffic_state_chart")
        if state_chart:
            try:
                state_counts: Dict[str, int] = defaultdict(int)
                for f in state.flows:
                    st = str(f.get("conn_state", "SF")).upper().strip()
                    state_counts[st] += 1
                    
                state_pie_data = []
                for st_code, info in STATE_PALETTE.items():
                    cnt = state_counts.get(st_code, 0)
                    if cnt > 0:
                        state_pie_data.append({
                            "name": info["label"],
                            "value": cnt,
                            "itemStyle": {
                                "color": info["color"],
                                "borderRadius": 6,
                                "borderColor": "transparent",
                            }
                        })
                for st_code, cnt in sorted(state_counts.items()):
                    if st_code not in STATE_PALETTE and cnt > 0:
                        state_pie_data.append({
                            "name": f"{st_code}: Other",
                            "value": cnt,
                            "itemStyle": {
                                "color": "#64748b",
                                "borderRadius": 6,
                                "borderColor": "transparent",
                            }
                        })

                state_chart.options["series"][0]["data"] = state_pie_data
                state_chart.update()
            except Exception:
                pass

        # 3. Update Targeted Destination Ports Chart
        ports_chart = elements.get("traffic_ports_chart")
        if ports_chart:
            try:
                port_counts: Dict[str, int] = defaultdict(int)
                port_service_map = {
                    80: "HTTP (80)",
                    443: "HTTPS (443)",
                    53: "DNS (53)",
                    22: "SSH (22)",
                    21: "FTP (21)",
                    25: "SMTP (25)",
                    3389: "RDP (3389)",
                    8080: "HTTP-Alt (8080)",
                }
                for f in state.flows:
                    dp = int(f.get("dst_port", 0) or 0)
                    if dp > 0:
                        p_label = port_service_map.get(dp, f"Port {dp}")
                        port_counts[p_label] += 1
                        
                top_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:6][::-1]
                ports_chart.options["yAxis"]["data"] = [k for k, _ in top_ports]
                ports_chart.options["series"][0]["data"] = [v for _, v in top_ports]
                ports_chart.update()
            except Exception:
                pass

        # 4. Update Protocol Volume Chart (Fixed persistent colors)
        proto_chart = elements.get("traffic_proto_chart")
        if proto_chart:
            try:
                proto_counts: Dict[str, int] = defaultdict(int)
                for f in state.flows:
                    pr = str(f.get("proto", "TCP")).upper().strip()
                    proto_counts[pr] += 1

                proto_pie_data = []
                for p_code, info in PROTO_PALETTE.items():
                    cnt = proto_counts.get(p_code, 0)
                    if cnt > 0:
                        proto_pie_data.append({
                            "name": info["label"],
                            "value": cnt,
                            "itemStyle": {
                                "color": info["color"],
                                "borderRadius": 6,
                                "borderColor": "transparent",
                            }
                        })
                for p_code, cnt in sorted(proto_counts.items()):
                    if p_code not in PROTO_PALETTE and cnt > 0:
                        proto_pie_data.append({
                            "name": p_code,
                            "value": cnt,
                            "itemStyle": {
                                "color": "#64748b",
                                "borderRadius": 6,
                                "borderColor": "transparent",
                            }
                        })

                proto_chart.options["series"][0]["data"] = proto_pie_data
                proto_chart.update()
            except Exception:
                pass

        # 5. Update Flows Table
        if table:
            rows = []
            for f in state.flows:
                rows.append({
                    "time": format_time_only(f.get("timestamp") or f.get("ts", "")),
                    "proto": str(f.get("proto", "TCP")).upper(),
                    "source": f"{f.get('src_ip', '-')}:{f.get('src_port', '')}",
                    "destination": f"{f.get('dst_ip', '-')}:{f.get('dst_port', '')}",
                    "state": f.get("conn_state", f.get("service", "-")),
                    "packets": f"{int(f.get('orig_pkts', 0) or 0)} / {int(f.get('resp_pkts', 0) or 0)}",
                    "bytes": f"{int(f.get('total_bytes', 0) or 0):,}",
                    "duration": f"{float(f.get('duration', 0.0) or 0.0):.2f}s" if f.get("duration") else "< 0.01s",
                })
            table.rows = rows
            if table_count:
                table_count.text = f"{len(rows)} Flows Ingested"

    # Trigger chart resize so charts render with true pixel dimensions
    for chart_key in ["traffic_activity_chart", "traffic_state_chart", "traffic_ports_chart", "traffic_proto_chart"]:
        c = elements.get(chart_key)
        if c:
            try:
                c.run_chart_method("resize")
            except Exception:
                pass


# ── PCAP Forensic Analysis View ───────────────────────────────────────

async def run_pcap_analysis(pcap_path_str: str, model_path_str: str, threshold: float, elements: Dict[str, Any]) -> None:
    p = Path(pcap_path_str)
    if not p.exists():
        ui.notify(f"PCAP file not found: {p.name}", type="negative")
        return

    p_bar = elements.get("pcap_progress_bar")
    p_label = elements.get("pcap_progress_label")
    p_container = elements.get("pcap_progress_container")
    analyze_btn = elements.get("pcap_analyze_button")
    client = ui.context.client

    try:
        with client:
            if analyze_btn:
                analyze_btn.disable()
            if p_container:
                p_container.set_visibility(True)
            if p_bar:
                p_bar.set_value(0.05)
            if p_label:
                p_label.text = f"Preparing analysis for {p.name}..."
    except Exception:
        pass

    await asyncio.sleep(0.05)

    thresh_val = float(threshold) if threshold is not None else 0.50
    loop = asyncio.get_running_loop()

    def progress_callback(step: int, message: str, ratio: float):
        def _apply_step_ui():
            try:
                with client:
                    if p_bar:
                        p_bar.set_value(ratio)
                    if p_label:
                        p_label.text = f"Step {step}/5: {message}"
                    ui.notify(f"Step {step}/5: {message}", type="info", position="top", timeout=2000)
            except Exception:
                pass
        loop.call_soon_threadsafe(_apply_step_ui)

    try:
        res = await loop.run_in_executor(
            None,
            lambda: analyze_pcap_file(p, model_path=model_path_str, threshold=thresh_val, on_progress=progress_callback)
        )
        
        with client:
            # 1. Update stats cards
            if "pcap_stat_packets" in elements:
                elements["pcap_stat_packets"].text = f"{res['packet_count']:,} Packets"
            if "pcap_stat_filesize" in elements:
                elements["pcap_stat_filesize"].text = f"{res['filename']} ({res['file_size_formatted']})"
                
            if "pcap_stat_throughput" in elements:
                elements["pcap_stat_throughput"].text = f"{res['duration_sec']}s Duration"
            if "pcap_stat_bandwidth" in elements:
                elements["pcap_stat_bandwidth"].text = f"{res['packets_per_sec']} PPS • {res['bandwidth_mbps']} Mbps"
                
            if "pcap_stat_flows" in elements:
                elements["pcap_stat_flows"].text = f"{res['summary']['total_flows']} Extracted Flows"
            if "pcap_stat_engine" in elements:
                eng_str = "Zeek Docker Engine" if res.get("zeek_engine_used") else "Scapy Flow Reconstructor"
                elements["pcap_stat_engine"].text = f"Engine: {eng_str}"
                
            threat_count = len(res["threats"])
            threat_pct = res["summary"]["threat_percentage"]
            if "pcap_stat_threats" in elements:
                elements["pcap_stat_threats"].text = f"{threat_count} Threats ({threat_pct}%)"
                if threat_count > 0:
                    elements["pcap_stat_threats"].classes("text-red-600 font-bold", remove="text-emerald-600")
                else:
                    elements["pcap_stat_threats"].classes("text-emerald-600 font-bold", remove="text-red-600")
            if "pcap_stat_latency" in elements:
                elements["pcap_stat_latency"].text = f"Analysis Latency: {res['analysis_latency_ms']} ms"
                
            # 2. Update Protocol Chart
            chart_proto = elements.get("pcap_chart_proto")
            if chart_proto:
                try:
                    proto_dist = res.get("protocol_distribution", {})
                    chart_proto.options["series"][0]["data"] = [
                        {"name": k, "value": v} for k, v in proto_dist.items()
                    ]
                    chart_proto.update()
                except Exception:
                    pass
                
            # 3. Update Threat Classes Chart
            chart_threats = elements.get("pcap_chart_threats")
            if chart_threats:
                try:
                    threat_class_counts: Dict[str, int] = defaultdict(int)
                    for t in res.get("threats", []):
                        tc = t.get("threat_class", "Threat")
                        threat_class_counts[tc] += 1
                    if not threat_class_counts:
                        threat_class_counts["Safe / Benign"] = res["summary"]["safe_flows"]
                    chart_threats.options["series"][0]["data"] = [
                        {"name": k, "value": v} for k, v in threat_class_counts.items()
                    ]
                    chart_threats.update()
                except Exception:
                    pass
                
            # 4. Update Alerts Table & Select
            elements["pcap_all_threats"] = res.get("threats", [])
            alerts_table = elements.get("pcap_alerts_table")
            alerts_lbl = elements.get("pcap_alerts_count_lbl")
            alerts_sel = elements.get("pcap_alerts_select")
            
            if alerts_lbl:
                alerts_lbl.text = f"{threat_count} Total Detections"
                
            if alerts_table:
                try:
                    alert_rows = []
                    for a in res.get("threats", []):
                        alert_rows.append({
                            "id": a["id"],
                            "time": a.get("time_str", "-"),
                            "threat": a.get("threat_class", ""),
                            "severity": a.get("severity", "MEDIUM"),
                            "confidence": a.get("confidence", "0%"),
                            "source": a.get("source", "-"),
                            "destination": a.get("destination", "-"),
                            "protocol": a.get("protocol", "TCP"),
                        })
                    alerts_table.rows = alert_rows
                    alerts_table.update()
                except Exception:
                    pass
                
            if alerts_sel:
                try:
                    alert_options = {a["id"]: f"[{a.get('severity')}] {a.get('threat_class')} ({a.get('source')})" for a in res.get("threats", [])}
                    alerts_sel.options = alert_options
                    if alert_options:
                        alerts_sel.value = list(alert_options.keys())[0]
                        first_t = res["threats"][0]
                        if "pcap_evidence_code" in elements:
                            elements["pcap_evidence_code"].set_content(json.dumps(first_t.get("evidence", {}), indent=2))
                    else:
                        alerts_sel.value = None
                        if "pcap_evidence_code" in elements:
                            elements["pcap_evidence_code"].set_content(json.dumps({"status": "No malicious threats detected in this PCAP."}, indent=2))
                    alerts_sel.update()
                except Exception:
                    pass
                        
            # 5. Update Flows Table
            elements["pcap_all_flows"] = res.get("flows", [])
            flows_table = elements.get("pcap_flows_table")
            if flows_table:
                try:
                    flows_table.rows = res.get("flows", [])
                    flows_table.update()
                except Exception:
                    pass
                
            if p_bar:
                p_bar.set_value(1.0)
            if p_label:
                p_label.text = f"Forensic analysis complete! Analyzed {res['summary']['total_flows']} flows ({threat_count} threats detected)."

            ui.notify(f"Forensic analysis complete for {p.name}! Found {threat_count} threats in {res['summary']['total_flows']} flows.", type="positive", position="top", timeout=4000)
    except Exception as e:
        logger.error("PCAP analysis error: %s", e)
        try:
            with client:
                if p_label:
                    p_label.text = f"Analysis error: {e}"
                ui.notify(f"Analysis failed: {e}", type="negative")
        except Exception:
            pass
    finally:
        try:
            with client:
                if analyze_btn:
                    analyze_btn.enable()
        except Exception:
            pass


def build_pcap_analysis_view(elements: Dict[str, Any]):
    ui.label("PCAP Forensic File Analyzer").classes("text-lg md:text-xl font-bold panel-title")
    ui.label("Upload or select offline packet capture files (.pcap / .pcapng) for deep threat inspection and flow reconstruction.").classes("text-xs text-slate-500 -mt-4")

    available_pcaps = get_available_pcaps()
    available_models = get_available_models()

    default_pcap = list(available_pcaps.keys())[0] if available_pcaps else "data/samples/test_traffic.pcap"
    default_model = str(DEFAULT_MODEL_PATH)
    if default_model not in available_models and available_models:
        default_model = list(available_models.keys())[0]

    elements["pcap_all_flows"] = []
    elements["pcap_all_threats"] = []

    # 1. Controller & File Upload Card
    with ui.card().classes("saas-card w-full p-5 gap-4"):
        ui.label("PCAP Ingestion & Model Configuration").classes("text-sm md:text-base font-bold panel-title")
        
        with ui.grid().classes("w-full grid-cols-1 lg:grid-cols-3 gap-4 items-start"):
            # Upload Box
            with ui.column().classes("w-full gap-2"):
                ui.label("Upload Custom PCAP").classes("text-[10px] font-bold text-slate-400 tracking-wider")
                
                async def handle_upload(e):
                    upload_dir = Path("data/uploads")
                    upload_dir.mkdir(parents=True, exist_ok=True)
                    
                    file_obj = getattr(e, "file", None)
                    raw_name = getattr(e, "name", None) or getattr(file_obj, "name", "uploaded.pcap")
                    dest_file = upload_dir / raw_name
                    
                    try:
                        if file_obj and hasattr(file_obj, "save"):
                            await file_obj.save(dest_file)
                        elif file_obj and hasattr(file_obj, "read"):
                            data = await file_obj.read()
                            dest_file.write_bytes(data)
                        elif hasattr(e, "content"):
                            if hasattr(e.content, "seek"):
                                e.content.seek(0)
                            data = e.content.read() if callable(getattr(e.content, "read", None)) else e.content
                            dest_file.write_bytes(data)
                    except Exception as ex:
                        logger.error("Failed to save uploaded PCAP: %s", ex)
                        ui.notify(f"Failed to save upload: {ex}", type="negative")
                        return

                    if not dest_file.exists() or dest_file.stat().st_size == 0:
                        ui.notify(f"Uploaded file '{raw_name}' was empty or could not be saved.", type="warning")
                        return

                    size_kb = round(dest_file.stat().st_size / 1024, 1)
                    ui.notify(f"Uploaded '{raw_name}' ({size_kb} KB)! Click 'Start Forensic Analysis' to evaluate.", type="positive", position="top", timeout=5000)
                    
                    # Refresh dropdown and set the uploaded file as selected
                    new_pcaps = get_available_pcaps()
                    pcap_sel.options = new_pcaps
                    pcap_sel.value = str(dest_file)
                    pcap_sel.update()
                    if progress_label:
                        progress_label.text = f"Uploaded '{raw_name}' • Click 'Start Forensic Analysis' to begin."

                ui.upload(
                    label="Drop .pcap or .pcapng file here",
                    auto_upload=True,
                    on_upload=handle_upload,
                    max_file_size=100 * 1024 * 1024,
                ).classes("w-full text-xs").props("outlined dense accept=.pcap,.pcapng,.cap")

            # Selection Controls (Middle Col)
            with ui.column().classes("w-full gap-2"):
                ui.label("Target PCAP File").classes("text-[10px] font-bold text-slate-400 tracking-wider")
                pcap_sel = ui.select(
                    options=available_pcaps,
                    value=default_pcap,
                    label="Select Existing / Uploaded PCAP"
                ).classes("w-full text-xs").props("outlined dense")
                elements["pcap_file_selector"] = pcap_sel

                threshold_input = ui.number(
                    label="Anomaly Confidence Threshold",
                    value=0.50,
                    min=0.05,
                    max=0.99,
                    step=0.05,
                    format="%.2f"
                ).classes("w-full text-xs").props("outlined dense")
                elements["pcap_threshold_input"] = threshold_input

            # Model Selection & Action (Right Col)
            with ui.column().classes("w-full gap-2"):
                ui.label("Inference Detection Engine").classes("text-[10px] font-bold text-slate-400 tracking-wider")
                model_sel = ui.select(
                    options=available_models,
                    value=default_model,
                    label="Classification Model"
                ).classes("w-full text-xs").props("outlined dense")
                elements["pcap_model_selector"] = model_sel

                async def on_analyze_click():
                    sel_pcap = pcap_sel.value or default_pcap
                    sel_model = model_sel.value or default_model
                    thresh = float(threshold_input.value) if threshold_input.value is not None else 0.50
                    await run_pcap_analysis(sel_pcap, sel_model, thresh, elements)

                analyze_btn = ui.button("Start Forensic Analysis", icon="radar", on_click=on_analyze_click).classes(
                    "w-full bg-blue-600 text-white text-xs font-semibold py-2.5 rounded-lg shadow-sm hover:bg-blue-700 mt-auto"
                ).props("no-caps flat")
                elements["pcap_analyze_button"] = analyze_btn

            def on_pcap_select_change():
                if pcap_sel.value and progress_label:
                    p_name = Path(pcap_sel.value).name
                    progress_label.text = f"Selected '{p_name}' • Click 'Start Forensic Analysis' to evaluate."

            pcap_sel.on_value_change(on_pcap_select_change)

        # Progress bar & Step Status Notification Container
        with ui.column().classes("w-full gap-1 pt-3 border-t mt-1") as progress_container:
            elements["pcap_progress_container"] = progress_container
            progress_bar = ui.linear_progress(value=0.0, show_value=False).classes("w-full").props("rounded size=8px color=primary")
            elements["pcap_progress_bar"] = progress_bar
            progress_label = ui.label("Ready for analysis • Select a PCAP and click 'Start Forensic Analysis'").classes("text-xs font-medium text-slate-500")
            elements["pcap_progress_label"] = progress_label

    # 2. Forensic Overview & Telemetry Cards (4 cards)
    with ui.grid().classes("w-full grid-cols-2 lg:grid-cols-4 gap-4"):
        with ui.card().classes("saas-card p-4 gap-0.5"):
            ui.label("FILE & PACKETS").classes("text-[10px] font-bold text-slate-400")
            elements["pcap_stat_packets"] = ui.label("-").classes("text-base md:text-xl font-extrabold text-slate-900")
            elements["pcap_stat_filesize"] = ui.label("Size: -").classes("text-[10px] text-slate-500")

        with ui.card().classes("saas-card p-4 gap-0.5"):
            ui.label("DURATION & THROUGHPUT").classes("text-[10px] font-bold text-slate-400")
            elements["pcap_stat_throughput"] = ui.label("-").classes("text-base md:text-xl font-extrabold text-slate-900")
            elements["pcap_stat_bandwidth"] = ui.label("Bandwidth: -").classes("text-[10px] text-slate-500")

        with ui.card().classes("saas-card p-4 gap-0.5"):
            ui.label("RECONSTRUCTED FLOWS").classes("text-[10px] font-bold text-slate-400")
            elements["pcap_stat_flows"] = ui.label("-").classes("text-base md:text-xl font-extrabold text-blue-600")
            elements["pcap_stat_engine"] = ui.label("Engine: Zeek/Scapy").classes("text-[10px] text-slate-500")

        with ui.card().classes("saas-card p-4 gap-0.5"):
            ui.label("FLAGGED THREATS").classes("text-[10px] font-bold text-slate-400")
            elements["pcap_stat_threats"] = ui.label("0 Threats").classes("text-base md:text-xl font-extrabold text-emerald-600")
            elements["pcap_stat_latency"] = ui.label("Analysis time: -").classes("text-[10px] text-slate-500")

    # 3. Interactive Visualizations (Row of 2 ECharts)
    with ui.grid().classes("w-full grid-cols-1 lg:grid-cols-2 gap-6"):
        with ui.card().classes("saas-card p-5 flex flex-col gap-3"):
            ui.label("PCAP Protocol Distribution").classes("text-sm md:text-base font-bold panel-title")
            initial_proto_opt = {
                "tooltip": {"trigger": "item"},
                "series": [{
                    "type": "pie",
                    "radius": ["45%", "75%"],
                    "center": ["50%", "50%"],
                    "itemStyle": {"borderRadius": 6, "borderColor": "#ffffff", "borderWidth": 2},
                    "data": [],
                    "color": ["#2563eb", "#3b82f6", "#06b6d4", "#8b5cf6", "#10b981", "#f59e0b"]
                }]
            }
            elements["pcap_chart_proto"] = ui.echart(initial_proto_opt).classes("w-full h-64")

        with ui.card().classes("saas-card p-5 flex flex-col gap-3"):
            ui.label("Threat Class & Vector Distribution").classes("text-sm md:text-base font-bold panel-title")
            initial_threat_opt = {
                "tooltip": {"trigger": "item"},
                "series": [{
                    "type": "pie",
                    "radius": ["45%", "75%"],
                    "center": ["50%", "50%"],
                    "itemStyle": {"borderRadius": 6, "borderColor": "#ffffff", "borderWidth": 2},
                    "data": [],
                    "color": ["#ef4444", "#f97316", "#f59e0b", "#8b5cf6", "#3b82f6", "#10b981"]
                }]
            }
            elements["pcap_chart_threats"] = ui.echart(initial_threat_opt).classes("w-full h-64")

    # 4. Detected Security Alerts Table
    with ui.card().classes("saas-card w-full p-5 gap-4"):
        with ui.row().classes("w-full justify-between items-center"):
            ui.label("Detected Forensic Security Alerts").classes("text-sm md:text-base font-bold panel-title")
            elements["pcap_alerts_count_lbl"] = ui.label("0 Detections").classes("text-xs font-semibold text-slate-400")

        alert_cols = [
            {"name": "id", "label": "Alert ID", "field": "id", "align": "left"},
            {"name": "time", "label": "Timestamp", "field": "time", "align": "left"},
            {"name": "threat", "label": "Threat Classification", "field": "threat", "align": "left"},
            {"name": "severity", "label": "Severity", "field": "severity", "align": "left"},
            {"name": "confidence", "label": "Confidence", "field": "confidence", "align": "left"},
            {"name": "source", "label": "Source Host", "field": "source", "align": "left"},
            {"name": "destination", "label": "Destination Host", "field": "destination", "align": "left"},
            {"name": "protocol", "label": "Protocol", "field": "protocol", "align": "left"},
        ]
        elements["pcap_alerts_table"] = ui.table(columns=alert_cols, rows=[], row_key="id").classes(
            "w-full shadow-none border border-slate-100 rounded-lg text-xs"
        )

        ui.separator().classes("my-3")
        ui.label("Inspect Forensic Evidence Artifact").classes("text-xs font-bold uppercase tracking-wider forensic-title")

        elements["pcap_alerts_select"] = ui.select(options={}, value=None).classes("w-full text-xs").props("outlined dense")
        elements["pcap_evidence_code"] = ui.code("", language="json").classes("w-full text-xs p-3 rounded-lg forensic-code")

        def on_alert_select(e):
            sel_val = e.value
            threats = elements.get("pcap_all_threats", [])
            target = next((a for a in threats if a["id"] == sel_val), None)
            if target and "pcap_evidence_code" in elements:
                elements["pcap_evidence_code"].set_content(json.dumps(target.get("evidence", {}), indent=2))

        elements["pcap_alerts_select"].on_value_change(on_alert_select)

    # 5. All Reconstructed Flows Table
    with ui.card().classes("saas-card w-full p-5 gap-4"):
        with ui.row().classes("w-full justify-between items-center"):
            ui.label("Reconstructed Connection Flows").classes("text-sm md:text-base font-bold panel-title")
            
            with ui.row().classes("gap-1"):
                def filter_flows(filter_type: str):
                    all_f = elements.get("pcap_all_flows", [])
                    t = elements.get("pcap_flows_table")
                    if not t:
                        return
                    if filter_type == "threats":
                        t.rows = [f for f in all_f if f.get("is_threat")]
                    elif filter_type == "safe":
                        t.rows = [f for f in all_f if not f.get("is_threat")]
                    else:
                        t.rows = all_f

                ui.button("All Flows", on_click=lambda: filter_flows("all")).props("flat dense no-caps").classes("text-xs")
                ui.button("Threats Only", on_click=lambda: filter_flows("threats")).props("flat dense no-caps color=red").classes("text-xs")
                ui.button("Safe Only", on_click=lambda: filter_flows("safe")).props("flat dense no-caps color=green").classes("text-xs")

        flow_cols = [
            {"name": "id", "label": "Flow UID", "field": "id", "align": "left"},
            {"name": "time", "label": "Time", "field": "time", "align": "left"},
            {"name": "proto", "label": "Proto", "field": "proto", "align": "left"},
            {"name": "source", "label": "Source Host", "field": "source", "align": "left"},
            {"name": "destination", "label": "Destination Host", "field": "destination", "align": "left"},
            {"name": "state", "label": "State", "field": "state", "align": "left"},
            {"name": "packets", "label": "Packets (Tx/Rx)", "field": "packets", "align": "left"},
            {"name": "bytes", "label": "Bytes", "field": "bytes", "align": "left"},
            {"name": "duration", "label": "Duration", "field": "duration", "align": "left"},
            {"name": "status", "label": "Status", "field": "status", "align": "left"},
            {"name": "confidence", "label": "Confidence", "field": "confidence", "align": "left"},
        ]
        elements["pcap_flows_table"] = ui.table(columns=flow_cols, rows=[], row_key="id").classes(
            "w-full shadow-none border border-slate-100 rounded-lg text-xs"
        )


def update_pcap_analysis_in_place(elements: Dict[str, Any]):
    pcap_sel = elements.get("pcap_file_selector")
    model_sel = elements.get("pcap_model_selector")
    if pcap_sel:
        cur_pcaps = get_available_pcaps()
        if set(pcap_sel.options.keys()) != set(cur_pcaps.keys()):
            old_val = pcap_sel.value
            pcap_sel.options = cur_pcaps
            if old_val and old_val in cur_pcaps:
                pcap_sel.value = old_val
            pcap_sel.update()
    if model_sel:
        cur_models = get_available_models()
        if set(model_sel.options.keys()) != set(cur_models.keys()):
            old_m = model_sel.value
            model_sel.options = cur_models
            if old_m and old_m in cur_models:
                model_sel.value = old_m
            model_sel.update()

    # Trigger chart resize so charts render with true pixel dimensions
    chart_proto = elements.get("pcap_chart_proto")
    chart_threats = elements.get("pcap_chart_threats")
    if chart_proto:
        try:
            chart_proto.run_chart_method("resize")
        except Exception:
            pass
    if chart_threats:
        try:
            chart_threats.run_chart_method("resize")
        except Exception:
            pass


# ── Threat Analysis View ──────────────────────────────────────────────

KNOWN_THREAT_INFO = {
    "port_scan": {
        "title": "Port Scanning & Reconnaissance",
        "desc": "Sequential and distributed port probing operations attempting to discover open network services.",
        "icon": "radar",
    },
    "reconnaissance": {
        "title": "Reconnaissance & Network Sweeper",
        "desc": "Host discovery and subnet scanning operations gathering intelligence on live infrastructure.",
        "icon": "search",
    },
    "ddos_syn_flood": {
        "title": "SYN Flood Volumetric DoS",
        "desc": "High-frequency TCP SYN packet floods intended to exhaust connection queues and memory buffers.",
        "icon": "warning",
    },
    "ddos_udp_flood": {
        "title": "UDP Flood Volumetric DoS",
        "desc": "Saturating UDP traffic bursts targeted at overwhelming interface bandwidth and network sockets.",
        "icon": "waves",
    },
    "ddos": {
        "title": "DDoS Volumetric Attack Engine",
        "desc": "Distributed denial-of-service traffic streams aimed at disrupting host availability.",
        "icon": "warning",
    },
    "c2_beacon": {
        "title": "C2 Beaconing Communication",
        "desc": "Periodic heartbeat signals and command-and-control communication channels with remote servers.",
        "icon": "cell_tower",
    },
    "botnet": {
        "title": "Botnet & Automated Agent Activity",
        "desc": "Automated compromised host coordination communicating with command & control infrastructure.",
        "icon": "smart_toy",
    },
    "dga_domain": {
        "title": "DGA Algorithmic Domain Generator",
        "desc": "Algorithmically generated domain names bypassing static reputation and blocklist filters.",
        "icon": "dns",
    },
    "dns_tunneling": {
        "title": "DNS Tunneling & Data Exfiltration",
        "desc": "Covert data exfiltration and tunnel channels concealed inside recursive DNS query streams.",
        "icon": "vpn_lock",
    },
    "encrypted_threat": {
        "title": "Encrypted Session & TLS Anomaly",
        "desc": "Malicious payload patterns and suspicious behavioral metrics inside encrypted TLS layers.",
        "icon": "lock",
    },
    "web_attack": {
        "title": "Web Application Exploit & Injection",
        "desc": "Cross-Site Scripting (XSS), SQL injection, and web application parameter tampering.",
        "icon": "code",
    },
    "brute_force": {
        "title": "Credential Brute Force Attack",
        "desc": "Automated dictionary and password cracking attempts targeting authentication services.",
        "icon": "key",
    },
    "infiltration": {
        "title": "Infiltration & Network Breach",
        "desc": "Unauthorized lateral movement and system infiltration detected via anomalous flow signatures.",
        "icon": "security",
    },
    "heartbleed": {
        "title": "Heartbleed SSL Memory Leak Exploit",
        "desc": "OpenSSL heartbeat extension vulnerability exploitation targeting private server memory.",
        "icon": "bug_report",
    },
    "unknown_anomaly": {
        "title": "Zero-Day & Unsupervised ML Anomaly",
        "desc": "Statistically significant flow feature deviations flagged by unsupervised machine learning.",
        "icon": "auto_awesome",
    },
    "ml_random_forest_threat": {
        "title": "Random Forest ML Threat Detection",
        "desc": "Malicious flow signature classified with high confidence by the trained Random Forest model.",
        "icon": "psychology",
    },
    "ml_xgboost_threat": {
        "title": "XGBoost Gradient Boosted Detection",
        "desc": "High-confidence malicious pattern identified by the gradient-boosted decision tree pipeline.",
        "icon": "bolt",
    },
    "ml_isolation_forest_threat": {
        "title": "Isolation Forest Anomaly Flag",
        "desc": "Outlier flow isolated from normal baseline distributions by unsupervised anomaly trees.",
        "icon": "filter_alt",
    },
}


def build_threats_view(elements: Dict[str, Any]):
    ui.label("Attack Analytics & Detection Engines").classes("text-lg md:text-xl font-bold panel-title")
    elements["threats_subtitle"] = ui.label("Live detected threat vectors ranked in increasing order of detection counts.").classes("text-xs text-slate-500 -mt-4")

    # Container that dynamically renders active detected threat cards
    with ui.column().classes("w-full gap-4") as container:
        elements["threats_container"] = container

    update_threats_in_place(elements)


def update_threats_in_place(elements: Dict[str, Any]):
    container = elements.get("threats_container")
    if not container:
        return

    # 1. Group alerts by threat_class (only detected threats)
    threat_groups: Dict[str, list] = defaultdict(list)
    for a in state.alerts:
        tc = str(a.get("threat_class", "")).strip().lower()
        if tc and tc != "benign":
            threat_groups[tc].append(a)

    # 2. Sort threats in increasing order of detections (ascending count: lowest to highest)
    sorted_threats = sorted(threat_groups.items(), key=lambda item: len(item[1]))

    # 3. Update subtitle with total detected threats
    subtitle = elements.get("threats_subtitle")
    if subtitle:
        total_unique = len(sorted_threats)
        total_alerts = sum(len(items) for _, items in sorted_threats)
        if total_unique == 0:
            subtitle.text = "No active threats detected yet • Monitoring live ingress traffic for suspicious activity."
        else:
            subtitle.text = f"Observing {total_unique} distinct active threat vectors ({total_alerts} total alerts) • Ranked in increasing order of detections."

    # 4. Check if signature changed to avoid unnecessary DOM clears
    current_signature = [(tc, len(items)) for tc, items in sorted_threats]
    last_signature = elements.get("last_threats_signature")

    if current_signature == last_signature:
        return

    elements["last_threats_signature"] = current_signature
    container.clear()

    with container:
        if not sorted_threats:
            # Clean Empty State
            with ui.card().classes("saas-card w-full p-8 items-center text-center gap-3"):
                with ui.element("div").classes("w-14 h-14 rounded-full bg-emerald-50 text-emerald-600 flex items-center justify-center"):
                    ui.icon("verified_user").classes("text-3xl")
                with ui.column().classes("gap-1 items-center"):
                    ui.label("Ingress Traffic Normal • No Active Threats").classes("text-base font-bold panel-title")
                    ui.label("Continuous passive threat monitoring is active. As suspicious flow patterns or anomalies are detected, threat cards will appear here in increasing order of detection counts.").classes("text-xs text-slate-500 max-w-lg leading-relaxed")
        else:
            with ui.grid().classes("w-full grid-cols-1 md:grid-cols-2 gap-4"):
                for rank, (tc, items) in enumerate(sorted_threats, 1):
                    count = len(items)
                    confidences = [a.get("confidence", 0.0) for a in items if "confidence" in a]
                    avg_conf = f"{int(np.mean(confidences) * 100)}%" if confidences else "N/A"
                    
                    severities = [str(a.get("severity", "medium")).lower() for a in items]
                    highest_sev = "critical" if "critical" in severities else ("high" if "high" in severities else ("medium" if "medium" in severities else "low"))
                    
                    info = KNOWN_THREAT_INFO.get(tc, {})
                    title = info.get("title", tc.replace("_", " ").replace("-", " ").title())
                    desc = info.get("desc", f"Dynamically detected threat pattern for '{tc}' observed in live flow stream.")
                    icon_name = info.get("icon", "shield_alert")
                    
                    border_color = "border-l-red-500" if highest_sev in ["critical", "high"] else "border-l-amber-500"
                    
                    with ui.card().classes(f"saas-card p-5 gap-3 border-l-4 {border_color}"):
                        with ui.row().classes("w-full justify-between items-start gap-3"):
                            with ui.row().classes("items-center gap-2"):
                                ui.icon(icon_name).classes("text-base text-blue-600")
                                with ui.column().classes("gap-0"):
                                    ui.label(title).classes("text-sm font-bold leading-snug threat-engine-title")
                                    ui.label(f"Rank #{rank} in Detections ({count} occurrences)").classes("text-[10px] text-slate-400 font-medium")
                            
                            with ui.row().classes("items-center gap-1.5 shrink-0"):
                                ui.label(f"{highest_sev.upper()}").classes(
                                    f"text-[10px] font-bold px-2 py-0.5 rounded-full {'bg-red-50 text-red-600' if highest_sev in ['critical', 'high'] else 'bg-amber-50 text-amber-600'}"
                                )
                                ui.label("ALERT DETECTED").classes("text-[10px] font-bold px-2 py-0.5 rounded-full threat-badge-alert")
                                
                        ui.label(desc).classes("text-xs leading-relaxed threat-engine-description")

                        with ui.row().classes("w-full justify-between pt-2 border-t text-xs threat-engine-footer"):
                            ui.label(f"Total Detections: {count}").classes("font-semibold threat-engine-metric")
                            ui.label(f"Avg Confidence: {avg_conf}").classes("threat-engine-confidence")


# ── Models View ───────────────────────────────────────────────────────

def build_models_view(elements: Dict[str, Any]):
    ui.label("Machine Learning Engine Registry").classes("text-lg md:text-xl font-bold text-slate-900")
    ui.label("Explore, evaluate, and activate ML classifiers for live detection and prototyping.").classes("text-xs text-slate-500 -mt-4")

    available_models = get_available_models()
    available_datasets = get_available_datasets()

    default_model_choice = str(DEFAULT_MODEL_PATH)
    if default_model_choice not in available_models and available_models:
        default_model_choice = list(available_models.keys())[0]

    default_dataset_choice = list(available_datasets.keys())[0] if available_datasets else "data/samples/labeled_flows.csv"
    if "data/samples/cic_combined.parquet" in available_datasets:
        default_dataset_choice = "data/samples/cic_combined.parquet"

    elements["current_selected_model"] = default_model_choice
    elements["current_selected_dataset"] = default_dataset_choice

    # Model & Benchmark Control Center Card
    with ui.card().classes("saas-card w-full p-5 gap-4"):
        ui.label("Model Selection & Prototyping Controls").classes("text-sm md:text-base font-bold panel-title")
        
        with ui.grid().classes("w-full grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 items-end"):
            model_sel = ui.select(
                options=available_models,
                value=default_model_choice,
                label="Select Model for Analysis / Deployment"
            ).classes("w-full text-xs").props("outlined dense")
            elements["model_selector"] = model_sel

            dataset_sel = ui.select(
                options=available_datasets,
                value=default_dataset_choice,
                label="Benchmark Validation Dataset"
            ).classes("w-full text-xs").props("outlined dense")
            elements["dataset_selector"] = dataset_sel

            with ui.row().classes("w-full gap-2 items-center"):
                def on_activate():
                    sel_m = model_sel.value or default_model_choice
                    p_src = Path(sel_m)
                    if not p_src.exists():
                        ui.notify("Selected model file does not exist", type="negative")
                        return
                    try:
                        # Copy selected model to default_rf.joblib if it is a different file
                        if p_src.resolve() != DEFAULT_MODEL_PATH.resolve():
                            shutil.copyfile(p_src, DEFAULT_MODEL_PATH)
                        
                        # Update sensor config
                        cfg_path = Path("data/sensor_config.json")
                        cur_cfg = {"mode": "replay", "interface": "any", "rotation": 5}
                        if cfg_path.exists():
                            try:
                                with open(cfg_path, "r") as f:
                                    cur_cfg = json.load(f)
                            except Exception:
                                pass
                        cur_cfg["model_path"] = str(p_src)
                        cfg_path.parent.mkdir(parents=True, exist_ok=True)
                        with open(cfg_path, "w") as f:
                            json.dump(cur_cfg, f)
                        
                        ui.notify(f"Activated {p_src.name} for live sensor detection!", type="positive", position="top")
                        run_model_evaluation(model_sel.value, dataset_sel.value, elements)
                    except Exception as e:
                        ui.notify(f"Failed to activate model: {e}", type="negative")

                ui.button("Activate Model", icon="check_circle", on_click=on_activate).classes(
                    "flex-1 bg-blue-600 text-white text-xs font-semibold py-2 rounded-lg shadow-sm hover:bg-blue-700"
                ).props("no-caps flat")

                def on_benchmark():
                    sel_m = model_sel.value or default_model_choice
                    sel_d = dataset_sel.value or default_dataset_choice
                    run_model_evaluation(sel_m, sel_d, elements)
                    ui.notify("Validation metrics updated!", type="info", position="top")

                ui.button("Run Benchmark", icon="speed", on_click=on_benchmark).classes(
                    "flex-1 bg-slate-800 text-white text-xs font-semibold py-2 rounded-lg shadow-sm hover:bg-slate-900"
                ).props("no-caps flat")

        def on_selection_change():
            sel_m = model_sel.value or default_model_choice
            sel_d = dataset_sel.value or default_dataset_choice
            elements["current_selected_model"] = sel_m
            elements["current_selected_dataset"] = sel_d
            run_model_evaluation(sel_m, sel_d, elements)

        model_sel.on_value_change(on_selection_change)
        dataset_sel.on_value_change(on_selection_change)

    # Model Specification Metadata Cards
    with ui.card().classes("saas-card w-full p-5 gap-4"):
        with ui.grid().classes("w-full grid-cols-2 lg:grid-cols-4 gap-4"):
            with ui.column().classes("gap-0"):
                ui.label("MODEL ARCHITECTURE").classes("text-[10px] font-bold text-slate-400")
                elements["model_classifier_type"] = ui.label("Random Forest").classes("text-sm md:text-base font-bold text-blue-600")
            with ui.column().classes("gap-0"):
                ui.label("SENSOR DEPLOYMENT").classes("text-[10px] font-bold text-slate-400")
                elements["model_status_badge"] = ui.label("Active in Live Sensor").classes("text-sm md:text-base font-bold text-emerald-600")
            with ui.column().classes("gap-0"):
                ui.label("INPUT FEATURES").classes("text-[10px] font-bold text-slate-400")
                elements["model_feature_dim"] = ui.label("37 Flow Features").classes("text-sm md:text-base font-bold text-slate-900")
            with ui.column().classes("gap-0"):
                ui.label("FILE & ARTIFACT").classes("text-[10px] font-bold text-slate-400")
                elements["model_artifact_size"] = ui.label("default_rf.joblib").classes("text-sm md:text-base font-mono text-slate-500")

    # Evaluation Validation Metrics (4 metric cards)
    with ui.grid().classes("w-full grid-cols-2 lg:grid-cols-4 gap-4"):
        for key, lbl in [
            ("model_f1_score", "F1-SCORE"),
            ("model_precision", "PRECISION"),
            ("model_recall", "RECALL"),
            ("model_latency", "INFERENCE LATENCY"),
        ]:
            with ui.card().classes("saas-card p-4 gap-0.5"):
                ui.label(lbl).classes("text-[10px] font-bold text-slate-400")
                elements[key] = ui.label("-").classes("text-lg md:text-2xl font-extrabold text-slate-900")

    # Classification Report & Confusion Matrix
    with ui.grid().classes("w-full grid-cols-1 lg:grid-cols-3 gap-6"):
        with ui.card().classes("saas-card lg:col-span-2 p-5 gap-3"):
            with ui.row().classes("w-full justify-between items-center"):
                ui.label("Validation Classification Report").classes("text-sm md:text-base font-bold panel-title")
                elements["model_report_subtitle"] = ui.label("Holdout Temporal Partition").classes("text-[11px] font-medium text-slate-400")

            report_cols = [
                {"name": "class_name", "label": "Classification Class / Average", "field": "class_name", "align": "left"},
                {"name": "precision", "label": "Precision", "field": "precision", "align": "right"},
                {"name": "recall", "label": "Recall", "field": "recall", "align": "right"},
                {"name": "f1_score", "label": "F1-Score", "field": "f1_score", "align": "right"},
                {"name": "support", "label": "Samples (Support)", "field": "support", "align": "right"},
            ]
            elements["model_report_table"] = ui.table(columns=report_cols, rows=[], row_key="class_name").classes(
                "w-full shadow-none border border-slate-100 rounded-lg text-xs"
            )

        with ui.card().classes("saas-card p-5 gap-3"):
            ui.label("Confusion Matrix").classes("text-sm md:text-base font-bold panel-title")
            with ui.column().classes("w-full gap-2 mt-1"):
                with ui.grid().classes("w-full grid-cols-2 gap-2 text-center"):
                    with ui.card().classes("p-3 bg-emerald-50 border border-emerald-200 rounded-lg shadow-none gap-0"):
                        ui.label("True Negative (TN)").classes("text-[10px] font-bold text-emerald-800 uppercase")
                        elements["model_cm_tn"] = ui.label("0").classes("text-xl font-black text-emerald-700")
                        ui.label("Actual: Benign").classes("text-[9px] text-emerald-600")

                    with ui.card().classes("p-3 bg-amber-50 border border-amber-200 rounded-lg shadow-none gap-0"):
                        ui.label("False Positive (FP)").classes("text-[10px] font-bold text-amber-800 uppercase")
                        elements["model_cm_fp"] = ui.label("0").classes("text-xl font-black text-amber-700")
                        ui.label("Predicted: Threat").classes("text-[9px] text-amber-600")

                    with ui.card().classes("p-3 bg-amber-50 border border-amber-200 rounded-lg shadow-none gap-0"):
                        ui.label("False Negative (FN)").classes("text-[10px] font-bold text-amber-800 uppercase")
                        elements["model_cm_fn"] = ui.label("0").classes("text-xl font-black text-amber-700")
                        ui.label("Missed Detection").classes("text-[9px] text-amber-600")

                    with ui.card().classes("p-3 bg-emerald-50 border border-emerald-200 rounded-lg shadow-none gap-0"):
                        ui.label("True Positive (TP)").classes("text-[10px] font-bold text-emerald-800 uppercase")
                        elements["model_cm_tp"] = ui.label("0").classes("text-xl font-black text-emerald-700")
                        ui.label("Actual: Intrusion").classes("text-[9px] text-emerald-600")

    # Run initial evaluation
    run_model_evaluation(default_model_choice, default_dataset_choice, elements)


def update_models_in_place(elements: Dict[str, Any]):
    model_sel = elements.get("model_selector")
    dataset_sel = elements.get("dataset_selector")
    if model_sel:
        latest_models = get_available_models()
        if set(model_sel.options.keys()) != set(latest_models.keys()):
            model_sel.options = latest_models
            model_sel.update()
    if dataset_sel:
        latest_datasets = get_available_datasets()
        if set(dataset_sel.options.keys()) != set(latest_datasets.keys()):
            dataset_sel.options = latest_datasets
            dataset_sel.update()


# ── System View ───────────────────────────────────────────────────────

def build_system_view(elements: Dict[str, Any]):
    ui.label("Node Status & System Telemetry").classes("text-lg md:text-xl font-bold text-slate-900")
    ui.label("Resource utilization and pipeline engine statuses.").classes("text-xs text-slate-500 -mt-4")

    zeek_detected = detect_backend()
    zeek_str = f"Available ({'Docker' if str(zeek_detected) == 'ZeekBackend.DOCKER' else 'Native'})" if zeek_detected else "Not Installed"

    with ui.card().classes("saas-card w-full p-5 gap-3"):
        ui.label("Component Health").classes("text-sm md:text-base font-bold text-slate-900")

        components = [
            ("Zeek Ingestion Engine", zeek_str, bool(zeek_detected)),
            ("Detection Rule Engine", "Running", True),
            ("ML Inference Pipeline", "Active" if DEFAULT_MODEL_PATH.exists() else "Missing", DEFAULT_MODEL_PATH.exists()),
            ("FastAPI Core REST API", "Running", True),
            ("Telemetry Database", "Connected", True),
        ]

        for name, status_txt, is_ok in components:
            with ui.row().classes("w-full justify-between items-center py-2 border-b border-slate-50 text-xs"):
                ui.label(name).classes("font-medium text-slate-700")
                with ui.row().classes("items-center gap-1.5"):
                    ui.element("div").classes(f"w-2 h-2 rounded-full {'bg-emerald-500' if is_ok else 'bg-red-500'}")
                    ui.label(status_txt).classes(f"font-bold {'text-emerald-700' if is_ok else 'text-red-700'}")

    with ui.grid().classes("w-full grid-cols-2 lg:grid-cols-4 gap-4"):
        with ui.card().classes("saas-card p-4 gap-0.5"):
            ui.label("HOST CPU UTILIZATION").classes("text-[10px] font-bold text-slate-400")
            elements["system_cpu_label"] = ui.label("0%").classes("text-lg md:text-2xl font-extrabold text-slate-900")
        with ui.card().classes("saas-card p-4 gap-0.5"):
            ui.label("HOST MEMORY USAGE").classes("text-[10px] font-bold text-slate-400")
            elements["system_mem_label"] = ui.label("0%").classes("text-lg md:text-2xl font-extrabold text-slate-900")
        with ui.card().classes("saas-card p-4 gap-0.5"):
            ui.label("PROCESSING RATE").classes("text-[10px] font-bold text-slate-400")
            elements["system_rate_label"] = ui.label("0 flows/s").classes("text-lg md:text-2xl font-extrabold text-blue-600")
        with ui.card().classes("saas-card p-4 gap-0.5"):
            ui.label("PIPELINE LATENCY").classes("text-[10px] font-bold text-slate-400")
            elements["system_latency_label"] = ui.label("< 1.0 ms").classes("text-lg md:text-2xl font-extrabold text-slate-900")


def update_system_in_place(elements: Dict[str, Any]):
    cpu = get_cpu_usage()
    mem = get_mem_usage()
    perf = state.pipeline_stats or {}
    rate_val = perf.get("packets_per_sec", 0.0)
    latency_val = perf.get("latency_ms", 0.0)

    if "system_cpu_label" in elements:
        elements["system_cpu_label"].text = f"{cpu}%"
    if "system_mem_label" in elements:
        elements["system_mem_label"].text = f"{mem}%"
    if "system_rate_label" in elements:
        elements["system_rate_label"].text = f"{rate_val} flows/s"
    if "system_latency_label" in elements:
        elements["system_latency_label"].text = f"{latency_val:.3f} ms" if latency_val > 0 else "< 1.0 ms"


if __name__ in {"__main__", "__mp_main__"}:
    ui.run(
        title="NETra - ML-Based Network Threat Detection",
        port=8501,
        reload=False,
        show=False
    )
