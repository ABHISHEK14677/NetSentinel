#!/usr/bin/env python3
"""
NetSentinel Professional Presentation Generator
Generates a 16:9 cybersecurity executive-grade presentation deck for the NetSentinel Dashboard Guide.
"""

import os
import sys
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE

# ── Color Palette Definitions ──────────────────────────────────────────────────
C_BG_DARK       = RGBColor(10, 15, 29)      # Deep Navy Dark #0A0F1D
C_BG_CARD       = RGBColor(22, 30, 49)      # Card Navy #161E31
C_BG_CARD_LIGHT = RGBColor(30, 41, 67)      # Lighter Card #1E2943
C_BORDER        = RGBColor(46, 56, 77)      # Border Slate #2E384D
C_TEXT_WHITE    = RGBColor(255, 255, 255)  # Clean White
C_TEXT_OFFWHITE = RGBColor(226, 232, 240)  # Light Slate Text #E2E8F0
C_TEXT_MUTED    = RGBColor(148, 163, 184)  # Muted Slate #94A3B8
C_ACCENT_BLUE   = RGBColor(56, 189, 248)   # Electric Cyan/Blue #38BDF8
C_ACCENT_GREEN  = RGBColor(16, 185, 129)   # Emerald Green #10B981
C_ACCENT_AMBER  = RGBColor(245, 158, 11)   # Warning Amber #F59E0B
C_ACCENT_RED    = RGBColor(239, 68, 68)    # Critical Red #EF4444
C_ACCENT_PURPLE = RGBColor(168, 85, 247)   # Purple #A855F7

FONT_HEADING = "Trebuchet MS"
FONT_BODY    = "Calibri"

def create_deck(output_path: str):
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    def set_slide_background(slide):
        bg_shape = slide.shapes.add_shape(
            MSO_SHAPE.RECTANGLE, 0, 0, Inches(13.333), Inches(7.5)
        )
        bg_shape.fill.solid()
        bg_shape.fill.fore_color.rgb = C_BG_DARK
        bg_shape.line.fill.background()
        return bg_shape

    def add_header(slide, title_text: str, subtitle_text: str, category_badge: str = "NETSENTINEL SOC OPERATIONS"):
        # Category Badge
        badge_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(8), Inches(0.35))
        tf_b = badge_box.text_frame
        tf_b.word_wrap = True
        tf_b.margin_left = tf_b.margin_right = tf_b.margin_top = tf_b.margin_bottom = 0
        p_b = tf_b.paragraphs[0]
        p_b.text = category_badge.upper()
        p_b.font.name = FONT_HEADING
        p_b.font.size = Pt(10)
        p_b.font.bold = True
        p_b.font.color.rgb = C_ACCENT_BLUE

        # Main Title
        title_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.7), Inches(11.7), Inches(0.65))
        tf_t = title_box.text_frame
        tf_t.word_wrap = True
        tf_t.margin_left = tf_t.margin_right = tf_t.margin_top = tf_t.margin_bottom = 0
        p_t = tf_t.paragraphs[0]
        p_t.text = title_text
        p_t.font.name = FONT_HEADING
        p_t.font.size = Pt(22)
        p_t.font.bold = True
        p_t.font.color.rgb = C_TEXT_WHITE

        # Subtitle
        sub_box = slide.shapes.add_textbox(Inches(0.8), Inches(1.35), Inches(11.7), Inches(0.35))
        tf_s = sub_box.text_frame
        tf_s.word_wrap = True
        tf_s.margin_left = tf_s.margin_right = tf_s.margin_top = tf_s.margin_bottom = 0
        p_s = tf_s.paragraphs[0]
        p_s.text = subtitle_text
        p_s.font.name = FONT_BODY
        p_s.font.size = Pt(12)
        p_s.font.color.rgb = C_TEXT_MUTED

        # Subtle divider line
        div = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.8), Inches(1.75), Inches(11.733), Inches(0.02))
        div.fill.solid()
        div.fill.fore_color.rgb = C_BORDER
        div.line.fill.background()

    def add_footer(slide, current_page: int, total_pages: int = 12):
        footer_box = slide.shapes.add_textbox(Inches(0.8), Inches(7.05), Inches(11.733), Inches(0.3))
        tf = footer_box.text_frame
        tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
        p = tf.paragraphs[0]
        p.text = f"NetSentinel NIDS/NIPS Engine  |  Active Threat Defense Dashboard Guide  |  Slide {current_page} of {total_pages}"
        p.font.name = FONT_BODY
        p.font.size = Pt(9)
        p.font.color.rgb = C_TEXT_MUTED

    def add_card(slide, left, top, width, height, title: str = "", accent_color: RGBColor = C_ACCENT_BLUE, bg_color: RGBColor = C_BG_CARD):
        card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
        card.fill.solid()
        card.fill.fore_color.rgb = bg_color
        card.line.color.rgb = C_BORDER
        card.line.width = Pt(1)

        # Accent top border strip
        strip = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, left, top, width, Inches(0.06))
        strip.fill.solid()
        strip.fill.fore_color.rgb = accent_color
        strip.line.fill.background()

        if title:
            tb = slide.shapes.add_textbox(left + Inches(0.2), top + Inches(0.12), width - Inches(0.4), Inches(0.35))
            tf = tb.text_frame
            tf.word_wrap = True
            tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
            p = tf.paragraphs[0]
            p.text = title
            p.font.name = FONT_HEADING
            p.font.size = Pt(13)
            p.font.bold = True
            p.font.color.rgb = accent_color

        return card

    # ══════════════════════════════════════════════════════════════════════════════
    # SLIDE 1: Title Slide (Cover)
    # ══════════════════════════════════════════════════════════════════════════════
    s1 = prs.slides.add_slide(blank_layout)
    set_slide_background(s1)

    # Accent decorative top strip
    top_bar = s1.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, Inches(13.333), Inches(0.1))
    top_bar.fill.solid()
    top_bar.fill.fore_color.rgb = C_ACCENT_BLUE
    top_bar.line.fill.background()

    # System Badge
    s1_badge = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(1.0), Inches(1.5), Inches(3.2), Inches(0.4))
    s1_badge.fill.solid()
    s1_badge.fill.fore_color.rgb = C_BG_CARD_LIGHT
    s1_badge.line.color.rgb = C_ACCENT_BLUE
    tf = s1_badge.text_frame
    p = tf.paragraphs[0]
    p.text = "🛡️  NIDS / NIPS ACTIVE PROTECTION"
    p.font.name = FONT_HEADING
    p.font.size = Pt(10)
    p.font.bold = True
    p.font.color.rgb = C_ACCENT_BLUE
    p.alignment = PP_ALIGN.CENTER

    # Main Headline
    tb = s1.shapes.add_textbox(Inches(1.0), Inches(2.2), Inches(11.3), Inches(1.6))
    tf = tb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "NetSentinel Dashboard"
    p.font.name = FONT_HEADING
    p.font.size = Pt(44)
    p.font.bold = True
    p.font.color.rgb = C_TEXT_WHITE

    p2 = tf.add_paragraph()
    p2.text = "Operator Control Plane & Active Defense User Guide"
    p2.font.name = FONT_HEADING
    p2.font.size = Pt(26)
    p2.font.bold = True
    p2.font.color.rgb = C_ACCENT_BLUE

    # Sub-description
    tb_desc = s1.shapes.add_textbox(Inches(1.0), Inches(4.0), Inches(10.5), Inches(1.0))
    tf_d = tb_desc.text_frame
    tf_d.word_wrap = True
    p_d = tf_d.paragraphs[0]
    p_d.text = "A comprehensive operational walkthrough for Security Analysts, SOC Engineers, and Network Administrators navigating real-time threat detection, kernel nftables enforcement, human-in-the-loop approvals, and disaster recovery."
    p_d.font.name = FONT_BODY
    p_d.font.size = Pt(13)
    p_d.font.color.rgb = C_TEXT_OFFWHITE

    # 3 Summary Pillar Cards at bottom
    pillars = [
        ("Real-Time Telemetry", "3-second reactive polling for active blocks, quarantine, and audit events.", C_ACCENT_BLUE),
        ("Four Defense Modes", "Policy control ranging from passive monitor-only to strict active prevention.", C_ACCENT_AMBER),
        ("Kernel State Verification", "Strict post-enforcement validation with cryptographic SHA-256 audit logs.", C_ACCENT_GREEN),
    ]
    card_w = Inches(3.6)
    for i, (title, text, color) in enumerate(pillars):
        left_pos = Inches(1.0) + i * (card_w + Inches(0.25))
        add_card(s1, left_pos, Inches(5.2), card_w, Inches(1.4), title, color)
        tb_c = s1.shapes.add_textbox(left_pos + Inches(0.2), Inches(5.65), card_w - Inches(0.4), Inches(0.85))
        tf_c = tb_c.text_frame
        tf_c.word_wrap = True
        tf_c.margin_left = tf_c.margin_right = tf_c.margin_top = tf_c.margin_bottom = 0
        p_c = tf_c.paragraphs[0]
        p_c.text = text
        p_c.font.name = FONT_BODY
        p_c.font.size = Pt(11)
        p_c.font.color.rgb = C_TEXT_MUTED

    # ══════════════════════════════════════════════════════════════════════════════
    # SLIDE 2: Executive Overview & Architecture Concept
    # ══════════════════════════════════════════════════════════════════════════════
    s2 = prs.slides.add_slide(blank_layout)
    set_slide_background(s2)
    add_header(s2, "Executive Overview & Defense Architecture", "Bridging passive network intrusion monitoring and kernel-level active prevention", "CORE ARCHITECTURE")
    add_footer(s2, 2)

    col_w = Inches(3.68)
    cards_s2 = [
        ("The Challenge", "Passive NIDS (Snort/Suricata) alert analysts but cannot prevent lateral spread or data exfiltration in real time. Manual firewall edits introduce latency, human error, and dangerous lockouts.", C_ACCENT_RED, [
            "Delayed manual response enables attacker dwell time",
            "Complex firewall syntax leads to misconfigurations",
            "Lack of post-enforcement verification creates false sense of security"
        ]),
        ("NetSentinel Solution", "An intelligent policy engine combining multi-factor correlation, calibrated risk scoring (0-100), automated nftables prevention, and live state verification in a single dashboard.", C_ACCENT_BLUE, [
            "Calibrated risk scoring with safe AI anomaly capping",
            "Dedicated 'inet netsentinel' kernel tables with timed sets",
            "Immediate fail-safe rollback & 1-click Emergency Stop"
        ]),
        ("Operator Experience", "Empowers operators with clear visibility, impact preview before enforcement, live block countdown timers, and cryptographic SHA-256 tamper-evident audit trails.", C_ACCENT_GREEN, [
            "Intuitive modern dark-mode security HUD",
            "3-second real-time auto-refresh across all panels",
            "Interactive lab threat simulator for instant dry-run testing"
        ])
    ]

    for i, (title, desc, color, bullets) in enumerate(cards_s2):
        l = Inches(0.8) + i * (col_w + Inches(0.35))
        add_card(s2, l, Inches(2.0), col_w, Inches(4.75), title, color)

        tb = s2.shapes.add_textbox(l + Inches(0.2), Inches(2.5), col_w - Inches(0.4), Inches(1.3))
        tf = tb.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
        p = tf.paragraphs[0]
        p.text = desc
        p.font.name = FONT_BODY
        p.font.size = Pt(11.5)
        p.font.color.rgb = C_TEXT_OFFWHITE

        # Bullet list
        tb_b = s2.shapes.add_textbox(l + Inches(0.2), Inches(3.95), col_w - Inches(0.4), Inches(2.5))
        tf_b = tb_b.text_frame
        tf_b.word_wrap = True
        tf_b.margin_left = tf_b.margin_right = tf_b.margin_top = tf_b.margin_bottom = 0
        for b_text in bullets:
            p_b = tf_b.add_paragraph()
            p_b.text = f"•  {b_text}"
            p_b.font.name = FONT_BODY
            p_b.font.size = Pt(11)
            p_b.font.color.rgb = C_TEXT_MUTED
            p_b.space_after = Pt(8)

    # ══════════════════════════════════════════════════════════════════════════════
    # SLIDE 3: Getting Started & Dashboard Access
    # ══════════════════════════════════════════════════════════════════════════════
    s3 = prs.slides.add_slide(blank_layout)
    set_slide_background(s3)
    add_header(s3, "Launching & Connecting to the Dashboard", "Standard access procedure, universal launcher commands, and startup sequence", "DEPLOYMENT & ACCESS")
    add_footer(s3, 3)

    # Left Column: Step-by-Step launch
    w_left = Inches(5.7)
    add_card(s3, Inches(0.8), Inches(2.0), w_left, Inches(4.75), "Quick Start Execution Steps", C_ACCENT_BLUE)

    steps = [
        ("Step 1: Universal Launcher Execution", "Run 'netsentinel start' from any directory or execute './scripts/start_netsentinel.sh'. The engine initializes SQLite, creates nftables sets, and loads ML models."),
        ("Step 2: Verify Service Listener", "NetSentinel binds to 0.0.0.0:8000 via FastAPI & Uvicorn. The background expiration worker starts automatically with a 5-second scanning cycle."),
        ("Step 3: Open Browser Interface", "Point any modern browser to http://127.0.0.1:8000 (local) or http://<NODE_IP>:8000 (remote SOC workstation). No plugins or complex dependencies required."),
        ("Step 4: Automatic Polling Established", "The frontend establishes a 3000ms periodic poll (/api/status) to render real-time state, block counters, and device discovery telemetry.")
    ]

    tb_s = s3.shapes.add_textbox(Inches(1.0), Inches(2.5), w_left - Inches(0.4), Inches(4.1))
    tf_s = tb_s.text_frame
    tf_s.word_wrap = True
    tf_s.margin_left = tf_s.margin_right = tf_s.margin_top = tf_s.margin_bottom = 0

    for title, detail in steps:
        p_t = tf_s.add_paragraph()
        p_t.text = title
        p_t.font.name = FONT_HEADING
        p_t.font.size = Pt(12)
        p_t.font.bold = True
        p_t.font.color.rgb = C_ACCENT_BLUE

        p_d = tf_s.add_paragraph()
        p_d.text = detail
        p_d.font.name = FONT_BODY
        p_d.font.size = Pt(10.5)
        p_d.font.color.rgb = C_TEXT_OFFWHITE
        p_d.space_after = Pt(10)

    # Right Column: CLI Quick Reference Card & Startup Order
    w_right = Inches(5.68)
    add_card(s3, Inches(6.85), Inches(2.0), w_right, Inches(4.75), "CLI Control Reference & Startup Order", C_ACCENT_GREEN)

    tb_r = s3.shapes.add_textbox(Inches(7.05), Inches(2.5), w_right - Inches(0.4), Inches(4.1))
    tf_r = tb_r.text_frame
    tf_r.word_wrap = True
    tf_r.margin_left = tf_r.margin_right = tf_r.margin_top = tf_r.margin_bottom = 0

    commands = [
        ("netsentinel", "Starts web dashboard & protection daemon on port 8000"),
        ("netsentinel test", "Executes automated 26-test verification suite"),
        ("netsentinel simulate <1-6>", "Injects synthetic threat traffic for testing"),
        ("netsentinel verify", "Validates SHA-256 cryptographic audit chain integrity"),
        ("netsentinel recover", "Emergency: offline flush of all active nftables rules"),
        ("netsentinel export", "Dumps current active Linux nftables ruleset to stdout")
    ]

    p_lbl = tf_r.paragraphs[0]
    p_lbl.text = "Universal CLI Operations:"
    p_lbl.font.name = FONT_HEADING
    p_lbl.font.size = Pt(12)
    p_lbl.font.bold = True
    p_lbl.font.color.rgb = C_TEXT_WHITE
    p_lbl.space_after = Pt(6)

    for cmd, desc in commands:
        p_c = tf_r.add_paragraph()
        p_c.text = f"$ {cmd}"
        p_c.font.name = "Consolas"
        p_c.font.size = Pt(10.5)
        p_c.font.bold = True
        p_c.font.color.rgb = C_ACCENT_GREEN

        p_cd = tf_r.add_paragraph()
        p_cd.text = f"   → {desc}"
        p_cd.font.name = FONT_BODY
        p_cd.font.size = Pt(10)
        p_cd.font.color.rgb = C_TEXT_MUTED
        p_cd.space_after = Pt(4)

    # ══════════════════════════════════════════════════════════════════════════════
    # SLIDE 4: Dashboard Interface & Layout Topology
    # ══════════════════════════════════════════════════════════════════════════════
    s4 = prs.slides.add_slide(blank_layout)
    set_slide_background(s4)
    add_header(s4, "Dashboard Visual Topology & HUD Layout", "High-level visual breakdown of navigation, sidebar controls, and active telemetry panels", "HUD GEOMETRY")
    add_footer(s4, 4)

    hud_regions = [
        ("1. Top Navigation Bar", "Global System Controls", "Houses brand identity, live Mode indicator pulse dot, Dry-Run state badge, Toggle Dry-Run button, and the 1-Click EMERGENCY STOP kill switch.", Inches(0.8), Inches(2.0), Inches(11.733), Inches(1.1), C_ACCENT_BLUE),
        ("2. Operations Sidebar", "Policy & Aux Controls", "• Mode Selector: Modes A to D\n• ESP32 Hardware Status Card\n• Lab Threat Simulator Form for testing", Inches(0.8), Inches(3.25), Inches(3.6), Inches(3.5), C_ACCENT_PURPLE),
        ("3. Metrics Overview", "Live Tactical Counts", "Four real-time counter cards: Active Blocks, Mode B Pending Approvals, Quarantined Devices, and Verified Enforcements.", Inches(4.6), Inches(3.25), Inches(7.933), Inches(1.0), C_ACCENT_AMBER),
        ("4. Active Defense Grids", "Rule & Inventory Lifecycle", "• Active Blocks Table with real-time second-by-second countdowns & unblock buttons\n• Split Grid: Monitored LAN Inventory vs Quarantined Devices\n• Recent Response Actions & Verification Audit Table\n• Protected Infrastructure & Allowlist Manager", Inches(4.6), Inches(4.4), Inches(7.933), Inches(2.35), C_ACCENT_GREEN)
    ]

    for title, subtitle, desc, left, top, width, height, color in hud_regions:
        add_card(s4, left, top, width, height, f"{title} — {subtitle}", color)
        tb = s4.shapes.add_textbox(left + Inches(0.2), top + Inches(0.4), width - Inches(0.4), height - Inches(0.45))
        tf = tb.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
        for line in desc.split("\n"):
            p = tf.add_paragraph()
            p.text = line
            p.font.name = FONT_BODY
            p.font.size = Pt(10.5)
            p.font.color.rgb = C_TEXT_OFFWHITE
            p.space_after = Pt(2)

    # ══════════════════════════════════════════════════════════════════════════════
    # SLIDE 5: Global Controls & Emergency Protocols
    # ══════════════════════════════════════════════════════════════════════════════
    s5 = prs.slides.add_slide(blank_layout)
    set_slide_background(s5)
    add_header(s5, "Global Controls, Dry-Run & Emergency Kill Switch", "Essential fail-safes designed to prevent administrative lockouts and network disruption", "SAFETY & FAIL-SAFES")
    add_footer(s5, 5)

    col_w5 = Inches(3.68)
    cards_s5 = [
        ("Dry-Run Simulation Mode", "Safe Policy Evaluation", C_ACCENT_AMBER, [
            "Toggled instantly via the top navbar button without restarts",
            "Generates full nftables syntax and calculates impact in memory",
            "Records actions with 'dry_run: true' in audit database",
            "Zero kernel rules written — ideal for policy validation & training"
        ]),
        ("1-Click GUI Emergency Stop", "Immediate Tactical Reversion", C_ACCENT_RED, [
            "Triggered via red 'EMERGENCY STOP' button in top navbar",
            "Immediately flushes all active nftables elements in inet netsentinel",
            "Revokes active quarantines and halts automated enforcements",
            "Detection and packet analysis remain 100% active and unhalted",
            "Button switches to 'CLEAR EMERGENCY STOP' to restore operations"
        ]),
        ("Offline Emergency Recovery", "Disaster Recovery Tooling", C_ACCENT_BLUE, [
            "Executed via CLI: 'netsentinel recover' or shell script",
            "Operates offline with zero dependency on the web server or DB",
            "Safely flushes dedicated NetSentinel tables without altering system rules",
            "Guarantees admin SSH (Port 22) and core routing are never stranded"
        ])
    ]

    for i, (title, sub, color, points) in enumerate(cards_s5):
        l = Inches(0.8) + i * (col_w5 + Inches(0.35))
        add_card(s5, l, Inches(2.0), col_w5, Inches(4.75), title, color)

        tb_sub = s5.shapes.add_textbox(l + Inches(0.2), Inches(2.45), col_w5 - Inches(0.4), Inches(0.3))
        tf_sub = tb_sub.text_frame
        tf_sub.margin_left = tf_sub.margin_right = tf_sub.margin_top = tf_sub.margin_bottom = 0
        p_sub = tf_sub.paragraphs[0]
        p_sub.text = sub.upper()
        p_sub.font.name = FONT_HEADING
        p_sub.font.size = Pt(10)
        p_sub.font.color.rgb = color

        tb = s5.shapes.add_textbox(l + Inches(0.2), Inches(2.8), col_w5 - Inches(0.4), Inches(3.8))
        tf = tb.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
        for pt in points:
            p = tf.add_paragraph()
            p.text = f"•  {pt}"
            p.font.name = FONT_BODY
            p.font.size = Pt(11)
            p.font.color.rgb = C_TEXT_OFFWHITE
            p.space_after = Pt(8)

    # ══════════════════════════════════════════════════════════════════════════════
    # SLIDE 6: The 4 Selectable Protection Modes
    # ══════════════════════════════════════════════════════════════════════════════
    s6 = prs.slides.add_slide(blank_layout)
    set_slide_background(s6)
    add_header(s6, "The Four Selectable Protection Modes (Modes A – D)", "Policy-driven operational postures matching organizational risk tolerance", "PROTECTION MODES")
    add_footer(s6, 6)

    modes = [
        ("Mode A: Monitor Only", "Zero Firewall Alteration", C_ACCENT_BLUE, [
            "Passively ingests packet telemetry and IDS alerts",
            "Performs multi-factor correlation & risk scoring",
            "Logs detections to dashboard & audit trail",
            "Guarantees zero packet modification or rule injection"
        ]),
        ("Mode B: Assisted Protection", "Human Operator Sign-Off Required", C_ACCENT_AMBER, [
            "Calculates proposed nftables rule and blast impact",
            "Generates pending approval card in dashboard banner",
            "Operator reviews risk score & rule before enforcement",
            "Provides one-click Authorize or Reject capabilities"
        ]),
        ("Mode C: Auto Temporary", "Automated Low-Risk Blocks with Expiry", C_ACCENT_GREEN, [
            "Automatically mitigates high-confidence threats (Score ≥ 60)",
            "Enforces temporary blocks with mandatory TTL expiry (e.g. 300s)",
            "Automatic background rollback via scheduled worker",
            "Bypasses critical gateway and allowlisted infrastructure"
        ]),
        ("Mode D: Strict Prevention", "Immediate Boundary Defense", C_ACCENT_RED, [
            "Immediate boundary enforcement against high-risk threats (Score ≥ 80)",
            "Enforces DNS sinkholing (0.0.0.0) against malicious domains",
            "Applies aggressive source connection rate limiting",
            "Strict preservation of essential admin management channels"
        ])
    ]

    card_w6 = Inches(2.7)
    for i, (m_title, m_sub, m_col, m_pts) in enumerate(modes):
        l = Inches(0.8) + i * (card_w6 + Inches(0.3))
        add_card(s6, l, Inches(2.0), card_w6, Inches(4.75), m_title, m_col)

        tb_sub = s6.shapes.add_textbox(l + Inches(0.15), Inches(2.45), card_w6 - Inches(0.3), Inches(0.35))
        tf_sub = tb_sub.text_frame
        tf_sub.word_wrap = True
        tf_sub.margin_left = tf_sub.margin_right = tf_sub.margin_top = tf_sub.margin_bottom = 0
        p_sub = tf_sub.paragraphs[0]
        p_sub.text = m_sub.upper()
        p_sub.font.name = FONT_HEADING
        p_sub.font.size = Pt(9.5)
        p_sub.font.color.rgb = m_col

        tb = s6.shapes.add_textbox(l + Inches(0.15), Inches(2.9), card_w6 - Inches(0.3), Inches(3.7))
        tf = tb.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
        for pt in m_pts:
            p = tf.add_paragraph()
            p.text = f"• {pt}"
            p.font.name = FONT_BODY
            p.font.size = Pt(10.5)
            p.font.color.rgb = C_TEXT_OFFWHITE
            p.space_after = Pt(6)

    # ══════════════════════════════════════════════════════════════════════════════
    # SLIDE 7: Operator Approval Workflow (Mode B In Action)
    # ══════════════════════════════════════════════════════════════════════════════
    s7 = prs.slides.add_slide(blank_layout)
    set_slide_background(s7)
    add_header(s7, "Operator Approval Workflow (Mode B In Action)", "Human-in-the-loop validation process for high-impact protective actions", "WORKFLOW & APPROVALS")
    add_footer(s7, 7)

    # Left Card: Flow Steps
    add_card(s7, Inches(0.8), Inches(2.0), Inches(5.7), Inches(4.75), "Mode B Human Decision Lifecycle", C_ACCENT_AMBER)
    tb_wf = s7.shapes.add_textbox(Inches(1.0), Inches(2.5), Inches(5.3), Inches(4.1))
    tf_wf = tb_wf.text_frame
    tf_wf.word_wrap = True
    tf_wf.margin_left = tf_wf.margin_right = tf_wf.margin_top = tf_wf.margin_bottom = 0

    wf_steps = [
        ("1. Threat Detected & Correlated", "An attack (e.g. brute-force) triggers correlation. Risk score exceeds threshold, but Mode B dictates zero autonomous changes without sign-off."),
        ("2. Approval Request Generated", "A yellow alert banner dynamically mounts at the top of the dashboard displaying Target IP, Action Type, Risk Score, and Impact assessment."),
        ("3. Impact Confirmation Review", "Operator clicks 'Review & Authorize'. A dedicated modal presents the exact proposed nftables rule syntax, potential service blast radius, and rule duration."),
        ("4. Operator Decision & Verification", "Authorizing executes the rule in kernel state and runs post-enforcement verification. Rejecting archives the event with an audit justification.")
    ]

    for title, detail in wf_steps:
        p_t = tf_wf.add_paragraph()
        p_t.text = title
        p_t.font.name = FONT_HEADING
        p_t.font.size = Pt(11.5)
        p_t.font.bold = True
        p_t.font.color.rgb = C_ACCENT_AMBER

        p_d = tf_wf.add_paragraph()
        p_d.text = detail
        p_d.font.name = FONT_BODY
        p_d.font.size = Pt(10)
        p_d.font.color.rgb = C_TEXT_OFFWHITE
        p_d.space_after = Pt(8)

    # Right Card: UI Mockup / Field Breakdown
    add_card(s7, Inches(6.85), Inches(2.0), Inches(5.68), Inches(4.75), "Approval Modal Data Elements", C_ACCENT_BLUE)
    tb_m = s7.shapes.add_textbox(Inches(7.05), Inches(2.5), Inches(5.28), Inches(4.1))
    tf_m = tb_m.text_frame
    tf_m.word_wrap = True
    tf_m.margin_left = tf_m.margin_right = tf_m.margin_top = tf_m.margin_bottom = 0

    modal_fields = [
        ("Target", "e.g. 198.51.100.77 (Identifies source IP, subnet, or domain)"),
        ("Action Type", "e.g. BLOCK_SOURCE_IP or ISOLATE_ENDPOINT"),
        ("Risk Score", "Calibrated numeric score (0-100) combining IDS + Anomaly + TTL"),
        ("Proposed Rule", "Exact kernel command: nft add element inet netsentinel blocked_v4 { 198.51.100.77 timeout 300s }"),
        ("Potential Impact", "Clear plain-language impact (e.g. Drops inbound connections from external host; internal LAN unaffected)"),
        ("Duration", "Automatic expiry lifespan in seconds (default: 300s)"),
        ("Buttons", "[Reject Action] (Safe discard) vs [Authorize & Enforce] (Kernel execution)")
    ]

    for field, detail in modal_fields:
        p_f = tf_m.add_paragraph()
        p_f.text = f"{field}:"
        p_f.font.name = FONT_HEADING
        p_f.font.size = Pt(11)
        p_f.font.bold = True
        p_f.font.color.rgb = C_TEXT_WHITE

        p_fd = tf_m.add_paragraph()
        p_fd.text = f"  {detail}"
        p_fd.font.name = FONT_BODY
        p_fd.font.size = Pt(10)
        p_fd.font.color.rgb = C_TEXT_MUTED
        p_fd.space_after = Pt(4)

    # ══════════════════════════════════════════════════════════════════════════════
    # SLIDE 8: Active Firewall Enforcement & Expiry Management
    # ══════════════════════════════════════════════════════════════════════════════
    s8 = prs.slides.add_slide(blank_layout)
    set_slide_background(s8)
    add_header(s8, "Active Firewall Enforcement & Expiry Management", "Real-time kernel nftables tracking with live countdowns and fail-safe unblocking", "FIREWALL CONTROLS")
    add_footer(s8, 8)

    col_w8 = Inches(3.68)
    cards_s8 = [
        ("Kernel 'nftables' Integration", "Dedicated Namespace Architecture", C_ACCENT_BLUE, [
            "All NetSentinel rules exist in a dedicated 'inet netsentinel' table",
            "Never interferes with host base firewall or Docker/container tables",
            "Leverages native timed sets ('timeout 300s') for automatic expiry",
            "Zero stale rule buildup even during heavy attack campaigns"
        ]),
        ("Live Block Countdown HUD", "Real-Time Table Telemetry", C_ACCENT_GREEN, [
            "Lists target IP, detection reason, and risk score badge",
            "Displays dynamic live countdown: 'Expires In: 284s'",
            "Calculates time remaining directly from UTC timestamp delta",
            "Provides instant visual feedback on upcoming auto-rollbacks"
        ]),
        ("Unblock & Background Worker", "Fail-Safe Expiry Lifecycle", C_ACCENT_AMBER, [
            "Background expiration worker polls every 5 seconds per Section 14.11",
            "Expires database records and syncs with kernel state",
            "Manual 'Unblock' button enables instant early rule revocation",
            "Full cryptographic audit logging of unblock reason and operator ID"
        ])
    ]

    for i, (title, sub, color, pts) in enumerate(cards_s8):
        l = Inches(0.8) + i * (col_w8 + Inches(0.35))
        add_card(s8, l, Inches(2.0), col_w8, Inches(4.75), title, color)

        tb_sub = s8.shapes.add_textbox(l + Inches(0.2), Inches(2.45), col_w8 - Inches(0.4), Inches(0.3))
        tf_sub = tb_sub.text_frame
        tf_sub.margin_left = tf_sub.margin_right = tf_sub.margin_top = tf_sub.margin_bottom = 0
        p_sub = tf_sub.paragraphs[0]
        p_sub.text = sub.upper()
        p_sub.font.name = FONT_HEADING
        p_sub.font.size = Pt(10)
        p_sub.font.color.rgb = color

        tb = s8.shapes.add_textbox(l + Inches(0.2), Inches(2.8), col_w8 - Inches(0.4), Inches(3.8))
        tf = tb.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
        for pt in pts:
            p = tf.add_paragraph()
            p.text = f"•  {pt}"
            p.font.name = FONT_BODY
            p.font.size = Pt(11)
            p.font.color.rgb = C_TEXT_OFFWHITE
            p.space_after = Pt(8)

    # ══════════════════════════════════════════════════════════════════════════════
    # SLIDE 9: Endpoint Inventory, Quarantine & Allowlisting
    # ══════════════════════════════════════════════════════════════════════════════
    s9 = prs.slides.add_slide(blank_layout)
    set_slide_background(s9)
    add_header(s9, "Endpoint Inventory, Quarantine & Allowlisting", "Managing internal network assets, containment protocols, and protected infrastructure", "ASSET MANAGEMENT")
    add_footer(s9, 9)

    col_w9 = Inches(3.68)
    cards_s9 = [
        ("Monitored Device Inventory", "LAN Discovery & Trust States", C_ACCENT_BLUE, [
            "Tracks IP, MAC address, hostname, and active protocols",
            "Trust status states: Trusted, Unknown, Suspicious, Restricted",
            "Safe Discovery Rule: Unknown devices trigger observation, NEVER immediate disconnection",
            "One-click 'Trust' button promotes known endpoints"
        ]),
        ("Endpoint Quarantine", "LAN Host Containment", C_ACCENT_PURPLE, [
            "Isolates compromised internal endpoints showing lateral spread",
            "Restricts traffic to observation VLAN or drops non-essential packets",
            "Preserves emergency admin communication and forensics",
            "Instant 'Release' button safely restores client access"
        ]),
        ("Protected Infrastructure Allowlist", "Bypassing Response Safeguards", C_ACCENT_GREEN, [
            "Pre-seeded with default gateway, DNS servers, and loopback",
            "Strict Step 3 Response Safeguard prevents accidental lockout",
            "Click '+ Add Asset' to whitelist critical servers or subnets",
            "Shield badge indicates protected asset status across dashboard"
        ])
    ]

    for i, (title, sub, color, pts) in enumerate(cards_s9):
        l = Inches(0.8) + i * (col_w9 + Inches(0.35))
        add_card(s9, l, Inches(2.0), col_w9, Inches(4.75), title, color)

        tb_sub = s9.shapes.add_textbox(l + Inches(0.2), Inches(2.45), col_w9 - Inches(0.4), Inches(0.3))
        tf_sub = tb_sub.text_frame
        tf_sub.margin_left = tf_sub.margin_right = tf_sub.margin_top = tf_sub.margin_bottom = 0
        p_sub = tf_sub.paragraphs[0]
        p_sub.text = sub.upper()
        p_sub.font.name = FONT_HEADING
        p_sub.font.size = Pt(10)
        p_sub.font.color.rgb = color

        tb = s9.shapes.add_textbox(l + Inches(0.2), Inches(2.8), col_w9 - Inches(0.4), Inches(3.8))
        tf = tb.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
        for pt in pts:
            p = tf.add_paragraph()
            p.text = f"•  {pt}"
            p.font.name = FONT_BODY
            p.font.size = Pt(11)
            p.font.color.rgb = C_TEXT_OFFWHITE
            p.space_after = Pt(8)

    # ══════════════════════════════════════════════════════════════════════════════
    # SLIDE 10: Built-In Lab Threat Simulator
    # ══════════════════════════════════════════════════════════════════════════════
    s10 = prs.slides.add_slide(blank_layout)
    set_slide_background(s10)
    add_header(s10, "The Built-In Lab Threat Simulator", "Validating defensive posture and training operators without external attack infrastructure", "THREAT SIMULATION")
    add_footer(s10, 10)

    # Left Column: Simulator Capabilities
    add_card(s10, Inches(0.8), Inches(2.0), Inches(5.7), Inches(4.75), "Interactive In-Dashboard Simulator", C_ACCENT_PURPLE)
    tb_sim = s10.shapes.add_textbox(Inches(1.0), Inches(2.5), Inches(5.3), Inches(4.1))
    tf_sim = tb_sim.text_frame
    tf_sim.word_wrap = True
    tf_sim.margin_left = tf_sim.margin_right = tf_sim.margin_top = tf_sim.margin_bottom = 0

    sim_features = [
        ("No External Attack Tools Required", "Located directly in the dashboard sidebar. Operators can test any protection policy without needing external Nmap, Hydra, or Metasploit setups."),
        ("Configurable Attack Vectors", "Test Port Scanning, SSH/Auth Brute-Force, DoS Rate Anomalies, Malware C2 domain queries, Unauthorized Devices, and AI Anomaly events."),
        ("Calibrated Scoring Inputs", "Customize target IP, IDS Severity (0-100), and AI Anomaly Score (0-100) to observe how the correlation engine responds to varying threat thresholds."),
        ("Immediate Policy Feedback", "Generates an instant alert modal displaying final risk evaluation score, severity classification, and outcome action status.")
    ]

    for title, detail in sim_features:
        p_t = tf_sim.add_paragraph()
        p_t.text = title
        p_t.font.name = FONT_HEADING
        p_t.font.size = Pt(11.5)
        p_t.font.bold = True
        p_t.font.color.rgb = C_ACCENT_PURPLE

        p_d = tf_sim.add_paragraph()
        p_d.text = detail
        p_d.font.name = FONT_BODY
        p_d.font.size = Pt(10)
        p_d.font.color.rgb = C_TEXT_OFFWHITE
        p_d.space_after = Pt(8)

    # Right Column: CLI Simulation Scenarios Reference Table
    add_card(s10, Inches(6.85), Inches(2.0), Inches(5.68), Inches(4.75), "CLI Simulation Scenarios (1–6)", C_ACCENT_BLUE)
    tb_cli = s10.shapes.add_textbox(Inches(7.05), Inches(2.5), Inches(5.28), Inches(4.1))
    tf_cli = tb_cli.text_frame
    tf_cli.word_wrap = True
    tf_cli.margin_left = tf_cli.margin_right = tf_cli.margin_top = tf_cli.margin_bottom = 0

    scenarios = [
        ("netsentinel simulate 1", "Port Scan (Nmap SYN reconnaissance) → Triggers Connection Rate Limiting"),
        ("netsentinel simulate 2", "SSH / Auth Brute Force → Triggers Temporary Firewall Block (5 min TTL)"),
        ("netsentinel simulate 3", "Malware C2 Communication → Triggers DNS Sinkholing (0.0.0.0 destination)"),
        ("netsentinel simulate 4", "DDoS Flood / Rate Anomaly → Triggers Dynamic Traffic Throttling"),
        ("netsentinel simulate 5", "Lateral Movement Probe → Verifies Endpoint Quarantine Policy"),
        ("netsentinel simulate 6", "Allowlisted Gateway Traffic → Proves Infrastructure Safeguard Protection")
    ]

    p_header = tf_cli.paragraphs[0]
    p_header.text = "Available Command Scenarios:"
    p_header.font.name = FONT_HEADING
    p_header.font.size = Pt(11.5)
    p_header.font.bold = True
    p_header.font.color.rgb = C_TEXT_WHITE
    p_header.space_after = Pt(6)

    for cmd, desc in scenarios:
        p_cmd = tf_cli.add_paragraph()
        p_cmd.text = f"$ {cmd}"
        p_cmd.font.name = "Consolas"
        p_cmd.font.size = Pt(10.5)
        p_cmd.font.bold = True
        p_cmd.font.color.rgb = C_ACCENT_BLUE

        p_cd = tf_cli.add_paragraph()
        p_cd.text = f"  {desc}"
        p_cd.font.name = FONT_BODY
        p_cd.font.size = Pt(9.5)
        p_cd.font.color.rgb = C_TEXT_MUTED
        p_cd.space_after = Pt(4)

    # ══════════════════════════════════════════════════════════════════════════════
    # SLIDE 11: Verification Engine & Cryptographic Audit Trail
    # ══════════════════════════════════════════════════════════════════════════════
    s11 = prs.slides.add_slide(blank_layout)
    set_slide_background(s11)
    add_header(s11, "Verification Engine & Cryptographic Audit Trail", "Honest reporting via kernel state verification and tamper-evident SHA-256 chaining", "AUDIT & FORENSICS")
    add_footer(s11, 11)

    col_w11 = Inches(5.7)
    # Left Card: Step 7 Verification
    add_card(s11, Inches(0.8), Inches(2.0), col_w11, Inches(4.75), "Step 7: Post-Enforcement Kernel Verification", C_ACCENT_GREEN)
    tb_v = s11.shapes.add_textbox(Inches(1.0), Inches(2.5), col_w11 - Inches(0.4), Inches(4.1))
    tf_v = tb_v.text_frame
    tf_v.word_wrap = True
    tf_v.margin_left = tf_v.margin_right = tf_v.margin_top = tf_v.margin_bottom = 0

    v_points = [
        ("Honest Reporting Mandate", "Section 14.11 Step 8 requires NetSentinel to verify before reporting success. A threat is NEVER displayed as blocked based purely on command dispatch."),
        ("Direct Kernel Querying", "Immediately after issuing an nft command, ResponseVerifier queries the Linux kernel sets directly to confirm element presence:"),
        ("Verified Badge Display", "Enforcements confirmed in the kernel display a green 'VERIFIED' badge. If element insertion fails, the system displays 'FAILED' and triggers an alert."),
        ("Impact Metric Counter", "The dashboard's top metric card 'Verified Enforcements' tallies all confirmed enforcements, providing an accurate defense scorecard.")
    ]

    for title, detail in v_points:
        p_t = tf_v.add_paragraph()
        p_t.text = title
        p_t.font.name = FONT_HEADING
        p_t.font.size = Pt(11.5)
        p_t.font.bold = True
        p_t.font.color.rgb = C_ACCENT_GREEN

        p_d = tf_v.add_paragraph()
        p_d.text = detail
        p_d.font.name = FONT_BODY
        p_d.font.size = Pt(10)
        p_d.font.color.rgb = C_TEXT_OFFWHITE
        p_d.space_after = Pt(8)

    # Right Card: Cryptographic Audit Trail
    add_card(s11, Inches(6.85), Inches(2.0), Inches(5.68), Inches(4.75), "Section 14.13 Tamper-Evident Hash Chaining", C_ACCENT_BLUE)
    tb_a = s11.shapes.add_textbox(Inches(7.05), Inches(2.5), Inches(5.28), Inches(4.1))
    tf_a = tb_a.text_frame
    tf_a.word_wrap = True
    tf_a.margin_left = tf_a.margin_right = tf_a.margin_top = tf_a.margin_bottom = 0

    a_points = [
        ("Cryptographic Hash Chaining", "Every policy shift, firewall enforcement, approval, rollback, and emergency stop is recorded with a SHA-256 hash incorporating the previous entry's hash."),
        ("Chain Equation", "Hash(n) = SHA256( Hash(n-1) || Timestamp || Operator || EventType || Details || HMAC_Key )"),
        ("Forensic Tamper Detection", "Any unauthorized alteration, row deletion, or retroactive edit in the SQLite database breaks the cryptographic chain and triggers an immediate verification fault."),
        ("Instant Chain Validation", "Operators can verify total chain integrity at any time via CLI or API:\n$ netsentinel verify\nReturns: Validated records count & integrity status.")
    ]

    for title, detail in a_points:
        p_t = tf_a.add_paragraph()
        p_t.text = title
        p_t.font.name = FONT_HEADING
        p_t.font.size = Pt(11.5)
        p_t.font.bold = True
        p_t.font.color.rgb = C_ACCENT_BLUE

        p_d = tf_a.add_paragraph()
        p_d.text = detail
        p_d.font.name = FONT_BODY
        p_d.font.size = Pt(10)
        p_d.font.color.rgb = C_TEXT_OFFWHITE
        p_d.space_after = Pt(8)

    # ══════════════════════════════════════════════════════════════════════════════
    # SLIDE 12: Standard Operating Procedures (SOP) & Daily SOC Operations
    # ══════════════════════════════════════════════════════════════════════════════
    s12 = prs.slides.add_slide(blank_layout)
    set_slide_background(s12)
    add_header(s12, "Standard Operating Procedures (SOP) Reference", "Daily shift checklist, threat triage escalation workflow, and key command cheat sheet", "SOC SOP CHEAT SHEET")
    add_footer(s12, 12)

    col_w12 = Inches(3.68)
    cards_s12 = [
        ("Daily Shift Checklist", "SOC Morning Routine", C_ACCENT_BLUE, [
            "1. Verify Service Health: Check http://localhost:8000 loads with live pulsing dot",
            "2. Confirm Protection Mode: Ensure system is in designated Mode (Mode B or C)",
            "3. Review Hardware Status: Verify ESP32 is Online and Tamper Sensor is SECURED",
            "4. Check Active Blocks: Review active blocks and remaining countdown timers",
            "5. Verify Audit Chain: Run 'netsentinel verify' to ensure zero log tampering"
        ]),
        ("Incident Triage Workflow", "Handling Threat Alerts", C_ACCENT_AMBER, [
            "1. Mode B Alert Surface: Review target IP and potential impact before approving",
            "2. Verify Indicator Score: Check if threat is isolated (low score) or correlated (high score)",
            "3. Assess Impact: Confirm target is not a legitimate internal server or external partner",
            "4. Authorize or Reject: Authorize temporary block (default 300s TTL) or reject",
            "5. Early Unblock: If a false positive occurs, click Unblock or execute Rollback"
        ]),
        ("Emergency Triage Protocol", "Incident Containment", C_ACCENT_RED, [
            "• Network Outage Detected: Click red 'EMERGENCY STOP' button immediately",
            "• CLI Emergency Recovery: If web UI is unreachable, run 'netsentinel recover'",
            "• Rule Dump Inspection: Run 'netsentinel export' to view raw kernel rules",
            "• Test Suite Run: Run 'netsentinel test' to ensure all 26 verification tests pass",
            "• Whitelist Addition: Add affected essential IPs to Allowlist panel"
        ])
    ]

    for i, (title, sub, color, pts) in enumerate(cards_s12):
        l = Inches(0.8) + i * (col_w12 + Inches(0.35))
        add_card(s12, l, Inches(2.0), col_w12, Inches(4.75), title, color)

        tb_sub = s12.shapes.add_textbox(l + Inches(0.2), Inches(2.45), col_w12 - Inches(0.4), Inches(0.3))
        tf_sub = tb_sub.text_frame
        tf_sub.margin_left = tf_sub.margin_right = tf_sub.margin_top = tf_sub.margin_bottom = 0
        p_sub = tf_sub.paragraphs[0]
        p_sub.text = sub.upper()
        p_sub.font.name = FONT_HEADING
        p_sub.font.size = Pt(10)
        p_sub.font.color.rgb = color

        tb = s12.shapes.add_textbox(l + Inches(0.2), Inches(2.8), col_w12 - Inches(0.4), Inches(3.8))
        tf = tb.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
        for pt in pts:
            p = tf.add_paragraph()
            p.text = f"{pt}"
            p.font.name = FONT_BODY
            p.font.size = Pt(10.5)
            p.font.color.rgb = C_TEXT_OFFWHITE
            p.space_after = Pt(6)

    prs.save(output_path)
    print(f"Successfully generated presentation: {output_path}")

if __name__ == "__main__":
    out_file = "/home/abhi/NetSentinel/NetSentinel_Dashboard_Guide.pptx"
    if len(sys.argv) > 1:
        out_file = sys.argv[1]
    create_deck(out_file)
