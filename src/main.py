import warnings
warnings.filterwarnings("ignore") 
import os
os.environ["GRPC_VERBOSITY"] = "ERROR" 

import pandas as pd
import tkinter as tk
from tkinter import ttk, font, messagebox, filedialog, scrolledtext
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.backends.backend_pdf import PdfPages
import matplotlib.pyplot as plt
import seaborn as sns
from engine import NIDSEngine
import datetime
import threading
import textwrap
import re

# --- DESIGN SYSTEM ---
COLOR_BG = "#141414"
COLOR_CARD = "#1f1f1f"
COLOR_ACCENT = "#E50914" 
COLOR_SUCCESS = "#46c35f"
COLOR_YELLOW = "#FFD700" 
COLOR_TEXT = "#FFFFFF"
COLOR_SUBTEXT = "#B3B3B3"
COLOR_TERMINAL = "#00FF00"

# --- THEME PALETTE ---
GUCCI_GREEN = "#083315"
GUCCI_RED   = "#E01111"
GUCCI_GOLD  = "#FFD700"
GUCCI_BG    = "#031c0a"
COLOR_NEON_GREEN = "#39FF14"
COLOR_BLUE_ROYAL = "#4da6ff"
BLOCK_FONT  = "Courier"

try:
    from ctypes import windll
    windll.shcore.SetProcessDpiAwareness(1)
except:
    pass

class RoundedButton(tk.Canvas):
    def __init__(self, parent, text, command, bg, fg, width=150, height=40, corner_radius=20):
        super().__init__(parent, borderwidth=0, highlightthickness=0, bg=parent["bg"], cursor="hand2")
        self.command = command
        self.bg_color = bg
        self.fg_color = fg
        self.width = width
        self.height = height
        self.corner_radius = corner_radius
        self.config(width=self.width, height=self.height)
        self.rect = self._draw_rounded_rect()
        self.text_item = self.create_text(self.width/2, self.height/2, text=text, fill=self.fg_color, font=("Segoe UI", 10, "bold"))
        self.bind("<Button-1>", self._on_click)

    def _draw_rounded_rect(self):
        r = self.corner_radius; w = self.width; h = self.height
        shape = self.create_polygon(r,0, w-r,0, w,0, w,r, w,h-r, w,h, w-r,h, r,h, 0,h, 0,h-r, 0,r, 0,0, smooth=True, fill=self.bg_color)
        return shape

    def _on_click(self, event):
        if self.command: self.command()

    def config_text(self, text):
        self.itemconfig(self.text_item, text=text)

class NIDS_GUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.engine = NIDSEngine()
        self.selected_csv_path = None 
        self.latest_metrics = None 
        self.current_packet = None 
        self.current_pred = None
        self.current_ai_response = ""
        self.log_buffer = [] 
        
        self.title("AI-Based Network Intrusion Detection System")
        self.geometry("1600x1000") 
        self.configure(bg=COLOR_BG)
        
        self.font_hero = font.Font(family="Segoe UI", size=32, weight="bold")
        self.font_h2 = font.Font(family="Segoe UI", size=16, weight="bold")
        self.font_body = font.Font(family="Segoe UI", size=11)
        self.font_mono = font.Font(family="Consolas", size=10)

        self._configure_styles()
        self._init_layout_structure()

    def _configure_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        
        style.configure("Treeview", background="#262626", foreground="white", fieldbackground="#262626", font=("Consolas", 10), rowheight=25, borderwidth=0)
        style.configure("Treeview.Heading", background="#333", foreground="#E5E5E5", font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[('selected', COLOR_ACCENT)])

        style.configure("Gucci.Treeview", background=GUCCI_BG, foreground=GUCCI_GOLD, fieldbackground=GUCCI_BG, font=("Courier", 10, "bold"), rowheight=25, borderwidth=0)
        style.configure("Gucci.Treeview.Heading", background=GUCCI_GREEN, foreground="white", font=("Courier", 11, "bold"), relief="solid")
        style.map("Gucci.Treeview", background=[('selected', GUCCI_RED)])

    def _init_layout_structure(self):
        main_container = tk.Frame(self, bg=COLOR_BG)
        main_container.pack(fill=tk.BOTH, expand=True)
        self.canvas = tk.Canvas(main_container, bg=COLOR_BG, highlightthickness=0)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = ttk.Scrollbar(main_container, orient=tk.VERTICAL, command=self.canvas.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.canvas.configure(yscrollcommand=scrollbar.set)
        self.content_frame = tk.Frame(self.canvas, bg=COLOR_BG)
        self.canvas_window = self.canvas.create_window((0, 0), window=self.content_frame, anchor="nw")
        
        self.bind_all("<MouseWheel>", lambda event: self.canvas.yview_scroll(int(-1*(event.delta/120)), "units"))
        self.content_frame.bind('<Configure>', lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind('<Configure>', lambda e: self.canvas.itemconfig(self.canvas_window, width=e.width))
        self._build_grid_layout()

    def _build_grid_layout(self):
        self.content_frame.grid_columnconfigure(0, weight=1) 
        self.content_frame.grid_columnconfigure(1, weight=30) 
        self.content_frame.grid_columnconfigure(2, weight=1) 

        main_stage = tk.Frame(self.content_frame, bg=COLOR_BG)
        main_stage.grid(row=0, column=1, sticky="nsew", pady=20)
        self._build_navbar(main_stage)
        
        columns = tk.Frame(main_stage, bg=COLOR_BG)
        columns.pack(fill=tk.BOTH, expand=True)
        columns.grid_columnconfigure(0, weight=4, uniform="col") 
        columns.grid_columnconfigure(1, weight=6, uniform="col") 

        left_col = tk.Frame(columns, bg=COLOR_BG)
        left_col.grid(row=0, column=0, sticky="nsew", padx=(0, 20))
        right_col = tk.Frame(columns, bg=COLOR_BG)
        right_col.grid(row=0, column=1, sticky="nsew", padx=(0, 0))

        # --- PANELS ---
        self._build_hero(left_col)
        self._create_card(left_col, "Configuration", self._build_controls)
        self._create_card(left_col, "Performance Metrics", self._build_metrics)
        self._create_card(left_col, "Live Packet Stimulation", self._build_injection_panel)

        self.viz_frame = self._create_card(right_col, "Visual Diagnostics", None)
        self._build_minecraft_analyst_dashboard(right_col)

        self._build_terminal(main_stage)

    def _build_navbar(self, parent):
        nav = tk.Frame(parent, bg=COLOR_BG, height=60)
        nav.pack(fill=tk.X, pady=(0, 20))
        tk.Label(nav, text="  VOIS", font=("Impact", 28), fg=COLOR_ACCENT, bg=COLOR_BG).pack(side=tk.LEFT)
        tk.Label(nav, text="|  AI-Based NIDS (Network Intrusion Detection System)", font=self.font_h2, fg=COLOR_SUBTEXT, bg=COLOR_BG).pack(side=tk.LEFT, padx=15)
        self.btn_report = RoundedButton(nav, text="⇩ REPORT", bg="white", fg="black", command=self.generate_report, width=120, height=35)
        self.btn_report.pack(side=tk.RIGHT)

    def _build_hero(self, parent):
        hero = tk.Frame(parent, bg=COLOR_CARD, height=200) 
        hero.pack(fill=tk.X, pady=(0, 20))
        hero.pack_propagate(False) 
        inner = tk.Frame(hero, bg=COLOR_CARD)
        inner.place(relx=0.05, rely=0.1, relwidth=0.9, relheight=0.9)
        tk.Label(inner, text="System Status: WAITING", font=("Segoe UI", 24, "bold"), fg=COLOR_TEXT, bg=COLOR_CARD).pack(anchor="w")
        tk.Label(inner, text="Intelligent Network Defense. Load dataset to begin analysis.", font=self.font_body, fg=COLOR_SUBTEXT, bg=COLOR_CARD).pack(anchor="w")
        btn_row = tk.Frame(inner, bg=COLOR_CARD)
        btn_row.pack(anchor="w", pady=15)
        self.train_btn = RoundedButton(btn_row, text="INITIALIZE", command=self.run_training, bg=COLOR_YELLOW, fg="black", width=140, height=40)
        self.train_btn.pack(side=tk.LEFT, padx=(0, 15))
        RoundedButton(btn_row, text="RESET", command=self.reset_system, bg="#333", fg="white", width=100, height=40).pack(side=tk.LEFT)

    def _create_card(self, parent, title, builder):
        card = tk.Frame(parent, bg=COLOR_CARD)
        card.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
        header = tk.Frame(card, bg=COLOR_CARD)
        header.pack(fill=tk.X, padx=20, pady=(15, 10))
        tk.Label(header, text=title, font=self.font_h2, fg=COLOR_TEXT, bg=COLOR_CARD).pack(side=tk.LEFT)
        content = tk.Frame(card, bg=COLOR_CARD)
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        if builder: builder(content)
        return content

    def _build_minecraft_analyst_dashboard(self, parent):
        card = tk.Frame(parent, bg=GUCCI_GREEN, bd=2, relief="solid")
        card.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
        
        header = tk.Frame(card, bg=COLOR_CARD, height=50) 
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        
        tk.Label(header, text=" [ ANALYST DASHBOARD ] ", font=(BLOCK_FONT, 14, "bold"), fg="white", bg=COLOR_CARD).pack(side=tk.LEFT, padx=10, pady=5)
        self.lbl_status = tk.Label(header, text="STATUS: UNKNOWN", fg="white", bg="#333", font=(BLOCK_FONT, 14, "bold"), padx=15)
        self.lbl_status.pack(side=tk.RIGHT, padx=10, pady=5)

        content = tk.Frame(card, bg=GUCCI_BG)
        content.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        tools = tk.Frame(content, bg=GUCCI_BG)
        tools.pack(fill=tk.X, pady=(0, 10))
        tk.Label(tools, text="> ACTIVE CONNECTION: GROQ-AI-MOD_LLAMA3", font=(BLOCK_FONT, 10), fg=GUCCI_GOLD, bg=GUCCI_BG).pack(side=tk.LEFT)
        tk.Button(tools, text="[ RE-SCAN ]", command=self.manual_ai_trigger, bg=GUCCI_GREEN, fg=GUCCI_GOLD, font=(BLOCK_FONT, 9, "bold"), relief="solid", bd=2).pack(side=tk.RIGHT)

        split = tk.Frame(content, bg=GUCCI_BG)
        split.pack(fill=tk.BOTH, expand=True)
        
        # TABLE
        t_frame = tk.Frame(split, bg=GUCCI_BG, width=380, bd=2, relief="solid")
        t_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=False, padx=(0, 15))
        tk.Label(t_frame, text="-- PACKET HEADER --", bg=GUCCI_BG, fg="white", font=(BLOCK_FONT, 10)).pack(pady=2)
        
        self.packet_tree = ttk.Treeview(t_frame, columns=("Prop","Val"), show="headings", height=12, style="Gucci.Treeview")
        self.packet_tree.heading("Prop", text="PROPERTY"); self.packet_tree.heading("Val", text="VALUE")
        self.packet_tree.column("Prop", width=200); self.packet_tree.column("Val", width=120)
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # AI TEXT
        txt_frame = tk.Frame(split, bg=GUCCI_BG, bd=2, relief="solid")
        txt_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        tk.Label(txt_frame, text="-- INTELLIGENCE REPORT --", bg=GUCCI_BG, fg="white", font=(BLOCK_FONT, 10)).pack(pady=2)
        
        self.txt_ai = scrolledtext.ScrolledText(txt_frame, height=12, bg="#05200a", fg="#cfcfcf", font=(BLOCK_FONT, 10), 
                                                relief=tk.FLAT, bd=0, padx=10, pady=10, wrap=tk.WORD) 
        self.txt_ai.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        self.txt_ai.tag_config("HEADER", foreground=GUCCI_GOLD, font=(BLOCK_FONT, 11, "bold"))
        self.txt_ai.tag_config("SUB_KEY", foreground="white", font=(BLOCK_FONT, 10, "bold")) 
        self.txt_ai.tag_config("BLUE_CONTENT", foreground=COLOR_BLUE_ROYAL, font=(BLOCK_FONT, 10, "italic"))
        self.txt_ai.tag_config("NUM_DATA", foreground=COLOR_NEON_GREEN, font=(BLOCK_FONT, 10, "bold"))
        self.txt_ai.tag_config("NORMAL", foreground="#cfcfcf")
        
        self.txt_ai.insert(tk.END, "> Awaiting packet data stream...")

    def format_ai_text(self, text):
        self.txt_ai.delete(1.0, tk.END)
        self.txt_ai.insert(tk.END, text)
        lines = text.split('\n')
        line_idx = 1
        is_conclusion = False
        
        for line in lines:
            line_len = len(line)
            if line_len == 0: 
                line_idx += 1
                continue
            start = f"{line_idx}.0"
            end = f"{line_idx}.end"
            if "###" in line or "Analysis Logic" in line or "Conclusion" in line and "###" in line:
                self.txt_ai.tag_add("HEADER", start, end)
                if "Conclusion" in line: is_conclusion = True
            elif not is_conclusion:
                matches = list(re.finditer(r"\*\*(.*?)\*\*", line))
                for m in matches:
                    s = f"{line_idx}.{m.start()}"; e = f"{line_idx}.{m.end()}"
                    self.txt_ai.tag_add("SUB_KEY", s, e)
            elif is_conclusion:
                if not ("###" in line): self.txt_ai.tag_add("BLUE_CONTENT", start, end)
            line_idx += 1

        count_var = tk.IntVar()
        start_idx = "1.0"
        while True:
            pos = self.txt_ai.search(r"\b\d+([.,]\d+)?%?\b", start_idx, stopindex=tk.END, count=count_var, regexp=True)
            if not pos: break
            end_idx = f"{pos}+{count_var.get()}c"
            self.txt_ai.tag_add("NUM_DATA", pos, end_idx)
            start_idx = end_idx
        self.txt_ai.tag_raise("SUB_KEY")
        self.txt_ai.tag_raise("NUM_DATA")

    def _build_controls(self, parent):
        tk.Label(parent, text="Groq API Key", fg=COLOR_SUBTEXT, bg=COLOR_CARD, font=("Segoe UI", 9, "bold")).pack(anchor="w")
        kf = tk.Frame(parent, bg=COLOR_CARD)
        kf.pack(fill=tk.X, pady=(5, 10))
        self.key_var = tk.StringVar()
        tk.Entry(kf, textvariable=self.key_var, show="•", bg="#333", fg="white", font=self.font_mono, relief=tk.FLAT).pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=4)
        tk.Button(kf, text="SAVE", command=self.save_key, bg="#444", fg="white", relief=tk.FLAT).pack(side=tk.LEFT, ipadx=10, fill=tk.Y)
        
        tk.Label(parent, text="Dataset", fg=COLOR_SUBTEXT, bg=COLOR_CARD, font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.source_var = tk.StringVar(value="Synthetic Simulation")
        cb = ttk.Combobox(parent, textvariable=self.source_var, state="readonly", font=("Segoe UI", 9))
        cb['values'] = ("Synthetic Simulation", "Real Dataset (CIC-IDS2017 CSV)")
        cb.pack(fill=tk.X, pady=(5, 10))
        cb.bind("<<ComboboxSelected>>", self._on_source_change)

        self.split_var = tk.IntVar(value=80)
        self.tree_var = tk.IntVar(value=100)
        self._slider(parent, "Split %", 50, 90, self.split_var)
        self._slider(parent, "Trees", 10, 200, self.tree_var)

    def _slider(self, p, l, minv, maxv, var):
        tk.Label(p, text=l, fg=COLOR_SUBTEXT, bg=COLOR_CARD, font=("Segoe UI", 9)).pack(anchor="w")
        tk.Scale(p, from_=minv, to=maxv, orient=tk.HORIZONTAL, variable=var, bg=COLOR_CARD, fg=COLOR_TEXT, troughcolor="#333", highlightthickness=0).pack(fill=tk.X, pady=2)

    def _build_metrics(self, parent):
        self.lbl_acc = tk.Label(parent, text="Accuracy: --", fg=COLOR_TEXT, bg=COLOR_CARD, font=("Segoe UI", 24))
        self.lbl_acc.pack(anchor="w")
        self.lbl_threats = tk.Label(parent, text="Threats: --", fg=COLOR_ACCENT, bg=COLOR_CARD, font=("Segoe UI", 24, "bold"))
        self.lbl_threats.pack(anchor="w", pady=(5, 0))

    def _build_injection_panel(self, parent):
        inputs_frame = tk.Frame(parent, bg=COLOR_CARD)
        inputs_frame.pack(fill=tk.X)
        self.entries = {}
        fields = [("Duration (ms)", "5000", 0, 0), ("Total Packets", "12", 0, 1),
                  ("Length Mean", "450", 1, 0), ("Active Mean", "120", 1, 1)]
        for text, val, r, c in fields:
            f = tk.Frame(inputs_frame, bg=COLOR_CARD)
            f.grid(row=r, column=c, sticky="ew", padx=5, pady=5)
            inputs_frame.grid_columnconfigure(c, weight=1)
            tk.Label(f, text=text, fg="gray", bg=COLOR_CARD, font=("Segoe UI", 8)).pack(anchor="w")
            e = tk.Entry(f, bg="#2b2b2b", fg="white", font=self.font_mono, relief=tk.FLAT)
            e.insert(0, val)
            e.pack(fill=tk.X, ipady=4)
            self.entries[text] = e

        btn_row = tk.Frame(parent, bg=COLOR_CARD)
        btn_row.pack(fill=tk.X, pady=(20, 0))
        RoundedButton(btn_row, text="INJECT PACKET", command=self.inject_manual, bg=COLOR_ACCENT, fg="white", width=250, height=45).pack()
        tk.Label(parent, text="--- OR ---", bg=COLOR_CARD, fg="#444").pack(pady=5)
        RoundedButton(parent, text="RANDOM SAMPLE", command=self.capture_random, bg="#444", fg="white", width=200, height=35).pack()

    def _build_terminal(self, parent):
        lbl = tk.Label(parent, text="SYSTEM LOGS", font=("Segoe UI", 10, "bold"), fg=COLOR_SUBTEXT, bg=COLOR_BG)
        lbl.pack(anchor="w", pady=(10, 5))
        self.term = tk.Text(parent, height=8, bg="black", fg=COLOR_TERMINAL, font=self.font_mono, borderwidth=0, relief=tk.FLAT)
        self.term.pack(fill=tk.X, pady=(20, 0))
        self.log("AI-NIDS KERNEL INITIALIZED... WAITING FOR TRAINING COMMAND.")

    def log(self, msg):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        entry = f"[{ts}] {msg}"
        self.term.insert(tk.END, entry + "\n")
        self.term.see(tk.END)
        self.log_buffer.append(entry)

    def save_key(self):
        if self.engine.configure_ai(self.key_var.get()):
            messagebox.showinfo("Success", "API Key Saved.")
            self.log("AI Module Ready. API key Configured")

    def _on_source_change(self, e):
        if self.source_var.get().startswith("Real"):
            p = filedialog.askopenfilename(filetypes=[("CSV","*.csv")])
            if p: self.selected_csv_path = p
            else: self.source_var.set("Synthetic Simulation")

    def run_training(self):
        mode = 'csv' if self.source_var.get().startswith("Real") else 'synthetic'
        self.log("Training started...")
        self.update()
        try:
            self.engine.load_data(mode, self.selected_csv_path)
            self.engine.train(self.split_var.get(), self.tree_var.get())
            m = self.engine.get_metrics()
            self.latest_metrics = m
            self.lbl_acc.config(text=f"Accuracy: {m['accuracy']*100:.2f}%")
            self.lbl_threats.config(text=f"Threats: {m['threats']}")
            self._plot_cm(m['cm'])
            self.log("Training Complete. System is now Live.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _plot_cm(self, cm):
        for w in self.viz_frame.winfo_children(): w.destroy()
        fig = plt.Figure(figsize=(5, 2.8), dpi=100, facecolor=COLOR_CARD)
        ax = fig.add_subplot(111); ax.set_facecolor(COLOR_CARD)
        fig.subplots_adjust(bottom=0.2, top=0.9, left=0.15, right=0.95)
        sns.heatmap(cm, annot=True, fmt='d', cmap='Reds', ax=ax, cbar=False, annot_kws={"size":12})
        ax.set_xlabel("Predicted", color='white'); ax.set_ylabel("Actual", color='white')
        ax.tick_params(colors='white', labelsize=8)
        
        # --- FIXED ERROR HANDLING FOR LABELS ---
        # If the matrix is 1x1 (only one class present in small test), set basic label
        # Else if 2x2 (normal), set Safe/Attack
        if cm.shape == (2, 2):
            ax.set_xticklabels(['Safe', 'Attack'])
            ax.set_yticklabels(['Safe', 'Attack'])
        elif cm.shape == (1, 1):
            ax.set_xlabel("Predicted (Single Class in Batch)")
            ax.set_ylabel("Actual (Single Class in Batch)")
            
        canvas = FigureCanvasTkAgg(fig, self.viz_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        try:
            # Only print granular stats if matrix is full 2x2
            if cm.shape == (2, 2):
                tn, fp, fn, tp = cm.ravel()
                stats_txt = (f"✅ Safe Verified: {tn}   |   🛡️ Threats Blocked: {tp}\n"
                             f"⚠️ False Alarms: {fp}   |   🚫 Missed Attacks: {fn}")
                tk.Label(self.viz_frame, text=stats_txt, bg=COLOR_CARD, fg=COLOR_SUBTEXT, font=("Segoe UI", 9)).pack(pady=2)
        except: pass

    def _process_result(self, pkt, pred):
        self.current_packet = pkt; self.current_pred = pred
        for i in self.packet_tree.get_children(): self.packet_tree.delete(i)
        
        if isinstance(pkt, pd.DataFrame): items = pkt.iloc[0].to_dict().items() 
        else: items = pkt.items()
            
        for k, v in items:
            self.packet_tree.insert("", "end", values=(k, f"{v:.2f}" if isinstance(v,float) else str(v)))
        
        if pred == 1:
            self.lbl_status.config(text="! MALICIOUS ATTACK !", bg=GUCCI_RED)
            self.log("⨻NIDS ALERT- CRITICAL: Attack Pattern Recognized!")
        else:
            self.lbl_status.config(text="✓ BENIGN TRAFFIC", bg=COLOR_SUCCESS)
            self.log("Packet verified safe.>_< Traffic benign.")

        self.manual_ai_trigger() 

    def manual_ai_trigger(self):
        if self.current_packet is None: return
        self.txt_ai.delete(1.0, tk.END)
        self.txt_ai.insert(tk.END, "> INIT_ANALYSIS: Contacting Groq...\n> [ ... ]")
        threading.Thread(target=lambda: self._ai_thread()).start()

    def _ai_thread(self):
        res = self.engine.ask_groq(self.current_packet, self.current_pred)
        self.current_ai_response = res
        self.after(0, lambda: self.format_ai_text(res))

    def capture_random(self):
        pkt, _ = self.engine.get_random_test_packet()
        if pkt is None: return messagebox.showwarning("Wait", "Initialize Model first.")
        self._process_result(pkt, self.engine.predict_packet(pkt))

    def inject_manual(self):
        if self.engine.model is None: return messagebox.showwarning("Wait", "Initialize Model first.")
        try:
            df = self.engine.construct_manual_packet(
                float(self.entries["Duration (ms)"].get()), float(self.entries["Total Packets"].get()),
                float(self.entries["Length Mean"].get()), float(self.entries["Active Mean"].get())
            )
            self._process_result(df, self.engine.predict_packet(df))
        except ValueError:
            messagebox.showerror("Error", "Check numeric inputs.")

    def generate_report(self):
        """Generates a Multi-Page Professional PDF Report."""
        if not self.log_buffer and not self.latest_metrics:
            return messagebox.showerror("Empty", "No analysis to report.")
            
        p = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF","*.pdf")])
        if not p: return

        try:
            with PdfPages(p) as pdf:
                # --- PAGE 1: EXECUTIVE SUMMARY & CHARTS ---
                fig1 = plt.figure(figsize=(11, 8.5)) 
                plt.axis('off')
                
                # Header
                plt.text(0.5, 0.93, "AI-BASED NIDS SECURITY AUDIT", 
                         ha='center', fontsize=20, weight='bold', transform=fig1.transFigure)

                # Left Col: Intro & Metrics
                intro_text = (
                    f"'AI-BASED NIDS' - Security Audit Report\n"
                    f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                    f"Operator: Root\n"
                    f"Data Source: {self.source_var.get()}"
                )
                plt.text(0.05, 0.85, intro_text, fontsize=10, family='monospace', transform=fig1.transFigure, va='top')

                if self.latest_metrics:
                    m = self.latest_metrics
                    acc = m['accuracy']*100
                    
                    perf_text = (
                        "--- MODEL PERFORMANCE ---\n"
                        f"Total Records Analyzed: 5000+\n"
                        f"Model Accuracy: {acc:.2f}%\n"
                        f"Total Threats Intercepted: {m['threats']}\n"
                        f"Algorithm: Random Forest Classifier\n"
                        f"Trees: 100 | Split: {self.split_var.get()}%"
                    )
                    
                    status_text = (
                        "\n--- STATUS ---\n"
                        "System Status: ONLINE\n"
                        "Threat Level: MODERATE"
                    )
                    
                    plt.text(0.05, 0.70, perf_text + status_text, fontsize=10, family='monospace', va='top', transform=fig1.transFigure)

                # Right Col: Chart
                if self.latest_metrics:
                    ax_cm = fig1.add_axes([0.52, 0.55, 0.40, 0.30]) 
                    sns.heatmap(self.latest_metrics['cm'], annot=True, fmt='d', cmap='Reds', ax=ax_cm, cbar=False, 
                                annot_kws={"weight": "bold", "size": 12})
                    ax_cm.set_title("Confusion Matrix", fontsize=10)
                    ax_cm.set_xlabel('Predicted'); ax_cm.set_ylabel('Actual')

                    guide_box_text = (
                        "GUIDE TO VISUAL DIAGNOSTICS (How to read this graph):\n"
                        "----------------------------\n"
                        "The Confusion Matrix compares the AI's predictions vs Reality.\n"
                        "\n"
                        "1. Top-Left: Safe traffic correctly identified.\n"
                        "2. Bottom-Right: Attacks correctly blocked.\n"
                        "3. Top-Right: False Alarms (Safe marked as Attack).\n"
                        "4. Bottom-Left: Missed Attacks (Dangerous!).\n\n"
                        "Note-i: Dark red squares should be diagonal (0,0 and 1,1).\n"
                        "Note-ii: High numbers in the diagonal (Top-Left to Bottom-Right)\n"
                        "indicate a healthy, accurate model."
                    )
                    plt.text(0.52, 0.35, guide_box_text, fontsize=8, family='monospace', va='top', 
                             bbox=dict(facecolor='#eee', edgecolor='black'), transform=fig1.transFigure)

                pdf.savefig(fig1)

                # --- PAGE 2: FORENSIC ANALYST REPORT (DEDICATED PAGE) ---
                fig2 = plt.figure(figsize=(11, 8.5))
                plt.axis('off')
                
                # Title
                plt.text(0.5, 0.95, "FORENSIC ANALYST REPORT", ha='center', fontsize=20, weight='bold')
                
                # Dynamic Y-Cursor
                y_pos = 0.88

                # 1. Packet Data Header
                plt.text(0.05, y_pos, "TARGET PACKET HEADER:", fontsize=12, weight='bold', family='monospace')
                y_pos -= 0.03
                
                # Iterate columns/values neatly
                if self.current_packet is not None:
                    if isinstance(self.current_packet, pd.DataFrame): 
                        pkt_dict = self.current_packet.iloc[0].to_dict() 
                    else: 
                        pkt_dict = self.current_packet
                        
                    for k, v in pkt_dict.items():
                        val = f"{v:.4f}" if isinstance(v, float) else str(v)
                        plt.text(0.05, y_pos, f"{k}: {val}", fontsize=10, family='monospace')
                        y_pos -= 0.02
                
                # Spacer
                y_pos -= 0.04

                # 2. AI Analysis Logic (Line by Line Processing)
                plt.text(0.05, y_pos, "AI FORENSIC ANALYSIS:", fontsize=12, weight='bold', family='monospace')
                y_pos -= 0.03
                
                # Process line-by-line to avoid the 'Text Blob' issue
                lines = self.current_ai_response.split('\n')
                for line in lines:
                    line = line.strip()
                    if not line: 
                        y_pos -= 0.01
                        continue
                        
                    font_weight = 'normal'
                    text_color = 'black'
                    
                    if "###" in line or "Conclusion" in line:
                        font_weight = 'bold'
                        text_color = 'darkblue'
                    
                    # Wrap single line to 95 chars so bullet points wrap cleanly
                    wrapped_sub = textwrap.wrap(line, width=95)
                    for sub in wrapped_sub:
                        plt.text(0.05, y_pos, sub, fontsize=10, family='monospace', weight=font_weight, color=text_color)
                        y_pos -= 0.02
                        if y_pos < 0.05: break # Avoid running off page
                        
                pdf.savefig(fig2)

                # --- PAGE 3: SESSION LOGS (DEDICATED PAGE) ---
                fig3 = plt.figure(figsize=(11, 8.5))
                plt.axis('off')
                plt.text(0.5, 0.95, "SYSTEM SESSION LOGS", ha='center', fontsize=18, weight='bold')
                
                # Now the logs have full space and won't overlap
                logs = "\n".join(self.log_buffer[-55:]) # Fits approx 55 lines per page
                plt.text(0.05, 0.90, logs, fontsize=11, family='monospace', va='top')
                
                pdf.savefig(fig3)
                
            self.log(f"PDF Saved: {p}")
            messagebox.showinfo("Report Saved", "Success.")
        except Exception as e:
            messagebox.showerror("PDF Error", str(e))

    def reset_system(self):
        self.engine = NIDSEngine()
        self.latest_metrics = None; self.current_packet = None; self.log_buffer = []
        self.lbl_acc.config(text="Accuracy: --")
        self.lbl_threats.config(text="Threats: --")
        self.lbl_status.config(text="STATUS: UNKNOWN", bg="#333")
        for w in self.viz_frame.winfo_children(): w.destroy()
        self.txt_ai.delete(1.0, tk.END)
        for i in self.packet_tree.get_children(): self.packet_tree.delete(i)
        self.log("Reset Done.")

if __name__ == "__main__":
    app = NIDS_GUI()
    app.mainloop()