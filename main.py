"""
Advanced Cleaner & Uninstaller
Made by vetraservices
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import winreg
import os
import shutil
import threading
import subprocess
import re
from typing import List, Dict, Optional, Tuple
from pathlib import Path

class AdvancedUninstaller:
    def __init__(self):
        self.scan_mode = "Safe"

    def get_installed_programs(self) -> List[Dict]:
        programs = []
        uninstall_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]

        for hkey, base_path in uninstall_keys:
            try:
                key = winreg.OpenKey(hkey, base_path, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkey = winreg.OpenKey(key, subkey_name)

                        try:
                            display_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                            uninstall_string = None
                            quiet_uninstall_string = None
                            install_location = None
                            publisher = None
                            product_code = None

                            try:
                                uninstall_string = winreg.QueryValueEx(subkey, "UninstallString")[0]
                            except:
                                pass

                            try:
                                quiet_uninstall_string = winreg.QueryValueEx(subkey, "QuietUninstallString")[0]
                            except:
                                pass

                            try:
                                install_location = winreg.QueryValueEx(subkey, "InstallLocation")[0]
                            except:
                                pass

                            try:
                                publisher = winreg.QueryValueEx(subkey, "Publisher")[0]
                            except:
                                pass

                            try:
                                product_code = winreg.QueryValueEx(subkey, "PSChildName")[0]
                            except:
                                pass

                            programs.append({
                                'name': display_name,
                                'uninstall_string': uninstall_string,
                                'quiet_uninstall_string': quiet_uninstall_string,
                                'install_location': install_location,
                                'publisher': publisher,
                                'product_code': product_code,
                                'registry_key': f"{base_path}\\{subkey_name}",
                                'hkey': hkey
                            })
                        except:
                            pass

                        winreg.CloseKey(subkey)
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except Exception:
                pass

        return programs

    def run_uninstaller(self, program: Dict) -> bool:
        try:
            uninstall_cmd = program.get('quiet_uninstall_string') or program.get('uninstall_string')
            if not uninstall_cmd:
                return False

            if '/I{' in uninstall_cmd or '/x{' in uninstall_cmd or program.get('product_code'):
                if program.get('product_code'):
                    cmd = ['msiexec', '/x', program['product_code'], '/qn', '/norestart']
                else:
                    guid_match = re.search(r'\{[A-F0-9\-]{36}\}', uninstall_cmd, re.IGNORECASE)
                    if guid_match:
                        cmd = ['msiexec', '/x', guid_match.group(), '/qn', '/norestart']
                    else:
                        return False
            else:
                if uninstall_cmd.startswith('"'):
                    parts = uninstall_cmd.split('"')
                    cmd = [parts[1]] + parts[2].strip().split() if len(parts) > 2 else [parts[1]]
                else:
                    cmd = uninstall_cmd.split()

            subprocess.run(cmd, check=False, timeout=300)
            return True
        except Exception as e:
            return False

    def scan_leftovers(self, program_name: str, install_path: Optional[str],
                      publisher: Optional[str], scan_mode: str = "Safe") -> List[Dict]:
        items = []
        app_name_normalized = self.normalize_name(program_name)

        items.extend(self.scan_registry_leftovers(app_name_normalized, publisher, scan_mode))

        if install_path:
            items.extend(self.scan_filesystem_leftovers(install_path, app_name_normalized, scan_mode))
        else:
            items.extend(self.scan_filesystem_leftovers(None, app_name_normalized, scan_mode))

        if scan_mode == "Advanced":
            items.extend(self.scan_advanced_artifacts(app_name_normalized, publisher))

        return items

    def normalize_name(self, name: str) -> str:
        name = re.sub(r'\s+\d+\.\d+.*$', '', name)
        name = re.sub(r'\s*\(.*?\)', '', name)
        name = name.strip().lower()
        return name

    def scan_registry_leftovers(self, app_name: str, publisher: Optional[str],
                               scan_mode: str) -> List[Dict]:
        items = []
        search_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE"),
            (winreg.HKEY_CURRENT_USER, r"Software"),
        ]

        if scan_mode in ["Moderate", "Advanced"]:
            search_paths.append((winreg.HKEY_CLASSES_ROOT, r"CLSID"))
            search_paths.append((winreg.HKEY_CLASSES_ROOT, r"TypeLib"))
            search_paths.append((winreg.HKEY_CLASSES_ROOT, r"Interface"))

        for hkey, base_path in search_paths:
            items.extend(self.scan_registry_recursive(hkey, base_path, app_name, publisher, scan_mode))

        return items

    def scan_registry_recursive(self, hkey, path: str, app_name: str,
                               publisher: Optional[str], scan_mode: str, depth: int = 0) -> List[Dict]:
        items = []
        if depth > 5:
            return items

        try:
            key = winreg.OpenKey(hkey, path, 0, winreg.KEY_READ)

            key_name = path.split('\\')[-1].lower()
            if self.matches_pattern(key_name, app_name, publisher):
                items.append({
                    'name': key_name,
                    'type': 'Registry',
                    'location': f"{'HKLM' if hkey == winreg.HKEY_LOCAL_MACHINE else 'HKCU' if hkey == winreg.HKEY_CURRENT_USER else 'HKCR'}\\{path}",
                    'path': path,
                    'hkey': hkey,
                    'size': 'N/A',
                    'confidence': self.calculate_confidence(key_name, app_name, publisher)
                })

            i = 0
            while i < 100:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    subkey_path = f"{path}\\{subkey_name}" if path else subkey_name
                    items.extend(self.scan_registry_recursive(hkey, subkey_path, app_name, publisher, scan_mode, depth + 1))
                    i += 1
                except OSError:
                    break

            winreg.CloseKey(key)
        except (FileNotFoundError, PermissionError, OSError):
            pass

        return items

    def matches_pattern(self, text: str, app_name: str, publisher: Optional[str]) -> bool:
        text_lower = text.lower()
        app_lower = app_name.lower()

        if app_lower in text_lower or text_lower in app_lower:
            return True

        if publisher:
            pub_lower = publisher.lower()
            if pub_lower in text_lower:
                return True

        app_words = set(app_lower.split())
        text_words = set(text_lower.split())
        if app_words and app_words.intersection(text_words):
            return True

        return False

    def calculate_confidence(self, key_name: str, app_name: str, publisher: Optional[str]) -> str:
        if key_name == app_name.lower():
            return "High"
        elif app_name.lower() in key_name:
            return "Medium"
        else:
            return "Low"

    def scan_filesystem_leftovers(self, install_path: Optional[str], app_name: str,
                                 scan_mode: str) -> List[Dict]:
        items = []
        search_paths = []

        if install_path and os.path.exists(install_path):
            search_paths.append(install_path)

        appdata_local = os.environ.get('LOCALAPPDATA', '')
        appdata_roaming = os.environ.get('APPDATA', '')
        programdata = os.environ.get('PROGRAMDATA', '')
        program_files = os.environ.get('PROGRAMFILES', 'C:\\Program Files')
        program_files_x86 = os.environ.get('PROGRAMFILES(X86)', 'C:\\Program Files (x86)')

        if scan_mode in ["Moderate", "Advanced"]:
            if appdata_local:
                search_paths.extend([
                    os.path.join(appdata_local, app_name),
                    os.path.join(appdata_local, app_name.replace(' ', '')),
                ])

            if appdata_roaming:
                search_paths.extend([
                    os.path.join(appdata_roaming, app_name),
                    os.path.join(appdata_roaming, app_name.replace(' ', '')),
                ])

            if programdata:
                search_paths.extend([
                    os.path.join(programdata, app_name),
                    os.path.join(programdata, app_name.replace(' ', '')),
                ])

        if scan_mode == "Advanced":
            for pf in [program_files, program_files_x86]:
                if os.path.exists(pf):
                    try:
                        for entry in os.scandir(pf):
                            if entry.is_dir() and self.matches_pattern(entry.name.lower(), app_name, None):
                                search_paths.append(entry.path)
                    except PermissionError:
                        pass

        for path in search_paths:
            if os.path.exists(path):
                try:
                    size = self.get_folder_size(path)
                    items.append({
                        'name': os.path.basename(path),
                        'type': 'File/Folder',
                        'location': path,
                        'path': path,
                        'size': self.format_size(size),
                        'confidence': 'High' if install_path and path == install_path else 'Medium'
                    })
                except Exception:
                    pass

        return items

    def scan_advanced_artifacts(self, app_name: str, publisher: Optional[str]) -> List[Dict]:
        items = []


        return items

    def get_folder_size(self, path):
        total = 0
        try:
            for entry in os.scandir(path):
                if entry.is_file():
                    total += entry.stat().st_size
                elif entry.is_dir():
                    total += self.get_folder_size(entry.path)
        except PermissionError:
            pass
        return total

    def format_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"


class RustCleaner:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Cleaner & Uninstaller")
        self.root.geometry("1000x750")
        self.root.resizable(True, True)

        self.found_items = []
        self.scanning = False
        self.uninstaller = AdvancedUninstaller()
        self.installed_programs = []

        self.setup_ui()

    def setup_ui(self):
        main_container = ttk.Frame(self.root, padding="10")
        main_container.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_container.columnconfigure(0, weight=1)
        main_container.rowconfigure(1, weight=1)

        title_label = ttk.Label(
            main_container,
            text="Advanced Cleaner & Uninstaller",
            font=("Segoe UI", 16, "bold")
        )
        title_label.grid(row=0, column=0, pady=(0, 10))

        self.notebook = ttk.Notebook(main_container)
        self.notebook.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.rust_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.rust_frame, text="Rust Cleaner")
        self.setup_rust_cleaner_tab()

        self.uninstaller_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.uninstaller_frame, text="Advanced Uninstaller")
        self.setup_uninstaller_tab()

    def setup_rust_cleaner_tab(self):
        rust_frame = self.rust_frame
        rust_frame.columnconfigure(0, weight=1)
        rust_frame.rowconfigure(3, weight=1)

        button_frame = ttk.Frame(rust_frame)
        button_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        button_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(1, weight=1)
        button_frame.columnconfigure(2, weight=1)

        self.rust_scan_button = ttk.Button(
            button_frame,
            text="Scan",
            command=self.start_rust_scan,
            width=20
        )
        self.rust_scan_button.grid(row=0, column=0, padx=5)

        self.rust_clean_button = ttk.Button(
            button_frame,
            text="Clean Selected",
            command=self.clean_selected,
            width=20,
            state="disabled"
        )
        self.rust_clean_button.grid(row=0, column=1, padx=5)

        self.rust_select_all_button = ttk.Button(
            button_frame,
            text="Select All",
            command=self.toggle_select_all,
            width=20
        )
        self.rust_select_all_button.grid(row=0, column=2, padx=5)

        self.rust_progress = ttk.Progressbar(
            rust_frame,
            mode='indeterminate',
            length=400
        )
        self.rust_progress.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        self.rust_status_label = ttk.Label(
            rust_frame,
            text="Ready - Click 'Scan' button to start scanning",
            font=("Segoe UI", 9)
        )
        self.rust_status_label.grid(row=2, column=0, pady=(0, 10))

        list_frame = ttk.Frame(rust_frame)
        list_frame.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)

        columns = ('Type', 'Location', 'Size')
        self.rust_tree = ttk.Treeview(list_frame, columns=columns, show='tree headings', height=15)
        self.rust_tree.heading('#0', text='Item')
        self.rust_tree.heading('Type', text='Type')
        self.rust_tree.heading('Location', text='Location')
        self.rust_tree.heading('Size', text='Size')

        self.rust_tree.column('#0', width=200)
        self.rust_tree.column('Type', width=100)
        self.rust_tree.column('Location', width=400)
        self.rust_tree.column('Size', width=100)

        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.rust_tree.yview)
        self.rust_tree.configure(yscrollcommand=scrollbar.set)

        self.rust_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))

        self.rust_tree.bind('<Button-1>', self.on_rust_item_click)

    def setup_uninstaller_tab(self):
        uninstaller_frame = self.uninstaller_frame
        uninstaller_frame.columnconfigure(0, weight=1)
        uninstaller_frame.rowconfigure(2, weight=1)

        top_frame = ttk.Frame(uninstaller_frame)
        top_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        top_frame.columnconfigure(0, weight=1)

        mode_frame = ttk.Frame(top_frame)
        mode_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Label(mode_frame, text="Scan Mode:", font=("Segoe UI", 9)).grid(row=0, column=0, padx=5)
        self.scan_mode_var = tk.StringVar(value="Safe")
        mode_combo = ttk.Combobox(mode_frame, textvariable=self.scan_mode_var,
                                 values=["Safe", "Moderate", "Advanced"],
                                 state="readonly", width=15)
        mode_combo.grid(row=0, column=1, padx=5)

        button_frame = ttk.Frame(top_frame)
        button_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        button_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(1, weight=1)
        button_frame.columnconfigure(2, weight=1)
        button_frame.columnconfigure(3, weight=1)

        self.refresh_button = ttk.Button(
            button_frame,
            text="Refresh Programs",
            command=self.refresh_programs,
            width=18
        )
        self.refresh_button.grid(row=0, column=0, padx=5)

        self.uninstall_button = ttk.Button(
            button_frame,
            text="Uninstall Selected",
            command=self.uninstall_selected,
            width=18,
            state="disabled"
        )
        self.uninstall_button.grid(row=0, column=1, padx=5)

        self.scan_leftovers_button = ttk.Button(
            button_frame,
            text="Scan Leftovers",
            command=self.scan_leftovers,
            width=18,
            state="disabled"
        )
        self.scan_leftovers_button.grid(row=0, column=2, padx=5)

        self.forced_uninstall_button = ttk.Button(
            button_frame,
            text="Forced Uninstall",
            command=self.forced_uninstall,
            width=18
        )
        self.forced_uninstall_button.grid(row=0, column=3, padx=5)

        self.uninstaller_progress = ttk.Progressbar(
            uninstaller_frame,
            mode='indeterminate',
            length=400
        )
        self.uninstaller_progress.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        self.uninstaller_status_label = ttk.Label(
            uninstaller_frame,
            text="Ready - Click 'Refresh Programs' to load installed programs",
            font=("Segoe UI", 9)
        )
        self.uninstaller_status_label.grid(row=2, column=0, pady=(0, 10))

        programs_frame = ttk.Frame(uninstaller_frame)
        programs_frame.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        programs_frame.columnconfigure(0, weight=1)
        programs_frame.rowconfigure(0, weight=1)
        uninstaller_frame.rowconfigure(3, weight=1)

        prog_columns = ('Publisher', 'Install Location', 'Uninstall String')
        self.programs_tree = ttk.Treeview(programs_frame, columns=prog_columns, show='tree headings', height=10)
        self.programs_tree.heading('#0', text='Program Name')
        self.programs_tree.heading('Publisher', text='Publisher')
        self.programs_tree.heading('Install Location', text='Install Location')
        self.programs_tree.heading('Uninstall String', text='Uninstall String')

        self.programs_tree.column('#0', width=250)
        self.programs_tree.column('Publisher', width=150)
        self.programs_tree.column('Install Location', width=300)
        self.programs_tree.column('Uninstall String', width=200)

        prog_scrollbar = ttk.Scrollbar(programs_frame, orient="vertical", command=self.programs_tree.yview)
        self.programs_tree.configure(yscrollcommand=prog_scrollbar.set)

        self.programs_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        prog_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))

        self.programs_tree.bind('<Button-1>', self.on_program_click)

        leftovers_frame = ttk.LabelFrame(uninstaller_frame, text="Leftovers After Uninstall", padding="5")
        leftovers_frame.grid(row=4, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        leftovers_frame.columnconfigure(0, weight=1)
        leftovers_frame.rowconfigure(0, weight=1)
        uninstaller_frame.rowconfigure(4, weight=1)

        left_columns = ('Type', 'Location', 'Size', 'Confidence')
        self.leftovers_tree = ttk.Treeview(leftovers_frame, columns=left_columns, show='tree headings', height=8)
        self.leftovers_tree.heading('#0', text='Item')
        self.leftovers_tree.heading('Type', text='Type')
        self.leftovers_tree.heading('Location', text='Location')
        self.leftovers_tree.heading('Size', text='Size')
        self.leftovers_tree.heading('Confidence', text='Confidence')

        self.leftovers_tree.column('#0', width=150)
        self.leftovers_tree.column('Type', width=100)
        self.leftovers_tree.column('Location', width=350)
        self.leftovers_tree.column('Size', width=80)
        self.leftovers_tree.column('Confidence', width=100)

        left_scrollbar = ttk.Scrollbar(leftovers_frame, orient="vertical", command=self.leftovers_tree.yview)
        self.leftovers_tree.configure(yscrollcommand=left_scrollbar.set)

        self.leftovers_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        left_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))

        self.leftovers_tree.bind('<Button-1>', self.on_leftover_click)

        self.clean_leftovers_button = ttk.Button(
            leftovers_frame,
            text="Clean Selected Leftovers",
            command=self.clean_leftovers,
            state="disabled"
        )
        self.clean_leftovers_button.grid(row=1, column=0, pady=(10, 0))

        self.refresh_programs()

    def on_rust_item_click(self, event):
        region = self.rust_tree.identify_region(event.x, event.y)
        if region == "cell":
            item = self.rust_tree.identify_row(event.x)
            if item:
                current_tags = self.rust_tree.item(item, 'tags')
                if 'selected' in current_tags:
                    self.rust_tree.item(item, tags=())
                else:
                    self.rust_tree.item(item, tags=('selected',))
                self.update_rust_clean_button_state()

    def toggle_select_all(self):
        all_selected = all('selected' in self.rust_tree.item(child, 'tags')
                          for child in self.rust_tree.get_children())

        for child in self.rust_tree.get_children():
            if all_selected:
                self.rust_tree.item(child, tags=())
            else:
                self.rust_tree.item(child, tags=('selected',))
        self.update_rust_clean_button_state()

    def update_rust_clean_button_state(self):
        has_selected = any('selected' in self.rust_tree.item(child, 'tags')
                          for child in self.rust_tree.get_children())
        self.rust_clean_button.config(state="normal" if has_selected else "disabled")

    def start_rust_scan(self):
        if self.scanning:
            return

        self.scanning = True
        self.rust_scan_button.config(state="disabled")
        self.rust_clean_button.config(state="disabled")
        self.rust_tree.delete(*self.rust_tree.get_children())
        self.found_items = []
        self.rust_progress.start()
        self.rust_status_label.config(text="Scanning...")

        thread = threading.Thread(target=self.scan_rust_system, daemon=True)
        thread.start()

    def scan_rust_system(self):
        items = []
        items.extend(self.scan_rust_registry())
        items.extend(self.scan_rust_files())
        self.root.after(0, self.update_rust_ui_after_scan, items)

    def scan_rust_registry(self) -> List[Dict]:
        items = []
        registry_paths = [
            (winreg.HKEY_CURRENT_USER, [
                r"Software\EasyAntiCheat",
                r"Software\Facepunch Studios",
                r"Software\Rust",
                r"Software\Valve\Steam\Apps\252490",
            ]),
            (winreg.HKEY_LOCAL_MACHINE, [
                r"SOFTWARE\EasyAntiCheat",
                r"SOFTWARE\Facepunch Studios",
                r"SOFTWARE\Rust",
                r"SOFTWARE\WOW6432Node\EasyAntiCheat",
                r"SOFTWARE\WOW6432Node\Facepunch Studios",
            ])
        ]

        for hkey, paths in registry_paths:
            for path in paths:
                try:
                    key = winreg.OpenKey(hkey, path, 0, winreg.KEY_READ)
                    items.append({
                        'name': path.split('\\')[-1],
                        'type': 'Registry',
                        'location': f"{'HKCU' if hkey == winreg.HKEY_CURRENT_USER else 'HKLM'}\\{path}",
                        'path': path,
                        'hkey': hkey,
                        'size': 'N/A'
                    })
                    winreg.CloseKey(key)
                except FileNotFoundError:
                    continue
                except Exception:
                    try:
                        key = winreg.OpenKey(hkey, path.split('\\')[0], 0, winreg.KEY_READ)
                        i = 0
                        while True:
                            try:
                                subkey_name = winreg.EnumKey(key, i)
                                if 'rust' in subkey_name.lower() or 'eac' in subkey_name.lower() or 'facepunch' in subkey_name.lower():
                                    base_path = path.split('\\')[0]
                                    full_path = f"{base_path}\\{subkey_name}"
                                    items.append({
                                        'name': subkey_name,
                                        'type': 'Registry',
                                        'location': f"{'HKCU' if hkey == winreg.HKEY_CURRENT_USER else 'HKLM'}\\{full_path}",
                                        'path': full_path,
                                        'hkey': hkey,
                                        'size': 'N/A'
                                    })
                                i += 1
                            except OSError:
                                break
                        winreg.CloseKey(key)
                    except:
                        pass

        return items

    def scan_rust_files(self) -> List[Dict]:
        items = []
        appdata_local = os.environ.get('LOCALAPPDATA', '')
        appdata_roaming = os.environ.get('APPDATA', '')
        programdata = os.environ.get('PROGRAMDATA', '')

        search_paths = [
            (os.path.join(appdata_local, 'Facepunch Studios'), 'Facepunch Studios'),
            (os.path.join(appdata_local, 'Rust'), 'Rust'),
            (os.path.join(appdata_local, 'EasyAntiCheat'), 'EasyAntiCheat'),
            (os.path.join(appdata_roaming, 'Facepunch Studios'), 'Facepunch Studios'),
            (os.path.join(appdata_roaming, 'Rust'), 'Rust'),
            (os.path.join(programdata, 'EasyAntiCheat'), 'EasyAntiCheat'),
            (os.path.join(programdata, 'Facepunch Studios'), 'Facepunch Studios'),
        ]

        steam_paths = [
            os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files'), 'Steam', 'steamapps', 'common', 'Rust'),
            os.path.join(os.environ.get('PROGRAMFILES(X86)', 'C:\\Program Files (x86)'), 'Steam', 'steamapps', 'common', 'Rust'),
        ]

        for steam_path in steam_paths:
            if os.path.exists(steam_path):
                for subfolder in ['logs', 'cache', 'EAC']:
                    full_path = os.path.join(steam_path, subfolder)
                    if os.path.exists(full_path):
                        search_paths.append((full_path, f'Rust/{subfolder}'))

        for path, name in search_paths:
            if os.path.exists(path):
                try:
                    size = self.get_folder_size(path)
                    items.append({
                        'name': name,
                        'type': 'File/Folder',
                        'location': path,
                        'path': path,
                        'size': self.format_size(size)
                    })
                except Exception:
                    pass

        return items

    def update_rust_ui_after_scan(self, items):
        self.found_items = items

        for item in items:
            self.rust_tree.insert(
                '',
                'end',
                text=item['name'],
                values=(item['type'], item['location'], item['size']),
                tags=('selected',)
            )

        self.rust_tree.tag_configure('selected', background='#e3f2fd')

        self.rust_progress.stop()
        self.scanning = False
        self.rust_scan_button.config(state="normal")
        self.rust_status_label.config(text=f"Scan completed - {len(items)} items found")
        self.update_rust_clean_button_state()

    def clean_selected(self):
        selected_items = []
        for child in self.rust_tree.get_children():
            if 'selected' in self.rust_tree.item(child, 'tags'):
                item_text = self.rust_tree.item(child, 'text')
                for item in self.found_items:
                    if item['name'] == item_text:
                        selected_items.append(item)
                        break

        if not selected_items:
            messagebox.showwarning("Warning", "No items selected for cleaning!")
            return

        result = messagebox.askyesno(
            "Confirmation",
            f"{len(selected_items)} items will be cleaned. Do you want to continue?\n\n"
            "WARNING: This operation cannot be undone!"
        )

        if not result:
            return

        self.rust_progress.start()
        self.rust_status_label.config(text="Cleaning...")
        self.rust_scan_button.config(state="disabled")
        self.rust_clean_button.config(state="disabled")

        thread = threading.Thread(target=self.clean_rust_items, args=(selected_items,), daemon=True)
        thread.start()

    def clean_rust_items(self, items):
        success_count = 0
        error_count = 0
        errors = []

        for item in items:
            try:
                if item['type'] == 'Registry':
                    try:
                        self.delete_registry_key(item['hkey'], item['path'])
                        success_count += 1
                    except Exception as e:
                        error_count += 1
                        errors.append(f"{item['name']}: {str(e)}")

                elif item['type'] == 'File/Folder':
                    path = item['path']
                    if os.path.isfile(path):
                        os.remove(path)
                    elif os.path.isdir(path):
                        shutil.rmtree(path, ignore_errors=True)
                    success_count += 1

            except Exception as e:
                error_count += 1
                errors.append(f"{item['name']}: {str(e)}")

        self.root.after(0, self.update_rust_ui_after_clean, success_count, error_count, errors)

    def update_rust_ui_after_clean(self, success_count, error_count, errors):
        self.rust_progress.stop()
        self.rust_scan_button.config(state="normal")

        for child in list(self.rust_tree.get_children()):
            if 'selected' in self.rust_tree.item(child, 'tags'):
                self.rust_tree.delete(child)

        self.found_items = [item for item in self.found_items
                           if not any('selected' in self.rust_tree.item(child, 'tags')
                                     for child in self.rust_tree.get_children()
                                     if self.rust_tree.item(child, 'text') == item['name'])]

        message = f"Cleaning completed!\n\nSuccessful: {success_count}\nErrors: {error_count}"
        if errors:
            message += f"\n\nErrors:\n" + "\n".join(errors[:5])
            if len(errors) > 5:
                message += f"\n... and {len(errors) - 5} more errors"

        messagebox.showinfo("Completed", message)
        self.rust_status_label.config(text=f"Cleaning completed - {success_count} items cleaned")
        self.update_rust_clean_button_state()

    def delete_registry_key(self, hkey, path):
        try:
            key = winreg.OpenKey(hkey, path, 0, winreg.KEY_ALL_ACCESS)
            while True:
                try:
                    subkey = winreg.EnumKey(key, 0)
                    self.delete_registry_key(hkey, f"{path}\\{subkey}")
                except OSError:
                    break
            winreg.CloseKey(key)

            parent_path = '\\'.join(path.split('\\')[:-1])
            key_name = path.split('\\')[-1]
            if parent_path:
                parent_key = winreg.OpenKey(hkey, parent_path, 0, winreg.KEY_ALL_ACCESS)
                winreg.DeleteKey(parent_key, key_name)
                winreg.CloseKey(parent_key)
            else:
                winreg.DeleteKey(hkey, key_name)
        except FileNotFoundError:
            pass
        except PermissionError:
            raise

    def get_folder_size(self, path):
        total = 0
        try:
            for entry in os.scandir(path):
                if entry.is_file():
                    total += entry.stat().st_size
                elif entry.is_dir():
                    total += self.get_folder_size(entry.path)
        except PermissionError:
            pass
        return total

    def format_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"

    def refresh_programs(self):
        self.uninstaller_progress.start()
        self.uninstaller_status_label.config(text="Loading installed programs...")
        self.refresh_button.config(state="disabled")

        thread = threading.Thread(target=self.load_programs, daemon=True)
        thread.start()

    def load_programs(self):
        programs = self.uninstaller.get_installed_programs()
        self.root.after(0, self.update_programs_list, programs)

    def update_programs_list(self, programs):
        self.installed_programs = programs
        self.programs_tree.delete(*self.programs_tree.get_children())

        for prog in programs:
            self.programs_tree.insert(
                '',
                'end',
                text=prog['name'],
                values=(
                    prog.get('publisher', 'N/A'),
                    prog.get('install_location', 'N/A') or 'N/A',
                    'Yes' if prog.get('uninstall_string') or prog.get('quiet_uninstall_string') else 'No'
                ),
                tags=()
            )

        self.uninstaller_progress.stop()
        self.uninstaller_status_label.config(text=f"Loaded {len(programs)} installed programs")
        self.refresh_button.config(state="normal")
        self.update_uninstaller_buttons()

    def on_program_click(self, event):
        self.update_uninstaller_buttons()

    def update_uninstaller_buttons(self):
        selected = self.programs_tree.selection()
        has_selection = len(selected) > 0

        self.uninstall_button.config(state="normal" if has_selection else "disabled")
        self.scan_leftovers_button.config(state="normal" if has_selection else "disabled")

    def uninstall_selected(self):
        selected = self.programs_tree.selection()
        if not selected:
            return

        item = selected[0]
        program_name = self.programs_tree.item(item, 'text')

        program = None
        for prog in self.installed_programs:
            if prog['name'] == program_name:
                program = prog
                break

        if not program:
            return

        result = messagebox.askyesno(
            "Confirmation",
            f"Uninstall '{program_name}'?\n\n"
            "This will run the standard Windows uninstaller first, "
            "then scan for leftover files and registry entries."
        )

        if not result:
            return

        self.uninstaller_progress.start()
        self.uninstaller_status_label.config(text=f"Uninstalling {program_name}...")
        self.uninstall_button.config(state="disabled")

        thread = threading.Thread(target=self.run_uninstall_process, args=(program,), daemon=True)
        thread.start()

    def run_uninstall_process(self, program: Dict):
        uninstall_success = self.uninstaller.run_uninstaller(program)

        self.root.after(0, self.uninstaller_status_label.config,
                       {"text": f"Scanning for leftovers of {program['name']}..."})

        scan_mode = self.scan_mode_var.get()
        leftovers = self.uninstaller.scan_leftovers(
            program['name'],
            program.get('install_location'),
            program.get('publisher'),
            scan_mode
        )

        self.root.after(0, self.update_leftovers_list, leftovers, program['name'])

    def update_leftovers_list(self, leftovers, program_name):
        self.uninstaller_progress.stop()
        self.uninstaller_status_label.config(
            text=f"Uninstall completed. Found {len(leftovers)} leftover items for {program_name}"
        )
        self.uninstall_button.config(state="normal")

        self.leftovers_tree.delete(*self.leftovers_tree.get_children())

        for item in leftovers:
            self.leftovers_tree.insert(
                '',
                'end',
                text=item['name'],
                values=(
                    item['type'],
                    item['location'],
                    item.get('size', 'N/A'),
                    item.get('confidence', 'N/A')
                ),
                tags=('selected',)
            )

        self.leftovers_tree.tag_configure('selected', background='#e3f2fd')
        self.clean_leftovers_button.config(state="normal" if leftovers else "disabled")

    def scan_leftovers(self):
        selected = self.programs_tree.selection()
        if not selected:
            return

        item = selected[0]
        program_name = self.programs_tree.item(item, 'text')

        program = None
        for prog in self.installed_programs:
            if prog['name'] == program_name:
                program = prog
                break

        if not program:
            return

        self.uninstaller_progress.start()
        self.uninstaller_status_label.config(text=f"Scanning for leftovers of {program_name}...")
        self.scan_leftovers_button.config(state="disabled")

        scan_mode = self.scan_mode_var.get()
        thread = threading.Thread(
            target=self.scan_leftovers_thread,
            args=(program, scan_mode),
            daemon=True
        )
        thread.start()

    def scan_leftovers_thread(self, program: Dict, scan_mode: str):
        leftovers = self.uninstaller.scan_leftovers(
            program['name'],
            program.get('install_location'),
            program.get('publisher'),
            scan_mode
        )

        self.root.after(0, self.update_leftovers_list, leftovers, program['name'])
        self.root.after(0, self.scan_leftovers_button.config, {"state": "normal"})
        self.root.after(0, self.uninstaller_progress.stop)

    def on_leftover_click(self, event):
        region = self.leftovers_tree.identify_region(event.x, event.y)
        if region == "cell":
            item = self.leftovers_tree.identify_row(event.x)
            if item:
                current_tags = self.leftovers_tree.item(item, 'tags')
                if 'selected' in current_tags:
                    self.leftovers_tree.item(item, tags=())
                else:
                    self.leftovers_tree.item(item, tags=('selected',))

    def clean_leftovers(self):
        selected_items = []
        for child in self.leftovers_tree.get_children():
            if 'selected' in self.leftovers_tree.item(child, 'tags'):
                item_text = self.leftovers_tree.item(child, 'text')
                item_values = self.leftovers_tree.item(child, 'values')
                selected_items.append({
                    'name': item_text,
                    'type': item_values[0],
                    'location': item_values[1],
                    'path': item_values[1]
                })

        if not selected_items:
            messagebox.showwarning("Warning", "No items selected!")
            return

        result = messagebox.askyesno(
            "Confirmation",
            f"{len(selected_items)} leftover items will be cleaned. Continue?"
        )

        if not result:
            return

        self.uninstaller_progress.start()
        self.uninstaller_status_label.config(text="Cleaning leftovers...")

        thread = threading.Thread(target=self.clean_leftovers_thread, args=(selected_items,), daemon=True)
        thread.start()

    def clean_leftovers_thread(self, items):
        success_count = 0
        error_count = 0

        for item in items:
            try:
                if item['type'] == 'Registry':
                    location = item['location']
                    if location.startswith('HKLM\\'):
                        hkey = winreg.HKEY_LOCAL_MACHINE
                        path = location[5:]
                    elif location.startswith('HKCU\\'):
                        hkey = winreg.HKEY_CURRENT_USER
                        path = location[5:]
                    elif location.startswith('HKCR\\'):
                        hkey = winreg.HKEY_CLASSES_ROOT
                        path = location[5:]
                    else:
                        continue

                    self.delete_registry_key(hkey, path)
                    success_count += 1
                elif item['type'] == 'File/Folder':
                    path = item['path']
                    if os.path.isfile(path):
                        os.remove(path)
                    elif os.path.isdir(path):
                        shutil.rmtree(path, ignore_errors=True)
                    success_count += 1
            except Exception:
                error_count += 1

        self.root.after(0, self.clean_leftovers_complete, success_count, error_count)

    def clean_leftovers_complete(self, success_count, error_count):
        self.uninstaller_progress.stop()
        self.uninstaller_status_label.config(
            text=f"Cleaning completed - {success_count} items cleaned, {error_count} errors"
        )

        for child in list(self.leftovers_tree.get_children()):
            if 'selected' in self.leftovers_tree.item(child, 'tags'):
                self.leftovers_tree.delete(child)

        messagebox.showinfo("Completed", f"Cleaned {success_count} items successfully.")

    def forced_uninstall(self):
        query = simpledialog.askstring(
            "Forced Uninstall",
            "Enter program name, executable path, or folder path to search for:"
        )

        if not query:
            return

        self.uninstaller_progress.start()
        self.uninstaller_status_label.config(text=f"Searching for '{query}'...")

        thread = threading.Thread(target=self.forced_uninstall_search, args=(query,), daemon=True)
        thread.start()

    def forced_uninstall_search(self, query: str):
        items = []

        query_normalized = self.uninstaller.normalize_name(query)

        publisher = None

        scan_mode = self.scan_mode_var.get()
        registry_items = self.uninstaller.scan_registry_leftovers(query_normalized, publisher, scan_mode)
        items.extend(registry_items)

        if os.path.exists(query):
            install_path = query if os.path.isdir(query) else os.path.dirname(query)
        else:
            install_path = None

        filesystem_items = self.uninstaller.scan_filesystem_leftovers(
            install_path, query_normalized, scan_mode
        )
        items.extend(filesystem_items)

        if scan_mode == "Advanced":
            advanced_items = self.uninstaller.scan_advanced_artifacts(query_normalized, publisher)
            items.extend(advanced_items)

        self.root.after(0, self.update_forced_uninstall_results, items, query)

    def update_forced_uninstall_results(self, items, query):
        self.uninstaller_progress.stop()
        self.uninstaller_status_label.config(
            text=f"Found {len(items)} artifacts related to '{query}'"
        )

        self.leftovers_tree.delete(*self.leftovers_tree.get_children())

        for item in items:
            self.leftovers_tree.insert(
                '',
                'end',
                text=item['name'],
                values=(
                    item['type'],
                    item['location'],
                    item.get('size', 'N/A'),
                    item.get('confidence', 'N/A')
                ),
                tags=('selected',)
            )

        self.leftovers_tree.tag_configure('selected', background='#e3f2fd')
        self.clean_leftovers_button.config(state="normal" if items else "disabled")


def main():
    root = tk.Tk()
    app = RustCleaner(root)
    root.mainloop()


if __name__ == "__main__":
    main()
